//! Integration tests for compression residual gate — residual tracking,
//! restoration overhead, cold-start/memory/proof-surface claim gates,
//! reversibility verification, support cost estimation, residual ledger,
//! decision receipts, batch surface evaluation, and serde roundtrips (RGC-618C).

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

use frankenengine_engine::compression_residual_gate::{
    ArtifactRecord, BuildArtifactInput, COMPRESSION_RESIDUAL_GATE_BEAD_ID,
    COMPRESSION_RESIDUAL_GATE_COMPONENT, COMPRESSION_RESIDUAL_GATE_SCHEMA_VERSION,
    ClaimBlockingReason, ClaimSurface, CompressionClaimVerdict, CompressionPassKind,
    CompressionPassResult, CompressionResidualError, CompressionResidualGate, DecisionReceipt,
    GateConfig, GateInput, GateSummary, HiddenExpansionRecord, LedgerAppendInput, ResidualLedger,
    ResidualLedgerEntry, ReversibilityCheck, SupportCostRecord, build_artifact_record,
    build_pass_result,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn ts() -> u64 {
    1_000_000_000
}

fn simple_artifact(id: &str, orig: u64, comp: u64, reversible: bool) -> ArtifactRecord {
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

fn simple_pass(artifacts: Vec<ArtifactRecord>) -> CompressionPassResult {
    build_pass_result(
        "pass-1",
        CompressionPassKind::Deduplication,
        artifacts,
        epoch(1),
        ts(),
    )
}

fn simple_reversibility_check(id: &str, exact: bool) -> ReversibilityCheck {
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
        fidelity_millionths: if exact { MILLION } else { 900_000 },
        divergent_bytes: if exact { 0 } else { 100 },
        total_bytes: 1000,
        restoration_time_us: 50,
    }
}

fn simple_hidden_expansion(id: &str, saved: u64, hidden: u64) -> HiddenExpansionRecord {
    let net = saved as i64 - hidden as i64;
    HiddenExpansionRecord {
        source_id: id.to_string(),
        memory_saved_bytes: saved,
        hidden_cost_bytes: hidden,
        net_change_bytes: net,
        cost_explanation: "test".to_string(),
    }
}

fn simple_support_cost(id: &str, baseline: i64, overhead: i64) -> SupportCostRecord {
    SupportCostRecord {
        source_id: id.to_string(),
        baseline_cost_millionths: baseline,
        compression_overhead_millionths: overhead,
        indirection_layers: 1,
        debug_readable: true,
        stack_traces_accurate: true,
        explanation: "test".to_string(),
    }
}

#[allow(dead_code)]
fn ledger_input(
    artifact_id: &str,
    pass_kind: CompressionPassKind,
    original_size_bytes: u64,
    compressed_size_bytes: u64,
    dup_removed: u64,
    dup_remaining: u64,
    reversible: bool,
) -> LedgerAppendInput {
    LedgerAppendInput {
        artifact_id: artifact_id.to_string(),
        pass_kind,
        original_size_bytes,
        compressed_size_bytes,
        duplicate_mass_removed_bytes: dup_removed,
        duplicate_mass_remaining_bytes: dup_remaining,
        reversible,
        bytes_lost: if reversible {
            0
        } else {
            original_size_bytes.saturating_sub(compressed_size_bytes)
        },
        restoration_overhead_us: 100,
        epoch: epoch(1),
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
        epoch: epoch(1),
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
        epoch: epoch(1),
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
        epoch: epoch(1),
        timestamp_ns: ts(),
        cold_start_total_budget_us: 0,
        proof_total_size_bytes: 10_000,
    }
}

// ---------------------------------------------------------------------------
// 1. Constants and schema identifiers
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_is_well_formed() {
    assert!(!COMPRESSION_RESIDUAL_GATE_SCHEMA_VERSION.is_empty());
    assert!(COMPRESSION_RESIDUAL_GATE_SCHEMA_VERSION.contains("compression-residual-gate"));
}

#[test]
fn test_component_label_is_well_formed() {
    assert!(!COMPRESSION_RESIDUAL_GATE_COMPONENT.is_empty());
    assert!(COMPRESSION_RESIDUAL_GATE_COMPONENT.contains("compression"));
}

#[test]
fn test_bead_id_is_well_formed() {
    assert!(!COMPRESSION_RESIDUAL_GATE_BEAD_ID.is_empty());
    assert!(COMPRESSION_RESIDUAL_GATE_BEAD_ID.starts_with("bd-"));
}

// ---------------------------------------------------------------------------
// 2. ClaimSurface enum
// ---------------------------------------------------------------------------

#[test]
fn test_claim_surface_all_has_three_entries() {
    assert_eq!(ClaimSurface::ALL.len(), 3);
    assert_eq!(ClaimSurface::ALL[0], ClaimSurface::ColdStart);
    assert_eq!(ClaimSurface::ALL[1], ClaimSurface::Memory);
    assert_eq!(ClaimSurface::ALL[2], ClaimSurface::ProofSurface);
}

#[test]
fn test_claim_surface_display() {
    assert_eq!(ClaimSurface::ColdStart.to_string(), "cold_start");
    assert_eq!(ClaimSurface::Memory.to_string(), "memory");
    assert_eq!(ClaimSurface::ProofSurface.to_string(), "proof_surface");
}

#[test]
fn test_claim_surface_ordering() {
    assert!(ClaimSurface::ColdStart < ClaimSurface::Memory);
    assert!(ClaimSurface::Memory < ClaimSurface::ProofSurface);
}

// ---------------------------------------------------------------------------
// 3. CompressionPassKind enum
// ---------------------------------------------------------------------------

#[test]
fn test_pass_kind_display_all_variants() {
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
fn test_pass_kind_ordering() {
    assert!(CompressionPassKind::Deduplication < CompressionPassKind::StructuralSharing);
    assert!(CompressionPassKind::StructuralSharing < CompressionPassKind::DeltaEncoding);
    assert!(CompressionPassKind::DeltaEncoding < CompressionPassKind::EntropyCoding);
    assert!(CompressionPassKind::EntropyCoding < CompressionPassKind::ProofCompaction);
    assert!(CompressionPassKind::ProofCompaction < CompressionPassKind::SemanticFolding);
}

// ---------------------------------------------------------------------------
// 4. CompressionClaimVerdict enum
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_display_all_variants() {
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
fn test_verdict_ordering() {
    assert!(CompressionClaimVerdict::Approved < CompressionClaimVerdict::ApprovedWithCaveats);
    assert!(CompressionClaimVerdict::ApprovedWithCaveats < CompressionClaimVerdict::Blocked);
    assert!(CompressionClaimVerdict::Blocked < CompressionClaimVerdict::Insufficient);
}

// ---------------------------------------------------------------------------
// 5. ArtifactRecord calculations
// ---------------------------------------------------------------------------

#[test]
fn test_artifact_compression_ratio_normal() {
    let art = simple_artifact("a1", 1000, 500, true);
    assert_eq!(art.compression_ratio_millionths(), 500_000);
}

#[test]
fn test_artifact_compression_ratio_zero_original() {
    let art = simple_artifact("a1", 0, 0, true);
    assert_eq!(art.compression_ratio_millionths(), MILLION);
}

#[test]
fn test_artifact_compression_ratio_no_compression() {
    let art = simple_artifact("a1", 1000, 1000, true);
    assert_eq!(art.compression_ratio_millionths(), MILLION);
    assert_eq!(art.space_savings_millionths(), 0);
}

#[test]
fn test_artifact_space_savings() {
    let art = simple_artifact("a1", 1000, 250, true);
    // savings = 1M - (250/1000)*1M = 750_000
    assert_eq!(art.space_savings_millionths(), 750_000);
}

#[test]
fn test_artifact_remaining_duplicate_mass_with_duplicates() {
    let art = build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 100,
        duplicates_removed: 80,
        duplicates_remaining: 20,
    });
    // 20 / (80+20) = 200_000
    assert_eq!(art.remaining_duplicate_mass_millionths(), 200_000);
}

#[test]
fn test_artifact_remaining_duplicate_mass_no_duplicates() {
    let art = build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::EntropyCoding,
        reversible: true,
        restoration_us: 50,
        duplicates_removed: 0,
        duplicates_remaining: 0,
    });
    assert_eq!(art.remaining_duplicate_mass_millionths(), 0);
}

#[test]
fn test_artifact_remaining_duplicate_mass_all_remaining() {
    let art = build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 100,
        duplicates_removed: 0,
        duplicates_remaining: 50,
    });
    // 50 / (0+50) = 1_000_000
    assert_eq!(art.remaining_duplicate_mass_millionths(), MILLION);
}

// ---------------------------------------------------------------------------
// 6. CompressionPassResult calculations
// ---------------------------------------------------------------------------

#[test]
fn test_pass_result_aggregate_ratio() {
    let arts = vec![
        simple_artifact("a1", 1000, 500, true),
        simple_artifact("a2", 2000, 1000, true),
    ];
    let pass = simple_pass(arts);
    // 1500 / 3000 = 500_000
    assert_eq!(pass.aggregate_compression_ratio_millionths(), 500_000);
}

#[test]
fn test_pass_result_aggregate_savings() {
    let arts = vec![simple_artifact("a1", 1000, 200, true)];
    let pass = simple_pass(arts);
    assert_eq!(pass.aggregate_savings_millionths(), 800_000);
}

#[test]
fn test_pass_result_fully_reversible_all_true() {
    let arts = vec![
        simple_artifact("a1", 1000, 500, true),
        simple_artifact("a2", 2000, 1000, true),
    ];
    let pass = simple_pass(arts);
    assert!(pass.fully_reversible());
}

#[test]
fn test_pass_result_not_fully_reversible() {
    let arts = vec![
        simple_artifact("a1", 1000, 500, true),
        simple_artifact("a2", 2000, 1000, false),
    ];
    let pass = simple_pass(arts);
    assert!(!pass.fully_reversible());
}

#[test]
fn test_pass_result_remaining_duplicate_mass() {
    let pass = simple_pass(vec![simple_artifact("a1", 1000, 500, true)]);
    // Each simple_artifact has dup_removed=10, dup_remaining=2
    // 2 / (10+2) = 166_666
    assert_eq!(pass.remaining_duplicate_mass_millionths(), 166_666);
}

#[test]
fn test_pass_result_empty_original_bytes() {
    let arts = vec![simple_artifact("a1", 0, 0, true)];
    let pass = simple_pass(arts);
    assert_eq!(pass.aggregate_compression_ratio_millionths(), MILLION);
}

// ---------------------------------------------------------------------------
// 7. HiddenExpansionRecord calculations
// ---------------------------------------------------------------------------

#[test]
fn test_hidden_expansion_ratio_normal() {
    let h = simple_hidden_expansion("s1", 1000, 100);
    assert_eq!(h.expansion_ratio_millionths(), 100_000);
}

#[test]
fn test_hidden_expansion_is_net_savings() {
    let h = simple_hidden_expansion("s1", 1000, 100);
    assert!(h.is_net_savings());
}

#[test]
fn test_hidden_expansion_net_loss() {
    let h = simple_hidden_expansion("s1", 100, 200);
    assert!(!h.is_net_savings());
    assert_eq!(h.net_change_bytes, -100);
}

#[test]
fn test_hidden_expansion_zero_saved_nonzero_hidden() {
    let h = simple_hidden_expansion("s1", 0, 100);
    // infinite expansion capped at 2M
    assert_eq!(h.expansion_ratio_millionths(), MILLION * 2);
}

#[test]
fn test_hidden_expansion_zero_both() {
    let h = simple_hidden_expansion("s1", 0, 0);
    assert_eq!(h.expansion_ratio_millionths(), 0);
}

#[test]
fn test_hidden_expansion_breakeven() {
    let h = simple_hidden_expansion("s1", 500, 500);
    // net = 0, not net savings
    assert!(!h.is_net_savings());
    assert_eq!(h.expansion_ratio_millionths(), MILLION);
}

// ---------------------------------------------------------------------------
// 8. SupportCostRecord calculations
// ---------------------------------------------------------------------------

#[test]
fn test_support_cost_total_millionths() {
    let sc = simple_support_cost("s1", 500_000, 100_000);
    assert_eq!(sc.total_cost_millionths(), 600_000);
}

#[test]
fn test_support_cost_overhead_ratio_normal() {
    let sc = simple_support_cost("s1", 1_000_000, 200_000);
    assert_eq!(sc.overhead_ratio_millionths(), 200_000);
}

#[test]
fn test_support_cost_zero_baseline_nonzero_overhead() {
    let sc = simple_support_cost("s1", 0, 100_000);
    assert_eq!(sc.overhead_ratio_millionths(), MILLION * 2);
}

#[test]
fn test_support_cost_zero_both() {
    let sc = simple_support_cost("s1", 0, 0);
    assert_eq!(sc.overhead_ratio_millionths(), 0);
}

#[test]
fn test_support_cost_saturation_on_large_values() {
    let sc = simple_support_cost("s1", i64::MAX / 2, i64::MAX / 2);
    // saturating_add should not panic
    let total = sc.total_cost_millionths();
    assert!(total > 0);
}

// ---------------------------------------------------------------------------
// 9. ReversibilityCheck
// ---------------------------------------------------------------------------

#[test]
fn test_reversibility_check_exact_match() {
    let check = simple_reversibility_check("a1", true);
    assert!(check.exact_match);
    assert_eq!(check.fidelity_millionths, MILLION);
    assert!(check.meets_fidelity_threshold(MILLION));
    assert!(check.meets_fidelity_threshold(999_000));
}

#[test]
fn test_reversibility_check_inexact_match() {
    let check = simple_reversibility_check("a1", false);
    assert!(!check.exact_match);
    assert_eq!(check.fidelity_millionths, 900_000);
    assert!(check.meets_fidelity_threshold(900_000));
    assert!(!check.meets_fidelity_threshold(950_000));
}

#[test]
fn test_reversibility_check_threshold_zero() {
    let check = simple_reversibility_check("a1", false);
    assert!(check.meets_fidelity_threshold(0));
}

// ---------------------------------------------------------------------------
// 10. ClaimBlockingReason Display
// ---------------------------------------------------------------------------

#[test]
fn test_blocking_reason_decompression_cost_display() {
    let reason = ClaimBlockingReason::DecompressionCostExceedsBudget {
        observed_millionths: 100_000,
        budget_millionths: 50_000,
    };
    let s = reason.to_string();
    assert!(s.contains("100000"));
    assert!(s.contains("50000"));
    assert!(s.contains("decompression"));
}

#[test]
fn test_blocking_reason_hidden_expansion_display() {
    let reason = ClaimBlockingReason::HiddenExpansionExceedsThreshold {
        observed_millionths: 200_000,
        threshold_millionths: 100_000,
    };
    assert!(reason.to_string().contains("hidden expansion"));
}

#[test]
fn test_blocking_reason_proof_overhead_display() {
    let reason = ClaimBlockingReason::ProofOverheadExceedsThreshold {
        observed_millionths: 250_000,
        threshold_millionths: 150_000,
    };
    assert!(reason.to_string().contains("proof overhead"));
}

#[test]
fn test_blocking_reason_excessive_dup_mass_display() {
    let reason = ClaimBlockingReason::ExcessiveDuplicateMass {
        remaining_millionths: 300_000,
        max_millionths: 200_000,
    };
    assert!(reason.to_string().contains("duplicate mass"));
}

#[test]
fn test_blocking_reason_irreversible_display() {
    let reason = ClaimBlockingReason::IrreversibleArtifact {
        artifact_id: "art-42".to_string(),
    };
    assert!(reason.to_string().contains("art-42"));
}

#[test]
fn test_blocking_reason_insufficient_fidelity_display() {
    let reason = ClaimBlockingReason::InsufficientFidelity {
        artifact_id: "art-1".to_string(),
        fidelity_millionths: 800_000,
        required_millionths: 999_000,
    };
    let s = reason.to_string();
    assert!(s.contains("art-1"));
    assert!(s.contains("800000"));
    assert!(s.contains("999000"));
}

#[test]
fn test_blocking_reason_support_cost_ceiling_display() {
    let reason = ClaimBlockingReason::SupportCostCeilingExceeded {
        observed_millionths: 300_000,
        ceiling_millionths: 200_000,
    };
    assert!(reason.to_string().contains("support cost"));
}

#[test]
fn test_blocking_reason_no_compression_data_display() {
    let reason = ClaimBlockingReason::NoCompressionData;
    assert!(reason.to_string().contains("no compression data"));
}

#[test]
fn test_blocking_reason_net_memory_expansion_display() {
    let reason = ClaimBlockingReason::NetMemoryExpansion {
        net_change_bytes: -500,
    };
    assert!(reason.to_string().contains("-500"));
}

#[test]
fn test_blocking_reason_debug_readability_display() {
    let reason = ClaimBlockingReason::DebugReadabilityLost {
        source_id: "mod-x".to_string(),
    };
    assert!(reason.to_string().contains("mod-x"));
}

#[test]
fn test_blocking_reason_stack_trace_display() {
    let reason = ClaimBlockingReason::StackTraceAccuracyLost {
        source_id: "mod-y".to_string(),
    };
    assert!(reason.to_string().contains("mod-y"));
}

// ---------------------------------------------------------------------------
// 11. CompressionResidualError Display
// ---------------------------------------------------------------------------

#[test]
fn test_error_ledger_full_display() {
    let err = CompressionResidualError::LedgerFull {
        count: 10_000,
        max: 10_000,
    };
    assert!(err.to_string().contains("ledger full"));
    assert!(err.to_string().contains("10000"));
}

#[test]
fn test_error_too_many_artifacts_display() {
    let err = CompressionResidualError::TooManyArtifacts {
        count: 2000,
        max: 1000,
    };
    assert!(err.to_string().contains("too many artifacts"));
}

#[test]
fn test_error_invalid_config_display() {
    let err = CompressionResidualError::InvalidConfig {
        reason: "bad value".to_string(),
    };
    assert!(err.to_string().contains("invalid config"));
    assert!(err.to_string().contains("bad value"));
}

#[test]
fn test_error_empty_input_display() {
    let err = CompressionResidualError::EmptyInput {
        context: "test ctx".to_string(),
    };
    assert!(err.to_string().contains("empty input"));
    assert!(err.to_string().contains("test ctx"));
}

#[test]
fn test_error_implements_std_error() {
    let err = CompressionResidualError::EmptyInput {
        context: "x".to_string(),
    };
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// 12. ResidualLedger
// ---------------------------------------------------------------------------

#[test]
fn test_ledger_new_is_empty() {
    let ledger = ResidualLedger::new();
    assert!(ledger.is_empty());
    assert_eq!(ledger.len(), 0);
    assert_eq!(ledger.total_original_bytes(), 0);
    assert_eq!(ledger.total_compressed_bytes(), 0);
    assert_eq!(ledger.total_bytes_lost(), 0);
    assert_eq!(ledger.distinct_artifact_count(), 0);
}

#[test]
fn test_ledger_default_is_empty() {
    let ledger: ResidualLedger = Default::default();
    assert!(ledger.is_empty());
}

#[test]
fn test_ledger_append_and_query() {
    let mut ledger = ResidualLedger::new();
    let seq = ledger
        .append(&LedgerAppendInput {
            artifact_id: "art-1".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 10,
            duplicate_mass_remaining_bytes: 2,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 100,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    assert_eq!(seq, 0);
    assert_eq!(ledger.len(), 1);
    assert!(!ledger.is_empty());
    assert_eq!(ledger.total_original_bytes(), 1000);
    assert_eq!(ledger.total_compressed_bytes(), 500);
}

#[test]
fn test_ledger_entries_for_artifact_multi_pass() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "a".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 10,
            duplicate_mass_remaining_bytes: 2,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 100,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "b".to_string(),
            pass_kind: CompressionPassKind::EntropyCoding,
            original_size_bytes: 2000,
            compressed_size_bytes: 800,
            duplicate_mass_removed_bytes: 5,
            duplicate_mass_remaining_bytes: 1,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 200,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "a".to_string(),
            pass_kind: CompressionPassKind::DeltaEncoding,
            original_size_bytes: 500,
            compressed_size_bytes: 200,
            duplicate_mass_removed_bytes: 3,
            duplicate_mass_remaining_bytes: 1,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 50,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();

    assert_eq!(ledger.entries_for_artifact("a").len(), 2);
    assert_eq!(ledger.entries_for_artifact("b").len(), 1);
    assert_eq!(ledger.entries_for_artifact("nonexistent").len(), 0);
}

#[test]
fn test_ledger_distinct_artifact_count() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "a".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 0,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "b".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 0,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "a".to_string(),
            pass_kind: CompressionPassKind::DeltaEncoding,
            original_size_bytes: 500,
            compressed_size_bytes: 200,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 0,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    assert_eq!(ledger.distinct_artifact_count(), 2);
    assert_eq!(ledger.len(), 3);
}

#[test]
fn test_ledger_compression_ratio() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "a".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 0,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    assert_eq!(ledger.aggregate_compression_ratio_millionths(), 500_000);
}

#[test]
fn test_ledger_empty_compression_ratio() {
    let ledger = ResidualLedger::new();
    assert_eq!(ledger.aggregate_compression_ratio_millionths(), MILLION);
}

#[test]
fn test_ledger_duplicate_mass_ratio() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "a".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 80,
            duplicate_mass_remaining_bytes: 20,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 0,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    // 20 / (80+20) = 200_000
    assert_eq!(ledger.aggregate_duplicate_mass_millionths(), 200_000);
}

#[test]
fn test_ledger_empty_duplicate_mass() {
    let ledger = ResidualLedger::new();
    assert_eq!(ledger.aggregate_duplicate_mass_millionths(), 0);
}

#[test]
fn test_ledger_irreversible_tracking() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "a".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 0,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    assert!(!ledger.has_irreversible_entries());
    assert_eq!(ledger.irreversible_count(), 0);

    ledger
        .append(&LedgerAppendInput {
            artifact_id: "b".to_string(),
            pass_kind: CompressionPassKind::ProofCompaction,
            original_size_bytes: 2000,
            compressed_size_bytes: 800,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: false,
            bytes_lost: 200,
            restoration_overhead_us: 0,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    assert!(ledger.has_irreversible_entries());
    assert_eq!(ledger.irreversible_count(), 1);
}

#[test]
fn test_ledger_total_restoration_overhead() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "a".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 100,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "b".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 250,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    assert_eq!(ledger.total_restoration_overhead_us(), 350);
}

#[test]
fn test_ledger_bytes_lost_tracking() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "a".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: false,
            bytes_lost: 150,
            restoration_overhead_us: 0,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    assert_eq!(ledger.total_bytes_lost(), 150);
}

#[test]
fn test_ledger_entries_accessor() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "a".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 0,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    let entries = ledger.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].artifact_id, "a");
    assert_eq!(entries[0].sequence, 0);
}

#[test]
fn test_ledger_entry_hash_determinism() {
    let mut l1 = ResidualLedger::new();
    let mut l2 = ResidualLedger::new();
    l1.append(&LedgerAppendInput {
        artifact_id: "a".to_string(),
        pass_kind: CompressionPassKind::Deduplication,
        original_size_bytes: 1000,
        compressed_size_bytes: 500,
        duplicate_mass_removed_bytes: 10,
        duplicate_mass_remaining_bytes: 2,
        reversible: true,
        bytes_lost: 0,
        restoration_overhead_us: 100,
        epoch: epoch(1),
        timestamp_ns: ts(),
    })
    .unwrap();
    l2.append(&LedgerAppendInput {
        artifact_id: "a".to_string(),
        pass_kind: CompressionPassKind::Deduplication,
        original_size_bytes: 1000,
        compressed_size_bytes: 500,
        duplicate_mass_removed_bytes: 10,
        duplicate_mass_remaining_bytes: 2,
        reversible: true,
        bytes_lost: 0,
        restoration_overhead_us: 100,
        epoch: epoch(1),
        timestamp_ns: ts(),
    })
    .unwrap();
    assert_eq!(l1.entries()[0].entry_hash, l2.entries()[0].entry_hash);
}

#[test]
fn test_ledger_sequence_numbers_increment() {
    let mut ledger = ResidualLedger::new();
    let s0 = ledger
        .append(&LedgerAppendInput {
            artifact_id: "a".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 0,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    let s1 = ledger
        .append(&LedgerAppendInput {
            artifact_id: "b".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 0,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    let s2 = ledger
        .append(&LedgerAppendInput {
            artifact_id: "c".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 0,
            duplicate_mass_remaining_bytes: 0,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 0,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    assert_eq!(s0, 0);
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
}

// ---------------------------------------------------------------------------
// 13. GateConfig defaults and validation
// ---------------------------------------------------------------------------

#[test]
fn test_gate_config_default_values() {
    let config = GateConfig::default();
    assert_eq!(config.cold_start_decompression_budget_millionths, 50_000);
    assert_eq!(config.memory_hidden_expansion_threshold_millionths, 100_000);
    assert_eq!(config.proof_overhead_threshold_millionths, 150_000);
    assert_eq!(config.support_cost_ceiling_millionths, 200_000);
    assert_eq!(config.reversibility_threshold_millionths, 999_000);
    assert_eq!(config.max_duplicate_mass_millionths, 200_000);
    assert!(config.require_full_reversibility);
    assert!(config.require_debug_readability);
    assert!(config.require_stack_trace_accuracy);
    assert_eq!(config.max_cold_start_restoration_us, 500_000);
}

#[test]
fn test_gate_config_invalid_negative_budget() {
    let config = GateConfig {
        cold_start_decompression_budget_millionths: -1,
        ..GateConfig::default()
    };
    let result = CompressionResidualGate::with_config(config);
    assert!(result.is_err());
}

#[test]
fn test_gate_config_invalid_negative_memory_hidden_expansion_threshold() {
    let config = GateConfig {
        memory_hidden_expansion_threshold_millionths: -1,
        ..GateConfig::default()
    };
    let result = CompressionResidualGate::with_config(config);
    assert!(result.is_err());
}

#[test]
fn test_gate_config_invalid_negative_proof_overhead_threshold() {
    let config = GateConfig {
        proof_overhead_threshold_millionths: -1,
        ..GateConfig::default()
    };
    let result = CompressionResidualGate::with_config(config);
    assert!(result.is_err());
}

#[test]
fn test_gate_config_invalid_negative_support_cost_ceiling() {
    let config = GateConfig {
        support_cost_ceiling_millionths: -1,
        ..GateConfig::default()
    };
    let result = CompressionResidualGate::with_config(config);
    assert!(result.is_err());
}

#[test]
fn test_gate_config_invalid_reversibility_above_million() {
    let config = GateConfig {
        reversibility_threshold_millionths: MILLION + 1,
        ..GateConfig::default()
    };
    let result = CompressionResidualGate::with_config(config);
    assert!(result.is_err());
}

#[test]
fn test_gate_config_invalid_negative_reversibility() {
    let config = GateConfig {
        reversibility_threshold_millionths: -1,
        ..GateConfig::default()
    };
    let result = CompressionResidualGate::with_config(config);
    assert!(result.is_err());
}

#[test]
fn test_gate_config_invalid_negative_dup_mass() {
    let config = GateConfig {
        max_duplicate_mass_millionths: -5,
        ..GateConfig::default()
    };
    let result = CompressionResidualGate::with_config(config);
    assert!(result.is_err());
}

#[test]
fn test_gate_config_boundary_zero_reversibility_valid() {
    let config = GateConfig {
        reversibility_threshold_millionths: 0,
        ..GateConfig::default()
    };
    assert!(CompressionResidualGate::with_config(config).is_ok());
}

#[test]
fn test_gate_config_boundary_million_reversibility_valid() {
    let config = GateConfig {
        reversibility_threshold_millionths: MILLION,
        ..GateConfig::default()
    };
    assert!(CompressionResidualGate::with_config(config).is_ok());
}

// ---------------------------------------------------------------------------
// 14. CompressionResidualGate construction
// ---------------------------------------------------------------------------

#[test]
fn test_gate_new_defaults() {
    let gate = CompressionResidualGate::new();
    assert_eq!(gate.evaluations_run(), 0);
    assert_eq!(gate.claims_approved(), 0);
    assert_eq!(gate.claims_blocked(), 0);
    assert!(gate.ledger().is_empty());
    assert!(gate.receipts().is_empty());
}

#[test]
fn test_gate_default_trait() {
    let gate: CompressionResidualGate = Default::default();
    assert_eq!(gate.evaluations_run(), 0);
}

#[test]
fn test_gate_with_custom_config() {
    let config = GateConfig {
        cold_start_decompression_budget_millionths: 100_000,
        ..GateConfig::default()
    };
    let gate = CompressionResidualGate::with_config(config).unwrap();
    assert_eq!(
        gate.config().cold_start_decompression_budget_millionths,
        100_000
    );
}

// ---------------------------------------------------------------------------
// 15. Cold-start gate evaluation
// ---------------------------------------------------------------------------

#[test]
fn test_cold_start_approved_low_restoration() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Approved);
    assert!(receipt.blocking_reasons.is_empty());
    assert!(receipt.caveats.is_empty());
}

#[test]
fn test_cold_start_blocked_decompression_exceeds_budget() {
    let mut gate = CompressionResidualGate::new();
    // 100_000us / 1_000_000us budget = 100_000 millionths > 50_000 budget
    let arts = vec![build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 100_000,
        duplicates_removed: 10,
        duplicates_remaining: 2,
    })];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
}

#[test]
fn test_cold_start_caveat_near_budget() {
    let mut gate = CompressionResidualGate::new();
    // 40_000 / 1_000_000 = 40_000 millionths. Budget 50_000, 3/4 = 37_500, so caveat
    let arts = vec![build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 40_000,
        duplicates_removed: 10,
        duplicates_remaining: 2,
    })];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(
        receipt.verdict,
        CompressionClaimVerdict::ApprovedWithCaveats
    );
    assert!(!receipt.caveats.is_empty());
}

#[test]
fn test_cold_start_blocked_absolute_restoration_too_high() {
    let mut gate = CompressionResidualGate::new();
    // max_cold_start_restoration_us default = 500_000
    let arts = vec![build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 600_000,
        duplicates_removed: 10,
        duplicates_remaining: 2,
    })];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
}

// ---------------------------------------------------------------------------
// 16. Memory gate evaluation
// ---------------------------------------------------------------------------

#[test]
fn test_memory_approved_low_expansion() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let expansions = vec![simple_hidden_expansion("s1", 500, 10)];
    let input = memory_input(pass, expansions);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Approved);
}

#[test]
fn test_memory_blocked_net_expansion() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let expansions = vec![simple_hidden_expansion("s1", 100, 200)];
    let input = memory_input(pass, expansions);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, ClaimBlockingReason::NetMemoryExpansion { .. }) })
    );
}

#[test]
fn test_memory_blocked_high_hidden_expansion_ratio() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    // 200 / 1000 = 200_000 > threshold 100_000
    let expansions = vec![simple_hidden_expansion("s1", 1000, 200)];
    let input = memory_input(pass, expansions);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
}

#[test]
fn test_memory_blocked_debug_readability_lost() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let mut input = memory_input(pass, vec![simple_hidden_expansion("s1", 1000, 10)]);
    input.support_costs.push(SupportCostRecord {
        source_id: "s1".to_string(),
        baseline_cost_millionths: 100_000,
        compression_overhead_millionths: 10_000,
        indirection_layers: 1,
        debug_readable: false,
        stack_traces_accurate: true,
        explanation: "unreadable".to_string(),
    });
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, ClaimBlockingReason::DebugReadabilityLost { .. }) })
    );
}

#[test]
fn test_memory_caveat_near_hidden_expansion_threshold() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    // 80 / 1000 = 80_000 > 100_000 * 3/4 = 75_000, but < 100_000
    let expansions = vec![simple_hidden_expansion("s1", 1000, 80)];
    let input = memory_input(pass, expansions);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(
        receipt.verdict,
        CompressionClaimVerdict::ApprovedWithCaveats
    );
    assert!(!receipt.caveats.is_empty());
}

// ---------------------------------------------------------------------------
// 17. Proof-surface gate evaluation
// ---------------------------------------------------------------------------

#[test]
fn test_proof_surface_approved() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let input = proof_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Approved);
}

#[test]
fn test_proof_surface_blocked_irreversible_check() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let mut input = proof_input(pass);
    input
        .reversibility_checks
        .push(simple_reversibility_check("a1", false));
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
}

#[test]
fn test_proof_surface_blocked_overhead() {
    let mut gate = CompressionResidualGate::new();
    // compressed > original means overhead
    let arts = vec![simple_artifact("a1", 1000, 3000, true)];
    let pass = simple_pass(arts);
    let input = proof_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, ClaimBlockingReason::ProofOverheadExceedsThreshold { .. }) })
    );
}

// ---------------------------------------------------------------------------
// 18. Reversibility checks (common to all surfaces)
// ---------------------------------------------------------------------------

#[test]
fn test_reversibility_blocks_low_fidelity() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let mut input = cold_start_input(pass);
    input.reversibility_checks.push(ReversibilityCheck {
        artifact_id: "a1".to_string(),
        original_hash: ContentHash::compute(b"orig"),
        restored_hash: ContentHash::compute(b"restored"),
        exact_match: false,
        fidelity_millionths: 900_000, // below 999_000 threshold
        divergent_bytes: 100,
        total_bytes: 1000,
        restoration_time_us: 50,
    });
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, ClaimBlockingReason::InsufficientFidelity { .. }) })
    );
}

#[test]
fn test_reversibility_passes_when_above_threshold() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let mut input = cold_start_input(pass);
    input.reversibility_checks.push(ReversibilityCheck {
        artifact_id: "a1".to_string(),
        original_hash: ContentHash::compute(b"x"),
        restored_hash: ContentHash::compute(b"x"),
        exact_match: true,
        fidelity_millionths: MILLION,
        divergent_bytes: 0,
        total_bytes: 1000,
        restoration_time_us: 50,
    });
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Approved);
}

// ---------------------------------------------------------------------------
// 19. Support cost checks
// ---------------------------------------------------------------------------

#[test]
fn test_support_cost_blocks_ceiling_exceeded() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let mut input = cold_start_input(pass);
    // 500_000 / 1_000_000 = 500_000 > 200_000 ceiling
    input
        .support_costs
        .push(simple_support_cost("s1", 1_000_000, 500_000));
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, ClaimBlockingReason::SupportCostCeilingExceeded { .. }) })
    );
}

#[test]
fn test_support_cost_blocks_stack_trace_lost() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let mut input = cold_start_input(pass);
    input.support_costs.push(SupportCostRecord {
        source_id: "s1".to_string(),
        baseline_cost_millionths: 1_000_000,
        compression_overhead_millionths: 10_000,
        indirection_layers: 1,
        debug_readable: true,
        stack_traces_accurate: false,
        explanation: "traces lost".to_string(),
    });
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, ClaimBlockingReason::StackTraceAccuracyLost { .. }) })
    );
}

#[test]
fn test_support_cost_caveat_near_ceiling() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let mut input = cold_start_input(pass);
    // 160_000 / 1_000_000 = 160_000 > 200_000 * 3/4 = 150_000
    input
        .support_costs
        .push(simple_support_cost("s1", 1_000_000, 160_000));
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(
        receipt.verdict,
        CompressionClaimVerdict::ApprovedWithCaveats
    );
    assert!(receipt.caveats.iter().any(|c| c.contains("support cost")));
}

// ---------------------------------------------------------------------------
// 20. Duplicate mass threshold
// ---------------------------------------------------------------------------

#[test]
fn test_duplicate_mass_blocks_when_exceeded() {
    let mut gate = CompressionResidualGate::new();
    // 50 / (50+50) = 500_000 > 200_000 threshold
    let arts = vec![build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 100,
        duplicates_removed: 50,
        duplicates_remaining: 50,
    })];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, ClaimBlockingReason::ExcessiveDuplicateMass { .. }) })
    );
}

#[test]
fn test_duplicate_mass_passes_when_within_threshold() {
    let mut gate = CompressionResidualGate::new();
    // 2 / (10+2) = 166_666 < 200_000 threshold
    let arts = vec![build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 100,
        duplicates_removed: 10,
        duplicates_remaining: 2,
    })];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Approved);
}

// ---------------------------------------------------------------------------
// 21. Irreversible artifact handling
// ---------------------------------------------------------------------------

#[test]
fn test_irreversible_artifact_blocks_when_required() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, false)];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, ClaimBlockingReason::IrreversibleArtifact { .. }) })
    );
}

#[test]
fn test_irreversible_artifact_ok_when_not_required() {
    let config = GateConfig {
        require_full_reversibility: false,
        ..GateConfig::default()
    };
    let mut gate = CompressionResidualGate::with_config(config).unwrap();
    let arts = vec![simple_artifact("a1", 1000, 500, false)];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    let has_irreversible_block = receipt
        .blocking_reasons
        .iter()
        .any(|r| matches!(r, ClaimBlockingReason::IrreversibleArtifact { .. }));
    assert!(!has_irreversible_block);
}

// ---------------------------------------------------------------------------
// 22. No compression data
// ---------------------------------------------------------------------------

#[test]
fn test_no_pass_results_are_insufficient_with_no_compression_data() {
    let mut gate = CompressionResidualGate::new();
    let input = GateInput {
        surface: ClaimSurface::ColdStart,
        pass_results: Vec::new(),
        hidden_expansions: Vec::new(),
        support_costs: Vec::new(),
        reversibility_checks: Vec::new(),
        epoch: epoch(1),
        timestamp_ns: ts(),
        cold_start_total_budget_us: 1_000_000,
        proof_total_size_bytes: 0,
    };
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Insufficient);
    assert_eq!(gate.claims_insufficient(), 1);
    assert_eq!(gate.claims_blocked(), 0);
    assert!(gate.ledger().is_empty());
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, ClaimBlockingReason::NoCompressionData) })
    );
}

// ---------------------------------------------------------------------------
// 23. Decision receipt fields
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_schema_and_component_fields() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(
        receipt.schema_version,
        COMPRESSION_RESIDUAL_GATE_SCHEMA_VERSION
    );
    assert_eq!(receipt.component, COMPRESSION_RESIDUAL_GATE_COMPONENT);
    assert_eq!(receipt.bead_id, COMPRESSION_RESIDUAL_GATE_BEAD_ID);
    assert_eq!(receipt.surface, ClaimSurface::ColdStart);
    assert_eq!(receipt.epoch, epoch(1));
    assert_eq!(receipt.timestamp_ns, ts());
}

#[test]
fn test_receipt_reversibility_counts() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let mut input = cold_start_input(pass);
    input
        .reversibility_checks
        .push(simple_reversibility_check("a1", true));
    input
        .reversibility_checks
        .push(simple_reversibility_check("a2", false));
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.reversibility_pass_count, 1);
    assert_eq!(receipt.reversibility_fail_count, 1);
}

#[test]
fn test_receipt_passes_and_artifacts_counts() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![
        simple_artifact("a1", 1000, 500, true),
        simple_artifact("a2", 2000, 800, true),
    ];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.passes_considered, 1);
    assert_eq!(receipt.artifacts_considered, 2);
}

#[test]
fn test_receipt_net_memory_change() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let input = memory_input(
        pass,
        vec![
            simple_hidden_expansion("s1", 500, 10),
            simple_hidden_expansion("s2", 300, 5),
        ],
    );
    let receipt = gate.evaluate(&input).unwrap();
    // net = (500-10) + (300-5) = 490 + 295 = 785
    assert_eq!(receipt.net_memory_change_bytes, 785);
}

// ---------------------------------------------------------------------------
// 24. Receipt hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_hash_deterministic() {
    let mut gate1 = CompressionResidualGate::new();
    let mut gate2 = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass1 = simple_pass(arts.clone());
    let pass2 = simple_pass(arts);
    let input1 = cold_start_input(pass1);
    let input2 = cold_start_input(pass2);
    let r1 = gate1.evaluate(&input1).unwrap();
    let r2 = gate2.evaluate(&input2).unwrap();
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_hash_changes_with_surface() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass1 = simple_pass(arts.clone());
    let pass2 = simple_pass(arts);
    let input1 = cold_start_input(pass1);
    let input2 = proof_input(pass2);
    let r1 = gate.evaluate(&input1).unwrap();
    let r2 = gate.evaluate(&input2).unwrap();
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_hash_changes_with_epoch() {
    let mut gate = CompressionResidualGate::new();
    let arts1 = vec![simple_artifact("a1", 1000, 500, true)];
    let pass1 = simple_pass(arts1);
    let mut input1 = cold_start_input(pass1);
    input1.epoch = epoch(1);

    let arts2 = vec![simple_artifact("a1", 1000, 500, true)];
    let pass2 = simple_pass(arts2);
    let mut input2 = cold_start_input(pass2);
    input2.epoch = epoch(99);

    let r1 = gate.evaluate(&input1).unwrap();
    let r2 = gate.evaluate(&input2).unwrap();
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

// ---------------------------------------------------------------------------
// 25. Evaluate all surfaces
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_all_surfaces_returns_three_receipts() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let template = GateInput {
        surface: ClaimSurface::ColdStart,
        pass_results: vec![pass],
        hidden_expansions: vec![simple_hidden_expansion("s1", 1000, 10)],
        support_costs: Vec::new(),
        reversibility_checks: Vec::new(),
        epoch: epoch(1),
        timestamp_ns: ts(),
        cold_start_total_budget_us: 1_000_000,
        proof_total_size_bytes: 10_000,
    };
    let results = gate.evaluate_all_surfaces(&template).unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].surface, ClaimSurface::ColdStart);
    assert_eq!(results[1].surface, ClaimSurface::Memory);
    assert_eq!(results[2].surface, ClaimSurface::ProofSurface);
}

#[test]
fn test_evaluate_all_surfaces_increments_counters() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let template = GateInput {
        surface: ClaimSurface::ColdStart,
        pass_results: vec![pass],
        hidden_expansions: vec![simple_hidden_expansion("s1", 1000, 10)],
        support_costs: Vec::new(),
        reversibility_checks: Vec::new(),
        epoch: epoch(1),
        timestamp_ns: ts(),
        cold_start_total_budget_us: 1_000_000,
        proof_total_size_bytes: 10_000,
    };
    gate.evaluate_all_surfaces(&template).unwrap();
    assert_eq!(gate.evaluations_run(), 3);
}

#[test]
fn test_evaluate_all_surfaces_records_ledger_once() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![
        simple_artifact("a1", 1000, 500, true),
        simple_artifact("a2", 2000, 800, true),
    ];
    let pass = simple_pass(arts);
    let template = GateInput {
        surface: ClaimSurface::ColdStart,
        pass_results: vec![pass],
        hidden_expansions: vec![simple_hidden_expansion("s1", 1000, 10)],
        support_costs: Vec::new(),
        reversibility_checks: Vec::new(),
        epoch: epoch(1),
        timestamp_ns: ts(),
        cold_start_total_budget_us: 1_000_000,
        proof_total_size_bytes: 10_000,
    };

    let results = gate.evaluate_all_surfaces(&template).unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(gate.receipts().len(), 3);
    assert_eq!(gate.ledger().len(), 2);
    assert_eq!(gate.ledger().distinct_artifact_count(), 2);
    assert_eq!(gate.ledger().total_original_bytes(), 3000);
    assert_eq!(gate.ledger().total_compressed_bytes(), 1300);
}

// ---------------------------------------------------------------------------
// 26. Counter tracking and summary
// ---------------------------------------------------------------------------

#[test]
fn test_counters_increment_on_evaluation() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    gate.evaluate(&input).unwrap();
    assert_eq!(gate.evaluations_run(), 1);
    assert_eq!(gate.claims_approved(), 1);
    assert_eq!(gate.claims_blocked(), 0);
}

#[test]
fn test_mixed_verdict_counters() {
    let mut gate = CompressionResidualGate::new();

    // Approved
    let pass1 = simple_pass(vec![simple_artifact("a1", 1000, 500, true)]);
    gate.evaluate(&cold_start_input(pass1)).unwrap();

    // Blocked (irreversible)
    let pass2 = simple_pass(vec![simple_artifact("a2", 1000, 500, false)]);
    gate.evaluate(&cold_start_input(pass2)).unwrap();

    assert_eq!(gate.evaluations_run(), 2);
    assert_eq!(gate.claims_approved(), 1);
    assert_eq!(gate.claims_blocked(), 1);
}

#[test]
fn test_gate_summary_fields() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    gate.evaluate(&cold_start_input(pass)).unwrap();
    let summary = gate.summary();
    assert_eq!(summary.evaluations_run, 1);
    assert_eq!(summary.claims_approved, 1);
    assert_eq!(summary.claims_blocked, 0);
    assert_eq!(summary.claims_with_caveats, 0);
    assert_eq!(summary.claims_insufficient, 0);
    assert!(summary.ledger_entries > 0);
    assert!(summary.distinct_artifacts > 0);
}

#[test]
fn test_gate_summary_empty_gate() {
    let gate = CompressionResidualGate::new();
    let summary = gate.summary();
    assert_eq!(summary.evaluations_run, 0);
    assert_eq!(summary.ledger_entries, 0);
    assert_eq!(summary.distinct_artifacts, 0);
    assert_eq!(summary.ledger_compression_ratio_millionths, MILLION);
    assert_eq!(summary.ledger_duplicate_mass_millionths, 0);
    assert_eq!(summary.total_bytes_lost, 0);
}

// ---------------------------------------------------------------------------
// 27. Ledger population from evaluate
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_populates_ledger() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![
        simple_artifact("a1", 1000, 500, true),
        simple_artifact("a2", 2000, 800, true),
    ];
    let pass = simple_pass(arts);
    gate.evaluate(&cold_start_input(pass)).unwrap();
    assert_eq!(gate.ledger().len(), 2);
    assert_eq!(gate.ledger().distinct_artifact_count(), 2);
}

#[test]
fn test_multiple_evaluations_accumulate_ledger() {
    let mut gate = CompressionResidualGate::new();
    for i in 0..5 {
        let arts = vec![simple_artifact(&format!("a{i}"), 1000, 500, true)];
        let pass = simple_pass(arts);
        gate.evaluate(&cold_start_input(pass)).unwrap();
    }
    assert_eq!(gate.evaluations_run(), 5);
    assert_eq!(gate.claims_approved(), 5);
    assert_eq!(gate.receipts().len(), 5);
    assert_eq!(gate.ledger().len(), 5);
}

// ---------------------------------------------------------------------------
// 28. Relaxed config allows more
// ---------------------------------------------------------------------------

#[test]
fn test_relaxed_config_allows_otherwise_blocked() {
    let config = GateConfig {
        max_duplicate_mass_millionths: MILLION,
        require_full_reversibility: false,
        require_debug_readability: false,
        require_stack_trace_accuracy: false,
        cold_start_decompression_budget_millionths: MILLION,
        support_cost_ceiling_millionths: MILLION * 2,
        reversibility_threshold_millionths: 0,
        max_cold_start_restoration_us: u64::MAX,
        ..GateConfig::default()
    };

    let mut gate = CompressionResidualGate::with_config(config).unwrap();
    let arts = vec![build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: false,
        restoration_us: 999_999,
        duplicates_removed: 50,
        duplicates_remaining: 50,
    })];
    let pass = simple_pass(arts);
    let mut input = cold_start_input(pass);
    input.support_costs.push(SupportCostRecord {
        source_id: "s1".to_string(),
        baseline_cost_millionths: 100_000,
        compression_overhead_millionths: 90_000,
        indirection_layers: 5,
        debug_readable: false,
        stack_traces_accurate: false,
        explanation: "everything broken".to_string(),
    });
    let receipt = gate.evaluate(&input).unwrap();
    // Caveat expected: decompression ratio 999_999 > budget * 3/4 = 750_000.
    assert_eq!(
        receipt.verdict,
        CompressionClaimVerdict::ApprovedWithCaveats
    );
}

// ---------------------------------------------------------------------------
// 29. Build helpers
// ---------------------------------------------------------------------------

#[test]
fn test_build_artifact_record_produces_distinct_hashes() {
    let a1 = build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 100,
        duplicates_removed: 10,
        duplicates_remaining: 2,
    });
    let a2 = build_artifact_record(&BuildArtifactInput {
        artifact_id: "a2".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 100,
        duplicates_removed: 10,
        duplicates_remaining: 2,
    });
    assert_ne!(a1.original_hash, a2.original_hash);
    assert_ne!(a1.compressed_hash, a2.compressed_hash);
}

#[test]
fn test_build_pass_result_aggregates_correctly() {
    let arts = vec![
        simple_artifact("a1", 1000, 500, true),
        simple_artifact("a2", 2000, 800, false),
    ];
    let pass = build_pass_result(
        "p1",
        CompressionPassKind::Deduplication,
        arts,
        epoch(1),
        ts(),
    );
    assert_eq!(pass.total_original_bytes, 3000);
    assert_eq!(pass.total_compressed_bytes, 1300);
    assert_eq!(pass.reversible_count, 1);
    assert_eq!(pass.irreversible_count, 1);
    assert_eq!(pass.total_duplicates_removed, 20);
    assert_eq!(pass.total_duplicates_remaining, 4);
}

// ---------------------------------------------------------------------------
// 30. Serde round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn test_serde_roundtrip_claim_surface() {
    for surface in ClaimSurface::ALL {
        let json = serde_json::to_string(&surface).unwrap();
        let back: ClaimSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(surface, back);
    }
}

#[test]
fn test_serde_roundtrip_compression_pass_kind() {
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
        assert_eq!(kind, back);
    }
}

#[test]
fn test_serde_roundtrip_verdict() {
    let verdicts = [
        CompressionClaimVerdict::Approved,
        CompressionClaimVerdict::ApprovedWithCaveats,
        CompressionClaimVerdict::Blocked,
        CompressionClaimVerdict::Insufficient,
    ];
    for v in verdicts {
        let json = serde_json::to_string(&v).unwrap();
        let back: CompressionClaimVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn test_serde_roundtrip_artifact_record() {
    let art = build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::SemanticFolding,
        reversible: true,
        restoration_us: 100,
        duplicates_removed: 10,
        duplicates_remaining: 2,
    });
    let json = serde_json::to_string(&art).unwrap();
    let back: ArtifactRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(art, back);
}

#[test]
fn test_serde_roundtrip_compression_pass_result() {
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let json = serde_json::to_string(&pass).unwrap();
    let back: CompressionPassResult = serde_json::from_str(&json).unwrap();
    assert_eq!(pass, back);
}

#[test]
fn test_serde_roundtrip_hidden_expansion() {
    let h = simple_hidden_expansion("s1", 1000, 100);
    let json = serde_json::to_string(&h).unwrap();
    let back: HiddenExpansionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}

#[test]
fn test_serde_roundtrip_support_cost() {
    let sc = simple_support_cost("s1", 100_000, 50_000);
    let json = serde_json::to_string(&sc).unwrap();
    let back: SupportCostRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(sc, back);
}

#[test]
fn test_serde_roundtrip_reversibility_check() {
    let check = simple_reversibility_check("a1", true);
    let json = serde_json::to_string(&check).unwrap();
    let back: ReversibilityCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, back);
}

#[test]
fn test_serde_roundtrip_decision_receipt() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn test_serde_roundtrip_ledger_entry() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "art-1".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 10,
            duplicate_mass_remaining_bytes: 2,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 100,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    let entry = &ledger.entries()[0];
    let json = serde_json::to_string(entry).unwrap();
    let back: ResidualLedgerEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(*entry, back);
}

#[test]
fn test_serde_roundtrip_gate_summary() {
    let gate = CompressionResidualGate::new();
    let summary = gate.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn test_serde_roundtrip_gate_config() {
    let config = GateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn test_serde_roundtrip_gate_input() {
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let json = serde_json::to_string(&input).unwrap();
    let back: GateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn test_serde_roundtrip_blocking_reason_all_variants() {
    let reasons: Vec<ClaimBlockingReason> = vec![
        ClaimBlockingReason::DecompressionCostExceedsBudget {
            observed_millionths: 100_000,
            budget_millionths: 50_000,
        },
        ClaimBlockingReason::HiddenExpansionExceedsThreshold {
            observed_millionths: 200_000,
            threshold_millionths: 100_000,
        },
        ClaimBlockingReason::ProofOverheadExceedsThreshold {
            observed_millionths: 250_000,
            threshold_millionths: 150_000,
        },
        ClaimBlockingReason::ExcessiveDuplicateMass {
            remaining_millionths: 300_000,
            max_millionths: 200_000,
        },
        ClaimBlockingReason::IrreversibleArtifact {
            artifact_id: "art-1".to_string(),
        },
        ClaimBlockingReason::InsufficientFidelity {
            artifact_id: "art-2".to_string(),
            fidelity_millionths: 800_000,
            required_millionths: 999_000,
        },
        ClaimBlockingReason::SupportCostCeilingExceeded {
            observed_millionths: 300_000,
            ceiling_millionths: 200_000,
        },
        ClaimBlockingReason::NoCompressionData,
        ClaimBlockingReason::NetMemoryExpansion {
            net_change_bytes: -500,
        },
        ClaimBlockingReason::DebugReadabilityLost {
            source_id: "mod-x".to_string(),
        },
        ClaimBlockingReason::StackTraceAccuracyLost {
            source_id: "mod-y".to_string(),
        },
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: ClaimBlockingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

#[test]
fn test_serde_roundtrip_error() {
    let errors = vec![
        CompressionResidualError::LedgerFull {
            count: 100,
            max: 100,
        },
        CompressionResidualError::TooManyArtifacts {
            count: 2000,
            max: 1000,
        },
        CompressionResidualError::InvalidConfig {
            reason: "bad".to_string(),
        },
        CompressionResidualError::EmptyInput {
            context: "test".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: CompressionResidualError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn test_serde_roundtrip_residual_ledger() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "a".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 1000,
            compressed_size_bytes: 500,
            duplicate_mass_removed_bytes: 10,
            duplicate_mass_remaining_bytes: 2,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 100,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    ledger
        .append(&LedgerAppendInput {
            artifact_id: "b".to_string(),
            pass_kind: CompressionPassKind::EntropyCoding,
            original_size_bytes: 2000,
            compressed_size_bytes: 800,
            duplicate_mass_removed_bytes: 5,
            duplicate_mass_remaining_bytes: 1,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 50,
            epoch: epoch(2),
            timestamp_ns: ts(),
        })
        .unwrap();
    let json = serde_json::to_string(&ledger).unwrap();
    let back: ResidualLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
}

#[test]
fn test_serde_roundtrip_compression_residual_gate() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    gate.evaluate(&cold_start_input(pass)).unwrap();
    let json = serde_json::to_string(&gate).unwrap();
    let back: CompressionResidualGate = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, back);
}

// ---------------------------------------------------------------------------
// 31. Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_large_artifact_sizes_no_overflow() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![build_artifact_record(&BuildArtifactInput {
        artifact_id: "big".to_string(),
        original_size: u64::MAX / 2,
        compressed_size: u64::MAX / 4,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 100,
        duplicates_removed: 10,
        duplicates_remaining: 2,
    })];
    let pass = simple_pass(arts);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert!(receipt.aggregate_compression_ratio_millionths > 0);
}

#[test]
fn test_zero_cold_start_budget_us() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 500, true)];
    let pass = simple_pass(arts);
    let mut input = cold_start_input(pass);
    input.cold_start_total_budget_us = 0;
    // Should not divide by zero, and should not add decompression cost block
    let receipt = gate.evaluate(&input).unwrap();
    // But absolute restoration check still applies: 100us << 500_000us, so approved
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Approved);
}

#[test]
fn test_zero_proof_total_size_bytes() {
    let mut gate = CompressionResidualGate::new();
    let arts = vec![simple_artifact("a1", 1000, 3000, true)];
    let pass = simple_pass(arts);
    let mut input = proof_input(pass);
    input.proof_total_size_bytes = 0;
    // With zero proof size, overhead check is skipped
    let receipt = gate.evaluate(&input).unwrap();
    // No proof overhead block expected when proof_total_size_bytes is 0
    let has_proof_block = receipt
        .blocking_reasons
        .iter()
        .any(|r| matches!(r, ClaimBlockingReason::ProofOverheadExceedsThreshold { .. }));
    assert!(!has_proof_block);
}

#[test]
fn test_multiple_pass_results_aggregate() {
    let mut gate = CompressionResidualGate::new();
    let pass1 = build_pass_result(
        "p1",
        CompressionPassKind::Deduplication,
        vec![simple_artifact("a1", 1000, 500, true)],
        epoch(1),
        ts(),
    );
    let pass2 = build_pass_result(
        "p2",
        CompressionPassKind::EntropyCoding,
        vec![simple_artifact("a2", 2000, 800, true)],
        epoch(1),
        ts(),
    );
    let input = GateInput {
        surface: ClaimSurface::ColdStart,
        pass_results: vec![pass1, pass2],
        hidden_expansions: Vec::new(),
        support_costs: Vec::new(),
        reversibility_checks: Vec::new(),
        epoch: epoch(1),
        timestamp_ns: ts(),
        cold_start_total_budget_us: 10_000_000,
        proof_total_size_bytes: 0,
    };
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.passes_considered, 2);
    assert_eq!(receipt.artifacts_considered, 2);
    // 1300 / 3000 = 433_333
    assert_eq!(receipt.aggregate_compression_ratio_millionths, 433_333);
}

#[test]
fn test_ledger_mut_access() {
    let mut gate = CompressionResidualGate::new();
    gate.ledger_mut()
        .append(&LedgerAppendInput {
            artifact_id: "manual".to_string(),
            pass_kind: CompressionPassKind::Deduplication,
            original_size_bytes: 500,
            compressed_size_bytes: 200,
            duplicate_mass_removed_bytes: 5,
            duplicate_mass_remaining_bytes: 1,
            reversible: true,
            bytes_lost: 0,
            restoration_overhead_us: 50,
            epoch: epoch(1),
            timestamp_ns: ts(),
        })
        .unwrap();
    assert_eq!(gate.ledger().len(), 1);
    assert_eq!(gate.ledger().entries()[0].artifact_id, "manual");
}

// ---------------------------------------------------------------------------
// 32. Receipts accessor
// ---------------------------------------------------------------------------

#[test]
fn test_receipts_accessor_returns_all() {
    let mut gate = CompressionResidualGate::new();
    for i in 0..3 {
        let pass = simple_pass(vec![simple_artifact(&format!("a{i}"), 1000, 500, true)]);
        gate.evaluate(&cold_start_input(pass)).unwrap();
    }
    assert_eq!(gate.receipts().len(), 3);
    for (idx, receipt) in gate.receipts().iter().enumerate() {
        assert_eq!(receipt.surface, ClaimSurface::ColdStart);
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Approved);
        assert_eq!(receipt.artifacts_considered, 1);
        // Verify epoch is correct
        assert_eq!(receipt.epoch, epoch(1));
        let _ = idx;
    }
}
