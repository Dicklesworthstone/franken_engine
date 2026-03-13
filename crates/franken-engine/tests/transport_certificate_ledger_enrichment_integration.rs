#![forbid(unsafe_code)]
#![allow(
    clippy::too_many_arguments,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for the `transport_certificate_ledger` module.
//!
//! Covers Display uniqueness, serde roundtrips, cross-cutting transport
//! evaluation scenarios, residual ledger consistency, manifest summary
//! correctness, event lifecycle, degradation detection edge cases, and
//! deterministic hash behavior.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::transport_certificate_ledger::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn hash(label: &str) -> ContentHash {
    ContentHash::compute(label.as_bytes())
}

fn cell_x86_zen4() -> HardwareCell {
    HardwareCell::new("x86-zen4", "x86_64", "zen4", 256, 64)
}

fn cell_x86_alder() -> HardwareCell {
    HardwareCell::new("x86-alder", "x86_64", "alderlake", 256, 64)
}

fn cell_x86_avx512() -> HardwareCell {
    HardwareCell::new("x86-avx512", "x86_64", "sapphirerapids", 512, 64)
}

fn cell_arm_nv2() -> HardwareCell {
    HardwareCell::new("arm-nv2", "aarch64", "neoverse_v2", 128, 64)
}

fn cell_arm_a78() -> HardwareCell {
    HardwareCell::new("arm-a78", "aarch64", "cortex_a78", 128, 64)
}

fn cell_riscv() -> HardwareCell {
    HardwareCell::new("riscv-gen", "riscv64", "generic", 128, 64)
}

fn cell_arm_wide_cache() -> HardwareCell {
    HardwareCell::new("arm-wide", "aarch64", "neoverse_v2", 128, 128)
}

/// Convenience: evaluate and unwrap.
fn eval(
    kind: ArtifactKind,
    label: &str,
    source: &HardwareCell,
    target: &HardwareCell,
    src_perf: u64,
    tgt_perf: u64,
) -> TransportCertificate {
    evaluate_transport(kind, hash(label), source, target, src_perf, tgt_perf).unwrap()
}

// ---------------------------------------------------------------------------
// Constants — schema, bead, component, policy
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("transport_certificate_ledger"));
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn enrichment_constants_bead_id_nonempty() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_constants_component_matches_module_name() {
    assert_eq!(COMPONENT, "transport_certificate_ledger");
}

#[test]
fn enrichment_constants_policy_id_nonempty() {
    assert!(!POLICY_ID.is_empty());
    assert!(POLICY_ID.starts_with("RGC-"));
}

// ---------------------------------------------------------------------------
// ArtifactKind — Display uniqueness, as_str, serde, arch-sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_kind_display_uniqueness() {
    let mut displays = BTreeSet::new();
    for kind in ArtifactKind::ALL {
        displays.insert(kind.to_string());
    }
    assert_eq!(displays.len(), ArtifactKind::ALL.len());
}

#[test]
fn enrichment_artifact_kind_as_str_matches_display() {
    for kind in ArtifactKind::ALL {
        assert_eq!(kind.as_str(), kind.to_string());
    }
}

#[test]
fn enrichment_artifact_kind_serde_roundtrip_all() {
    for kind in ArtifactKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn enrichment_artifact_kind_all_has_seven_variants() {
    assert_eq!(ArtifactKind::ALL.len(), 7);
}

#[test]
fn enrichment_artifact_kind_arch_sensitive_partition() {
    // Arch-sensitive: SynthesizedKernel, AotModule, CodeLayout, SpeculationGuard
    let sensitive: Vec<_> = ArtifactKind::ALL
        .iter()
        .filter(|k| k.is_arch_sensitive())
        .collect();
    let not_sensitive: Vec<_> = ArtifactKind::ALL
        .iter()
        .filter(|k| !k.is_arch_sensitive())
        .collect();
    assert_eq!(sensitive.len(), 4);
    assert_eq!(not_sensitive.len(), 3);
    // Non-arch-sensitive: RewriteRule, CacheEntry, ProfileData
    assert!(!ArtifactKind::RewriteRule.is_arch_sensitive());
    assert!(!ArtifactKind::CacheEntry.is_arch_sensitive());
    assert!(!ArtifactKind::ProfileData.is_arch_sensitive());
}

#[test]
fn enrichment_artifact_kind_ordering_deterministic() {
    let mut kinds: Vec<ArtifactKind> = ArtifactKind::ALL.to_vec();
    kinds.reverse();
    kinds.sort();
    let sorted_strs: Vec<_> = kinds.iter().map(|k| k.as_str()).collect();
    let mut again = kinds.clone();
    again.sort();
    let again_strs: Vec<_> = again.iter().map(|k| k.as_str()).collect();
    assert_eq!(sorted_strs, again_strs);
}

// ---------------------------------------------------------------------------
// TransportOutcome — Display uniqueness, as_str, serde, usability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transport_outcome_display_uniqueness() {
    let outcomes = [
        TransportOutcome::FullTransport,
        TransportOutcome::PartialTransport,
        TransportOutcome::Degraded,
        TransportOutcome::Failed,
        TransportOutcome::Incompatible,
    ];
    let mut displays = BTreeSet::new();
    for o in &outcomes {
        displays.insert(o.to_string());
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_transport_outcome_as_str_matches_display() {
    let outcomes = [
        TransportOutcome::FullTransport,
        TransportOutcome::PartialTransport,
        TransportOutcome::Degraded,
        TransportOutcome::Failed,
        TransportOutcome::Incompatible,
    ];
    for o in &outcomes {
        assert_eq!(o.as_str(), o.to_string());
    }
}

#[test]
fn enrichment_transport_outcome_serde_roundtrip_all() {
    let outcomes = [
        TransportOutcome::FullTransport,
        TransportOutcome::PartialTransport,
        TransportOutcome::Degraded,
        TransportOutcome::Failed,
        TransportOutcome::Incompatible,
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let back: TransportOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

#[test]
fn enrichment_transport_outcome_usable_partition() {
    assert!(TransportOutcome::FullTransport.is_usable());
    assert!(TransportOutcome::PartialTransport.is_usable());
    assert!(TransportOutcome::Degraded.is_usable());
    assert!(!TransportOutcome::Failed.is_usable());
    assert!(!TransportOutcome::Incompatible.is_usable());
}

#[test]
fn enrichment_transport_outcome_is_full_only_for_full_transport() {
    assert!(TransportOutcome::FullTransport.is_full());
    assert!(!TransportOutcome::PartialTransport.is_full());
    assert!(!TransportOutcome::Degraded.is_full());
    assert!(!TransportOutcome::Failed.is_full());
    assert!(!TransportOutcome::Incompatible.is_full());
}

// ---------------------------------------------------------------------------
// DegradationReason — Display uniqueness, serde, penalty
// ---------------------------------------------------------------------------

#[test]
fn enrichment_degradation_reason_display_uniqueness_known_variants() {
    let reasons = [
        DegradationReason::MicroarchMismatch,
        DegradationReason::IsaMissing,
        DegradationReason::CachePressure,
        DegradationReason::AlignmentPenalty,
        DegradationReason::BranchPredictionDrift,
        DegradationReason::VectorizationUnavailable,
        DegradationReason::MemoryModelWeaker,
    ];
    let mut displays = BTreeSet::new();
    for r in &reasons {
        displays.insert(r.to_string());
    }
    assert_eq!(displays.len(), 7);
}

#[test]
fn enrichment_degradation_reason_as_str_matches_display() {
    let reasons = [
        DegradationReason::MicroarchMismatch,
        DegradationReason::IsaMissing,
        DegradationReason::CachePressure,
        DegradationReason::AlignmentPenalty,
        DegradationReason::BranchPredictionDrift,
        DegradationReason::VectorizationUnavailable,
        DegradationReason::MemoryModelWeaker,
    ];
    for r in &reasons {
        assert_eq!(r.as_str(), r.to_string());
    }
}

#[test]
fn enrichment_degradation_reason_unknown_preserves_string() {
    let r = DegradationReason::UnknownReason("thermal_throttle".into());
    assert_eq!(r.as_str(), "thermal_throttle");
    assert_eq!(r.to_string(), "thermal_throttle");
}

#[test]
fn enrichment_degradation_reason_serde_roundtrip_all_including_unknown() {
    let reasons = vec![
        DegradationReason::MicroarchMismatch,
        DegradationReason::IsaMissing,
        DegradationReason::CachePressure,
        DegradationReason::AlignmentPenalty,
        DegradationReason::BranchPredictionDrift,
        DegradationReason::VectorizationUnavailable,
        DegradationReason::MemoryModelWeaker,
        DegradationReason::UnknownReason("custom_reason".into()),
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: DegradationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn enrichment_degradation_reason_penalty_isa_missing_is_largest_known() {
    let reasons = [
        DegradationReason::MicroarchMismatch,
        DegradationReason::CachePressure,
        DegradationReason::AlignmentPenalty,
        DegradationReason::BranchPredictionDrift,
        DegradationReason::VectorizationUnavailable,
        DegradationReason::MemoryModelWeaker,
    ];
    let isa_penalty = DegradationReason::IsaMissing.penalty_millionths();
    for r in &reasons {
        assert!(
            isa_penalty >= r.penalty_millionths(),
            "IsaMissing penalty ({}) should be >= {} penalty ({})",
            isa_penalty,
            r.as_str(),
            r.penalty_millionths()
        );
    }
}

#[test]
fn enrichment_degradation_reason_unknown_penalty_is_default() {
    let unknown = DegradationReason::UnknownReason("anything".into());
    assert_eq!(unknown.penalty_millionths(), 100_000);
}

#[test]
fn enrichment_degradation_reason_all_penalties_nonzero() {
    let reasons = vec![
        DegradationReason::MicroarchMismatch,
        DegradationReason::IsaMissing,
        DegradationReason::CachePressure,
        DegradationReason::AlignmentPenalty,
        DegradationReason::BranchPredictionDrift,
        DegradationReason::VectorizationUnavailable,
        DegradationReason::MemoryModelWeaker,
        DegradationReason::UnknownReason("x".into()),
    ];
    for r in &reasons {
        assert!(r.penalty_millionths() > 0, "{} has zero penalty", r);
    }
}

// ---------------------------------------------------------------------------
// HardwareCell — construction, comparison, Display, serde, hash
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hardware_cell_same_arch_same_microarch_different_ids() {
    let a = HardwareCell::new("node-a", "x86_64", "zen4", 256, 64);
    let b = HardwareCell::new("node-b", "x86_64", "zen4", 256, 64);
    assert!(a.same_arch_family(&b));
    assert!(a.same_microarch(&b));
    assert!(a.hardware_equivalent(&b));
    assert_ne!(a.cell_id, b.cell_id);
}

#[test]
fn enrichment_hardware_cell_same_arch_different_microarch() {
    let zen4 = cell_x86_zen4();
    let alder = cell_x86_alder();
    assert!(zen4.same_arch_family(&alder));
    assert!(!zen4.same_microarch(&alder));
    assert!(!zen4.hardware_equivalent(&alder));
}

#[test]
fn enrichment_hardware_cell_different_arch_families() {
    let x86 = cell_x86_zen4();
    let arm = cell_arm_nv2();
    assert!(!x86.same_arch_family(&arm));
    assert!(!x86.same_microarch(&arm));
    assert!(!x86.hardware_equivalent(&arm));
}

#[test]
fn enrichment_hardware_cell_vector_width_breaks_equivalence() {
    let a = HardwareCell::new("cell-a", "x86_64", "zen4", 256, 64);
    let b = HardwareCell::new("cell-b", "x86_64", "zen4", 512, 64);
    assert!(a.same_arch_family(&b));
    assert!(a.same_microarch(&b));
    assert!(!a.hardware_equivalent(&b));
}

#[test]
fn enrichment_hardware_cell_cache_line_breaks_equivalence() {
    let a = HardwareCell::new("cell-a", "aarch64", "neoverse_v2", 128, 64);
    let b = HardwareCell::new("cell-b", "aarch64", "neoverse_v2", 128, 128);
    assert!(a.same_arch_family(&b));
    assert!(a.same_microarch(&b));
    assert!(!a.hardware_equivalent(&b));
}

#[test]
fn enrichment_hardware_cell_display_contains_all_fields() {
    let cell = cell_x86_avx512();
    let s = cell.to_string();
    assert!(s.contains("x86-avx512"), "display missing cell_id");
    assert!(s.contains("x86_64"), "display missing arch_family");
    assert!(s.contains("sapphirerapids"), "display missing microarch");
    assert!(s.contains("512"), "display missing vector_width");
    assert!(s.contains("64"), "display missing cache_line");
}

#[test]
fn enrichment_hardware_cell_serde_roundtrip() {
    let cell = cell_arm_nv2();
    let json = serde_json::to_string(&cell).unwrap();
    let back: HardwareCell = serde_json::from_str(&json).unwrap();
    assert_eq!(cell, back);
}

#[test]
fn enrichment_hardware_cell_content_hash_deterministic() {
    let a = cell_riscv();
    let b = cell_riscv();
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn enrichment_hardware_cell_content_hash_differs_for_different_cells() {
    let x86 = cell_x86_zen4();
    let arm = cell_arm_nv2();
    assert_ne!(x86.content_hash(), arm.content_hash());
}

// ---------------------------------------------------------------------------
// TransportError — Display uniqueness, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transport_error_display_uniqueness() {
    let errors = [
        TransportError::CellIncompatible,
        TransportError::ArtifactCorrupted,
        TransportError::MeasurementFailed,
        TransportError::LedgerInconsistent,
        TransportError::InternalError("test".into()),
    ];
    let mut displays = BTreeSet::new();
    for e in &errors {
        displays.insert(e.to_string());
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_transport_error_internal_preserves_message() {
    let e = TransportError::InternalError("overflow in component sum".into());
    let s = e.to_string();
    assert!(s.contains("overflow in component sum"));
    assert!(s.contains("internal error"));
}

#[test]
fn enrichment_transport_error_serde_roundtrip_all() {
    let errors = vec![
        TransportError::CellIncompatible,
        TransportError::ArtifactCorrupted,
        TransportError::MeasurementFailed,
        TransportError::LedgerInconsistent,
        TransportError::InternalError("msg".into()),
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: TransportError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn enrichment_transport_error_display_no_duplicates_between_variants() {
    let e1 = TransportError::CellIncompatible;
    let e2 = TransportError::ArtifactCorrupted;
    let e3 = TransportError::MeasurementFailed;
    let e4 = TransportError::LedgerInconsistent;
    let strs = [
        e1.to_string(),
        e2.to_string(),
        e3.to_string(),
        e4.to_string(),
    ];
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ---------------------------------------------------------------------------
// classify_outcome — boundary values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_classify_outcome_boundary_full_transport() {
    // At exactly 950_000 (95%) -> FullTransport
    assert_eq!(classify_outcome(950_000), TransportOutcome::FullTransport);
    // At 949_999 -> PartialTransport
    assert_eq!(
        classify_outcome(949_999),
        TransportOutcome::PartialTransport
    );
}

#[test]
fn enrichment_classify_outcome_boundary_partial_transport() {
    assert_eq!(
        classify_outcome(700_000),
        TransportOutcome::PartialTransport
    );
    assert_eq!(classify_outcome(699_999), TransportOutcome::Degraded);
}

#[test]
fn enrichment_classify_outcome_boundary_degraded() {
    assert_eq!(classify_outcome(300_000), TransportOutcome::Degraded);
    assert_eq!(classify_outcome(299_999), TransportOutcome::Failed);
}

#[test]
fn enrichment_classify_outcome_zero_is_failed() {
    assert_eq!(classify_outcome(0), TransportOutcome::Failed);
}

#[test]
fn enrichment_classify_outcome_million_is_full() {
    assert_eq!(classify_outcome(1_000_000), TransportOutcome::FullTransport);
}

#[test]
fn enrichment_classify_outcome_above_million_still_full() {
    // Values above 1M are accepted and classified as full
    assert_eq!(classify_outcome(2_000_000), TransportOutcome::FullTransport);
}

// ---------------------------------------------------------------------------
// compute_residual_fraction — edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_residual_fraction_equal_perf_yields_million() {
    assert_eq!(compute_residual_fraction(500_000, 500_000), 1_000_000);
}

#[test]
fn enrichment_residual_fraction_zero_source_returns_million() {
    assert_eq!(compute_residual_fraction(0, 123_456), 1_000_000);
}

#[test]
fn enrichment_residual_fraction_zero_both_returns_million() {
    assert_eq!(compute_residual_fraction(0, 0), 1_000_000);
}

#[test]
fn enrichment_residual_fraction_zero_target_returns_zero() {
    assert_eq!(compute_residual_fraction(1_000_000, 0), 0);
}

#[test]
fn enrichment_residual_fraction_target_exceeds_source_capped() {
    // Target better than source -> capped at 1_000_000
    assert_eq!(compute_residual_fraction(500_000, 1_000_000), 1_000_000);
}

#[test]
fn enrichment_residual_fraction_quarter_perf() {
    assert_eq!(compute_residual_fraction(1_000_000, 250_000), 250_000);
}

#[test]
fn enrichment_residual_fraction_scaled_values() {
    // 8M out of 10M -> 800_000 millionths (80%)
    assert_eq!(compute_residual_fraction(10_000_000, 8_000_000), 800_000);
}

// ---------------------------------------------------------------------------
// detect_degradation — cross-cutting scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_detect_degradation_same_cell_empty() {
    let cell = cell_x86_zen4();
    let reasons = detect_degradation(&cell, &cell);
    assert!(reasons.is_empty());
}

#[test]
fn enrichment_detect_degradation_same_arch_diff_microarch_produces_two() {
    let reasons = detect_degradation(&cell_x86_zen4(), &cell_x86_alder());
    assert!(reasons.contains(&DegradationReason::MicroarchMismatch));
    assert!(reasons.contains(&DegradationReason::BranchPredictionDrift));
    // Should NOT contain cross-arch reasons
    assert!(!reasons.contains(&DegradationReason::IsaMissing));
    assert!(!reasons.contains(&DegradationReason::MemoryModelWeaker));
}

#[test]
fn enrichment_detect_degradation_cross_arch_contains_isa_and_memory() {
    let reasons = detect_degradation(&cell_x86_zen4(), &cell_arm_nv2());
    assert!(reasons.contains(&DegradationReason::IsaMissing));
    assert!(reasons.contains(&DegradationReason::MemoryModelWeaker));
    // Cross-arch should NOT trigger microarch-specific checks
    assert!(!reasons.contains(&DegradationReason::MicroarchMismatch));
}

#[test]
fn enrichment_detect_degradation_vector_width_reduction() {
    // 512-bit to 256-bit
    let reasons = detect_degradation(&cell_x86_avx512(), &cell_x86_zen4());
    assert!(reasons.contains(&DegradationReason::VectorizationUnavailable));
}

#[test]
fn enrichment_detect_degradation_vector_width_increase_no_penalty() {
    // 256-bit to 512-bit should NOT penalize
    let reasons = detect_degradation(&cell_x86_zen4(), &cell_x86_avx512());
    assert!(!reasons.contains(&DegradationReason::VectorizationUnavailable));
}

#[test]
fn enrichment_detect_degradation_cache_line_increase_triggers_alignment() {
    // target.cache_line_bytes > source.cache_line_bytes -> CachePressure + AlignmentPenalty
    let source = cell_arm_nv2(); // 64-byte
    let target = cell_arm_wide_cache(); // 128-byte
    let reasons = detect_degradation(&source, &target);
    assert!(reasons.contains(&DegradationReason::CachePressure));
    assert!(reasons.contains(&DegradationReason::AlignmentPenalty));
}

#[test]
fn enrichment_detect_degradation_cache_line_decrease_no_alignment() {
    // target smaller cache line -> CachePressure but NO AlignmentPenalty
    let source = cell_arm_wide_cache(); // 128-byte
    let target = cell_arm_nv2(); // 64-byte
    let reasons = detect_degradation(&source, &target);
    assert!(reasons.contains(&DegradationReason::CachePressure));
    assert!(!reasons.contains(&DegradationReason::AlignmentPenalty));
}

#[test]
fn enrichment_detect_degradation_cross_arch_plus_vector_reduction() {
    // x86 AVX-512 -> ARM 128-bit: cross-arch + vector reduction
    let reasons = detect_degradation(&cell_x86_avx512(), &cell_arm_nv2());
    assert!(reasons.contains(&DegradationReason::IsaMissing));
    assert!(reasons.contains(&DegradationReason::MemoryModelWeaker));
    assert!(reasons.contains(&DegradationReason::VectorizationUnavailable));
}

#[test]
fn enrichment_detect_degradation_three_arch_triangle() {
    // x86 -> ARM, ARM -> RISC-V, RISC-V -> x86: all should have cross-arch reasons
    let pairs = [
        (cell_x86_zen4(), cell_arm_nv2()),
        (cell_arm_nv2(), cell_riscv()),
        (cell_riscv(), cell_x86_zen4()),
    ];
    for (src, tgt) in &pairs {
        let reasons = detect_degradation(src, tgt);
        assert!(
            reasons.contains(&DegradationReason::IsaMissing),
            "cross-arch {} -> {} should flag ISA missing",
            src.arch_family,
            tgt.arch_family,
        );
    }
}

// ---------------------------------------------------------------------------
// evaluate_transport — integration scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_same_cell_full_transport_all_artifact_kinds() {
    let cell = cell_x86_zen4();
    for kind in ArtifactKind::ALL {
        let cert = eval(
            *kind,
            &format!("same-{}", kind.as_str()),
            &cell,
            &cell,
            1_000_000,
            1_000_000,
        );
        assert_eq!(cert.outcome, TransportOutcome::FullTransport);
        assert!(cert.is_usable());
        assert!(cert.is_full_transport());
        assert_eq!(cert.performance_loss_millionths(), 0);
        assert_eq!(cert.degradation_count(), 0);
    }
}

#[test]
fn enrichment_evaluate_cross_arch_arch_sensitive_always_incompatible() {
    let src = cell_x86_zen4();
    let tgt = cell_arm_nv2();
    let sensitive_kinds = [
        ArtifactKind::AotModule,
        ArtifactKind::SynthesizedKernel,
        ArtifactKind::CodeLayout,
        ArtifactKind::SpeculationGuard,
    ];
    for kind in &sensitive_kinds {
        let cert = eval(
            *kind,
            &format!("xarch-{}", kind.as_str()),
            &src,
            &tgt,
            1_000_000,
            800_000,
        );
        assert_eq!(
            cert.outcome,
            TransportOutcome::Incompatible,
            "{} should be incompatible cross-arch",
            kind.as_str()
        );
        assert!(!cert.is_usable());
    }
}

#[test]
fn enrichment_evaluate_cross_arch_non_sensitive_uses_residual() {
    let src = cell_x86_zen4();
    let tgt = cell_arm_nv2();
    let non_sensitive_kinds = [
        ArtifactKind::RewriteRule,
        ArtifactKind::CacheEntry,
        ArtifactKind::ProfileData,
    ];
    for kind in &non_sensitive_kinds {
        let cert = eval(
            *kind,
            &format!("xarch-ns-{}", kind.as_str()),
            &src,
            &tgt,
            1_000_000,
            800_000,
        );
        // Not incompatible because not arch-sensitive
        assert_ne!(cert.outcome, TransportOutcome::Incompatible);
        // 800k/1M = 80%, which is PartialTransport
        assert_eq!(cert.outcome, TransportOutcome::PartialTransport);
    }
}

#[test]
fn enrichment_evaluate_certificate_id_starts_with_tc_prefix() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "prefix-check",
        &cell_x86_zen4(),
        &cell_arm_nv2(),
        1_000_000,
        500_000,
    );
    assert!(cert.certificate_id.starts_with("tc-"));
}

#[test]
fn enrichment_evaluate_certificate_id_deterministic_same_inputs() {
    let src = cell_x86_zen4();
    let tgt = cell_x86_alder();
    let h = hash("det-test");
    let c1 =
        evaluate_transport(ArtifactKind::CacheEntry, h, &src, &tgt, 1_000_000, 900_000).unwrap();
    let c2 =
        evaluate_transport(ArtifactKind::CacheEntry, h, &src, &tgt, 1_000_000, 900_000).unwrap();
    assert_eq!(c1.certificate_id, c2.certificate_id);
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn enrichment_evaluate_certificate_id_differs_for_different_artifacts() {
    let src = cell_x86_zen4();
    let tgt = cell_x86_alder();
    let c1 = eval(
        ArtifactKind::CacheEntry,
        "art-a",
        &src,
        &tgt,
        1_000_000,
        900_000,
    );
    let c2 = eval(
        ArtifactKind::CacheEntry,
        "art-b",
        &src,
        &tgt,
        1_000_000,
        900_000,
    );
    assert_ne!(c1.certificate_id, c2.certificate_id);
}

#[test]
fn enrichment_evaluate_performance_loss_complement() {
    let cert = eval(
        ArtifactKind::ProfileData,
        "loss",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        750_000,
    );
    assert_eq!(
        cert.residual_fraction_millionths + cert.performance_loss_millionths(),
        1_000_000
    );
}

#[test]
fn enrichment_evaluate_same_hardware_check() {
    let cell = cell_x86_zen4();
    let cert = eval(
        ArtifactKind::RewriteRule,
        "hw",
        &cell,
        &cell,
        1_000_000,
        1_000_000,
    );
    assert!(cert.same_arch_family());
    assert!(cert.same_hardware());
}

#[test]
fn enrichment_evaluate_different_arch_same_hardware_false() {
    let cert = eval(
        ArtifactKind::ProfileData,
        "xarch",
        &cell_x86_zen4(),
        &cell_arm_nv2(),
        1_000_000,
        500_000,
    );
    assert!(!cert.same_arch_family());
    assert!(!cert.same_hardware());
}

#[test]
fn enrichment_evaluate_certificate_serde_roundtrip() {
    let cert = eval(
        ArtifactKind::SynthesizedKernel,
        "serde-cert",
        &cell_x86_avx512(),
        &cell_x86_zen4(),
        1_000_000,
        700_000,
    );
    let json = serde_json::to_string(&cert).unwrap();
    let back: TransportCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

#[test]
fn enrichment_evaluate_certificate_display_contains_key_info() {
    let cert = eval(
        ArtifactKind::AotModule,
        "disp",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let s = cert.to_string();
    assert!(s.contains("aot_module"));
    assert!(s.contains("x86-zen4"));
    assert!(s.contains("x86-alder"));
    assert!(s.contains("800000"));
}

// ---------------------------------------------------------------------------
// ResidualComponent — construction, computation, Display, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_residual_component_survival_fraction_full() {
    let comp = ResidualComponent::new("perfect", 500_000, 500_000, "no loss");
    assert_eq!(comp.survival_fraction_millionths(), 1_000_000);
    assert_eq!(comp.loss_millionths(), 0);
}

#[test]
fn enrichment_residual_component_survival_fraction_half() {
    let comp = ResidualComponent::new("half", 400_000, 200_000, "half lost");
    assert_eq!(comp.survival_fraction_millionths(), 500_000);
    assert_eq!(comp.loss_millionths(), 200_000);
}

#[test]
fn enrichment_residual_component_survival_fraction_zero_source() {
    let comp = ResidualComponent::new("zero-src", 0, 0, "vacuous");
    assert_eq!(comp.survival_fraction_millionths(), 1_000_000);
}

#[test]
fn enrichment_residual_component_survival_fraction_total_loss() {
    let comp = ResidualComponent::new("dead", 300_000, 0, "total loss");
    assert_eq!(comp.survival_fraction_millionths(), 0);
    assert_eq!(comp.loss_millionths(), 300_000);
}

#[test]
fn enrichment_residual_component_display_contains_name_and_values() {
    let comp = ResidualComponent::new("branch_pred", 200_000, 150_000, "cold tables");
    let s = comp.to_string();
    assert!(s.contains("branch_pred"));
    assert!(s.contains("200000"));
    assert!(s.contains("150000"));
    // Loss should be 50_000
    assert!(s.contains("50000"));
}

#[test]
fn enrichment_residual_component_serde_roundtrip() {
    let comp = ResidualComponent::new("cache_locality", 600_000, 480_000, "eviction pressure");
    let json = serde_json::to_string(&comp).unwrap();
    let back: ResidualComponent = serde_json::from_str(&json).unwrap();
    assert_eq!(comp, back);
}

// ---------------------------------------------------------------------------
// build_residual_ledger + validate_ledger_consistency — integration
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_ledger_basic_then_validate() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "led-basic",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let components = vec![
        ResidualComponent::new("branch", 400_000, 350_000, "cold tables"),
        ResidualComponent::new("cache", 300_000, 250_000, "eviction"),
        ResidualComponent::new("misc", 200_000, 180_000, "other"),
    ];
    let ledger = build_residual_ledger(&cert, components).unwrap();
    assert_eq!(ledger.total_source_millionths, 900_000);
    assert_eq!(ledger.total_transported_millionths, 780_000);
    assert_eq!(ledger.component_count(), 3);
    // Validation should pass for ledger built by build_residual_ledger
    assert!(validate_ledger_consistency(&ledger).is_ok());
}

#[test]
fn enrichment_build_ledger_empty_components_valid() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "led-empty",
        &cell_x86_zen4(),
        &cell_x86_zen4(),
        1_000_000,
        1_000_000,
    );
    let ledger = build_residual_ledger(&cert, vec![]).unwrap();
    assert_eq!(ledger.total_source_millionths, 0);
    assert_eq!(ledger.total_transported_millionths, 0);
    assert_eq!(ledger.component_count(), 0);
    assert!(validate_ledger_consistency(&ledger).is_ok());
}

#[test]
fn enrichment_build_ledger_exceeds_cert_source_returns_error() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "exceed",
        &cell_x86_zen4(),
        &cell_x86_zen4(),
        500_000,
        500_000,
    );
    // Component source totals exceed cert source_perf
    let components = vec![
        ResidualComponent::new("a", 400_000, 300_000, "x"),
        ResidualComponent::new("b", 200_000, 150_000, "y"),
    ];
    let result = build_residual_ledger(&cert, components);
    assert!(result.is_err());
}

#[test]
fn enrichment_build_ledger_too_many_components_returns_error() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "many-comps",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        u64::MAX / 2,
        u64::MAX / 4,
    );
    // 129 components (over MAX_LEDGER_COMPONENTS = 128)
    let components: Vec<_> = (0..129)
        .map(|i| ResidualComponent::new(&format!("comp-{i}"), 1, 1, "tiny"))
        .collect();
    let result = build_residual_ledger(&cert, components);
    assert!(result.is_err());
    let err = result.unwrap_err();
    // Should be InternalError, not LedgerInconsistent
    match err {
        TransportError::InternalError(msg) => assert!(msg.contains("too many components")),
        other => panic!("expected InternalError, got: {:?}", other),
    }
}

#[test]
fn enrichment_build_ledger_id_prefixed_with_ledger() {
    let cert = eval(
        ArtifactKind::ProfileData,
        "id-test",
        &cell_arm_nv2(),
        &cell_arm_a78(),
        1_000_000,
        900_000,
    );
    let ledger = build_residual_ledger(&cert, vec![]).unwrap();
    assert!(ledger.ledger_id.starts_with("ledger-"));
    assert!(ledger.ledger_id.contains(&cert.certificate_id));
}

#[test]
fn enrichment_build_ledger_unexplained_remainder() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "unexp",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    // Components account for less than the target perf
    let components = vec![ResidualComponent::new("partial", 500_000, 400_000, "x")];
    let ledger = build_residual_ledger(&cert, components).unwrap();
    // unexplained = cert.target_perf - sum(transported) = 800_000 - 400_000 = 400_000
    assert_eq!(ledger.unexplained_remainder_millionths, 400_000);
}

#[test]
fn enrichment_build_ledger_serde_roundtrip() {
    let cert = eval(
        ArtifactKind::CodeLayout,
        "led-serde",
        &cell_arm_nv2(),
        &cell_arm_a78(),
        1_000_000,
        900_000,
    );
    let components = vec![ResidualComponent::new(
        "layout",
        500_000,
        450_000,
        "reorder cost",
    )];
    let ledger = build_residual_ledger(&cert, components).unwrap();
    let json = serde_json::to_string(&ledger).unwrap();
    let back: ResidualLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
}

#[test]
fn enrichment_build_ledger_deterministic_hash() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "det-led",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let c1 = vec![ResidualComponent::new("a", 300_000, 250_000, "x")];
    let c2 = vec![ResidualComponent::new("a", 300_000, 250_000, "x")];
    let l1 = build_residual_ledger(&cert, c1).unwrap();
    let l2 = build_residual_ledger(&cert, c2).unwrap();
    assert_eq!(l1.content_hash, l2.content_hash);
}

#[test]
fn enrichment_build_ledger_display_contains_key_info() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "disp-led",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let ledger = build_residual_ledger(&cert, vec![]).unwrap();
    let s = ledger.to_string();
    assert!(s.contains("ledger:"));
    assert!(s.contains("cert="));
    assert!(s.contains("components="));
}

#[test]
fn enrichment_build_ledger_component_by_name_found() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "lookup",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let components = vec![
        ResidualComponent::new("branch", 400_000, 350_000, "x"),
        ResidualComponent::new("cache", 300_000, 250_000, "y"),
    ];
    let ledger = build_residual_ledger(&cert, components).unwrap();
    let branch = ledger.component_by_name("branch").unwrap();
    assert_eq!(branch.source_contribution_millionths, 400_000);
    assert!(ledger.component_by_name("missing").is_none());
}

#[test]
fn enrichment_build_ledger_survival_fraction() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "surv-led",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let components = vec![
        ResidualComponent::new("a", 600_000, 480_000, "x"),
        ResidualComponent::new("b", 400_000, 320_000, "y"),
    ];
    let ledger = build_residual_ledger(&cert, components).unwrap();
    // survival = 800_000 / 1_000_000 * 1M = 800_000
    assert_eq!(ledger.survival_fraction_millionths(), 800_000);
    assert_eq!(ledger.total_loss_millionths(), 200_000);
}

#[test]
fn enrichment_build_ledger_survival_fraction_zero_source() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "zero-surv",
        &cell_x86_zen4(),
        &cell_x86_zen4(),
        1_000_000,
        1_000_000,
    );
    let ledger = build_residual_ledger(&cert, vec![]).unwrap();
    assert_eq!(ledger.survival_fraction_millionths(), 1_000_000);
}

// ---------------------------------------------------------------------------
// validate_ledger_consistency — failure scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_ledger_source_mismatch_error() {
    let ledger = ResidualLedger {
        ledger_id: "bad-src".into(),
        certificate_id: "cert-x".into(),
        components: vec![ResidualComponent::new("a", 100_000, 80_000, "x")],
        total_source_millionths: 999_999, // wrong
        total_transported_millionths: 80_000,
        unexplained_remainder_millionths: 0,
        content_hash: ContentHash::compute(b"bad-src"),
    };
    let result = validate_ledger_consistency(&ledger);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TransportError::LedgerInconsistent);
}

#[test]
fn enrichment_validate_ledger_transported_exceeds_source_error() {
    let ledger = ResidualLedger {
        ledger_id: "bad-xport".into(),
        certificate_id: "cert-y".into(),
        components: vec![ResidualComponent::new("a", 100_000, 200_000, "impossible")],
        total_source_millionths: 100_000,
        total_transported_millionths: 200_000,
        unexplained_remainder_millionths: 0,
        content_hash: ContentHash::compute(b"bad-xport"),
    };
    let result = validate_ledger_consistency(&ledger);
    assert!(result.is_err());
}

#[test]
fn enrichment_validate_ledger_transported_total_mismatch_error() {
    let ledger = ResidualLedger {
        ledger_id: "bad-total".into(),
        certificate_id: "cert-z".into(),
        components: vec![ResidualComponent::new("a", 100_000, 80_000, "x")],
        total_source_millionths: 100_000,
        total_transported_millionths: 999_000, // wrong
        unexplained_remainder_millionths: 0,
        content_hash: ContentHash::compute(b"bad-total"),
    };
    let result = validate_ledger_consistency(&ledger);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// franken_engine_transport_manifest — manifest correctness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_nonempty() {
    let certs = franken_engine_transport_manifest();
    assert!(certs.len() >= 10);
}

#[test]
fn enrichment_manifest_covers_all_outcome_types() {
    let certs = franken_engine_transport_manifest();
    let outcomes: BTreeSet<_> = certs.iter().map(|c| c.outcome).collect();
    assert!(outcomes.contains(&TransportOutcome::FullTransport));
    assert!(outcomes.contains(&TransportOutcome::Incompatible));
    // Should have at least FullTransport and Incompatible; check for more
    assert!(
        outcomes.len() >= 3,
        "manifest should cover at least 3 outcome types"
    );
}

#[test]
fn enrichment_manifest_covers_diverse_artifact_kinds() {
    let certs = franken_engine_transport_manifest();
    let kinds: BTreeSet<_> = certs.iter().map(|c| c.artifact_kind).collect();
    assert!(
        kinds.len() >= 5,
        "manifest should cover at least 5 artifact kinds, got {}",
        kinds.len()
    );
}

#[test]
fn enrichment_manifest_has_cross_arch_certificates() {
    let certs = franken_engine_transport_manifest();
    let cross_arch_count = certs.iter().filter(|c| !c.same_arch_family()).count();
    assert!(
        cross_arch_count >= 2,
        "manifest should have at least 2 cross-arch certificates"
    );
}

#[test]
fn enrichment_manifest_has_same_arch_certificates() {
    let certs = franken_engine_transport_manifest();
    let same_arch_count = certs.iter().filter(|c| c.same_arch_family()).count();
    assert!(
        same_arch_count >= 2,
        "manifest should have at least 2 same-arch certificates"
    );
}

#[test]
fn enrichment_manifest_certificate_ids_unique() {
    let certs = franken_engine_transport_manifest();
    let ids: BTreeSet<_> = certs.iter().map(|c| c.certificate_id.clone()).collect();
    assert_eq!(
        ids.len(),
        certs.len(),
        "all certificate IDs should be unique"
    );
}

#[test]
fn enrichment_manifest_all_cert_ids_start_with_tc() {
    let certs = franken_engine_transport_manifest();
    for cert in &certs {
        assert!(
            cert.certificate_id.starts_with("tc-"),
            "cert ID {} should start with tc-",
            cert.certificate_id
        );
    }
}

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let certs = franken_engine_transport_manifest();
    let json = serde_json::to_string(&certs).unwrap();
    let back: Vec<TransportCertificate> = serde_json::from_str(&json).unwrap();
    assert_eq!(certs, back);
}

// ---------------------------------------------------------------------------
// TransportManifestSummary — build, queries, Display, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_summary_counts_match_total() {
    let certs = franken_engine_transport_manifest();
    let summary = TransportManifestSummary::build(&certs);
    assert_eq!(summary.total_certificates, certs.len());
    let sum = summary.full_transport_count
        + summary.partial_transport_count
        + summary.degraded_count
        + summary.failed_count
        + summary.incompatible_count;
    assert_eq!(sum, summary.total_certificates);
}

#[test]
fn enrichment_manifest_summary_empty_set() {
    let summary = TransportManifestSummary::build(&[]);
    assert_eq!(summary.total_certificates, 0);
    assert_eq!(summary.avg_residual_fraction_millionths, 0);
    assert_eq!(summary.usability_rate_millionths(), 0);
    assert!(!summary.has_failures());
    assert!(summary.all_full_transport()); // vacuous truth
}

#[test]
fn enrichment_manifest_summary_single_full_transport() {
    let cell = cell_x86_zen4();
    let cert = eval(
        ArtifactKind::RewriteRule,
        "single-full",
        &cell,
        &cell,
        1_000_000,
        1_000_000,
    );
    let summary = TransportManifestSummary::build(&[cert]);
    assert_eq!(summary.total_certificates, 1);
    assert_eq!(summary.full_transport_count, 1);
    assert!(summary.all_full_transport());
    assert!(!summary.has_failures());
    assert_eq!(summary.usability_rate_millionths(), 1_000_000);
    assert_eq!(summary.avg_residual_fraction_millionths, 1_000_000);
}

#[test]
fn enrichment_manifest_summary_single_failed() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "single-fail",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        100_000,
    );
    let summary = TransportManifestSummary::build(&[cert]);
    assert_eq!(summary.failed_count, 1);
    assert!(summary.has_failures());
    assert!(!summary.all_full_transport());
    assert_eq!(summary.usability_rate_millionths(), 0);
}

#[test]
fn enrichment_manifest_summary_has_failures_includes_incompatible() {
    let cert = eval(
        ArtifactKind::AotModule,
        "incompat",
        &cell_x86_zen4(),
        &cell_arm_nv2(),
        1_000_000,
        500_000,
    );
    let summary = TransportManifestSummary::build(&[cert]);
    assert!(summary.has_failures());
    assert_eq!(summary.incompatible_count, 1);
}

#[test]
fn enrichment_manifest_summary_usability_rate_mixed() {
    let cell = cell_x86_zen4();
    let c1 = eval(
        ArtifactKind::RewriteRule,
        "usable-1",
        &cell,
        &cell,
        1_000_000,
        1_000_000,
    );
    let c2 = eval(
        ArtifactKind::CacheEntry,
        "usable-2",
        &cell,
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let c3 = eval(
        ArtifactKind::ProfileData,
        "failed-3",
        &cell,
        &cell_x86_alder(),
        1_000_000,
        100_000,
    );
    let summary = TransportManifestSummary::build(&[c1, c2, c3]);
    // 2 usable out of 3 => 666_666 millionths
    assert_eq!(summary.usability_rate_millionths(), 666_666);
}

#[test]
fn enrichment_manifest_summary_serde_roundtrip() {
    let certs = franken_engine_transport_manifest();
    let summary = TransportManifestSummary::build(&certs);
    let json = serde_json::to_string(&summary).unwrap();
    let back: TransportManifestSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn enrichment_manifest_summary_deterministic_hash() {
    let certs = franken_engine_transport_manifest();
    let s1 = TransportManifestSummary::build(&certs);
    let s2 = TransportManifestSummary::build(&certs);
    assert_eq!(s1.content_hash, s2.content_hash);
}

#[test]
fn enrichment_manifest_summary_display_contains_key_fields() {
    let certs = franken_engine_transport_manifest();
    let summary = TransportManifestSummary::build(&certs);
    let s = summary.to_string();
    assert!(s.contains("manifest"));
    assert!(s.contains("total="));
    assert!(s.contains("full="));
    assert!(s.contains("failed="));
    assert!(s.contains("avg_residual="));
}

// ---------------------------------------------------------------------------
// TransportEventKind — Display uniqueness, as_str, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transport_event_kind_display_uniqueness() {
    let kinds = [
        TransportEventKind::CertificateCreated,
        TransportEventKind::LedgerBuilt,
        TransportEventKind::CertificateInvalidated,
        TransportEventKind::TransportReEvaluated,
    ];
    let mut displays = BTreeSet::new();
    for k in &kinds {
        displays.insert(k.to_string());
    }
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_transport_event_kind_as_str_matches_display() {
    let kinds = [
        TransportEventKind::CertificateCreated,
        TransportEventKind::LedgerBuilt,
        TransportEventKind::CertificateInvalidated,
        TransportEventKind::TransportReEvaluated,
    ];
    for k in &kinds {
        assert_eq!(k.as_str(), k.to_string());
    }
}

#[test]
fn enrichment_transport_event_kind_serde_roundtrip() {
    let kinds = [
        TransportEventKind::CertificateCreated,
        TransportEventKind::LedgerBuilt,
        TransportEventKind::CertificateInvalidated,
        TransportEventKind::TransportReEvaluated,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: TransportEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// TransportEvent — from_certificate, fields, Display, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transport_event_from_certificate_fields_match() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "evt-match",
        &cell_x86_zen4(),
        &cell_arm_nv2(),
        1_000_000,
        500_000,
    );
    let evt =
        TransportEvent::from_certificate(&cert, TransportEventKind::CertificateCreated, epoch(42));
    assert_eq!(evt.kind, TransportEventKind::CertificateCreated);
    assert_eq!(evt.certificate_id, cert.certificate_id);
    assert_eq!(evt.artifact_kind, cert.artifact_kind);
    assert_eq!(evt.source_cell_id, cert.source_cell.cell_id);
    assert_eq!(evt.target_cell_id, cert.target_cell.cell_id);
    assert_eq!(evt.outcome, cert.outcome);
    assert_eq!(
        evt.residual_fraction_millionths,
        cert.residual_fraction_millionths
    );
    assert_eq!(evt.epoch, epoch(42));
}

#[test]
fn enrichment_transport_event_different_kinds_same_cert() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "evt-kinds",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        900_000,
    );
    let e1 =
        TransportEvent::from_certificate(&cert, TransportEventKind::CertificateCreated, epoch(1));
    let e2 = TransportEvent::from_certificate(&cert, TransportEventKind::LedgerBuilt, epoch(1));
    let e3 = TransportEvent::from_certificate(
        &cert,
        TransportEventKind::CertificateInvalidated,
        epoch(1),
    );
    let e4 =
        TransportEvent::from_certificate(&cert, TransportEventKind::TransportReEvaluated, epoch(1));
    // Same cert but different event kinds -> different content hashes
    let hashes: BTreeSet<_> = [
        e1.content_hash,
        e2.content_hash,
        e3.content_hash,
        e4.content_hash,
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(
        hashes.len(),
        4,
        "different event kinds should produce different content hashes"
    );
}

#[test]
fn enrichment_transport_event_different_epochs_different_hashes() {
    let cert = eval(
        ArtifactKind::ProfileData,
        "evt-epoch",
        &cell_arm_nv2(),
        &cell_arm_a78(),
        1_000_000,
        950_000,
    );
    let e1 =
        TransportEvent::from_certificate(&cert, TransportEventKind::CertificateCreated, epoch(1));
    let e2 =
        TransportEvent::from_certificate(&cert, TransportEventKind::CertificateCreated, epoch(2));
    assert_ne!(e1.content_hash, e2.content_hash);
}

#[test]
fn enrichment_transport_event_serde_roundtrip() {
    let cert = eval(
        ArtifactKind::SpeculationGuard,
        "evt-serde",
        &cell_x86_avx512(),
        &cell_x86_zen4(),
        1_000_000,
        700_000,
    );
    let evt = TransportEvent::from_certificate(&cert, TransportEventKind::LedgerBuilt, epoch(99));
    let json = serde_json::to_string(&evt).unwrap();
    let back: TransportEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

#[test]
fn enrichment_transport_event_display_contains_key_info() {
    let cert = eval(
        ArtifactKind::AotModule,
        "evt-disp",
        &cell_x86_zen4(),
        &cell_arm_nv2(),
        1_000_000,
        200_000,
    );
    let evt =
        TransportEvent::from_certificate(&cert, TransportEventKind::CertificateCreated, epoch(10));
    let s = evt.to_string();
    assert!(s.contains("certificate_created"));
    assert!(s.contains("x86-zen4"));
    assert!(s.contains("arm-nv2"));
}

// ---------------------------------------------------------------------------
// Cross-cutting integration scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_full_pipeline_evaluate_build_ledger_validate_event() {
    // End-to-end: evaluate transport -> build ledger -> validate -> create event
    let src = cell_x86_avx512();
    let tgt = cell_x86_zen4();
    let cert = eval(
        ArtifactKind::SynthesizedKernel,
        "pipeline",
        &src,
        &tgt,
        1_000_000,
        700_000,
    );

    // Build residual ledger
    let components = vec![
        ResidualComponent::new("vectorization", 400_000, 200_000, "AVX-512 -> AVX2"),
        ResidualComponent::new("branch_pred", 300_000, 280_000, "retrain cost"),
        ResidualComponent::new("cache", 200_000, 190_000, "similar cache lines"),
    ];
    let ledger = build_residual_ledger(&cert, components).unwrap();
    assert!(validate_ledger_consistency(&ledger).is_ok());

    // Check the ledger's survival fraction
    assert_eq!(ledger.total_source_millionths, 900_000);
    assert_eq!(ledger.total_transported_millionths, 670_000);

    // Look up individual component
    let vec_comp = ledger.component_by_name("vectorization").unwrap();
    assert_eq!(vec_comp.loss_millionths(), 200_000);

    // Create event
    let evt =
        TransportEvent::from_certificate(&cert, TransportEventKind::CertificateCreated, epoch(100));
    assert_eq!(evt.outcome, cert.outcome);

    // Create a second event for ledger build
    let evt2 = TransportEvent::from_certificate(&cert, TransportEventKind::LedgerBuilt, epoch(101));
    assert_ne!(evt.content_hash, evt2.content_hash);
}

#[test]
fn enrichment_manifest_to_summary_to_event_pipeline() {
    let certs = franken_engine_transport_manifest();
    let summary = TransportManifestSummary::build(&certs);

    // Summary should account for all certificates
    assert_eq!(summary.total_certificates, certs.len());

    // Create events for each certificate
    let events: Vec<_> = certs
        .iter()
        .map(|c| {
            TransportEvent::from_certificate(c, TransportEventKind::CertificateCreated, epoch(50))
        })
        .collect();

    // All events should have unique content hashes (different certs)
    let hashes: BTreeSet<_> = events.iter().map(|e| e.content_hash).collect();
    assert_eq!(hashes.len(), events.len());
}

#[test]
fn enrichment_cross_arch_roundtrip_both_directions() {
    // x86 -> ARM and ARM -> x86 for same non-arch-sensitive artifact
    let x86 = cell_x86_zen4();
    let arm = cell_arm_nv2();
    let c1 = eval(
        ArtifactKind::ProfileData,
        "x2a",
        &x86,
        &arm,
        1_000_000,
        600_000,
    );
    let c2 = eval(
        ArtifactKind::ProfileData,
        "a2x",
        &arm,
        &x86,
        1_000_000,
        600_000,
    );
    // Both should be Degraded (60%)
    assert_eq!(c1.outcome, TransportOutcome::Degraded);
    assert_eq!(c2.outcome, TransportOutcome::Degraded);
    // But different certificate IDs (different source/target order)
    assert_ne!(c1.certificate_id, c2.certificate_id);
}

#[test]
fn enrichment_arch_sensitive_identity_transport() {
    // Even arch-sensitive artifacts should be full transport on same cell
    let cell = cell_arm_nv2();
    for kind in ArtifactKind::ALL {
        if kind.is_arch_sensitive() {
            let cert = eval(
                *kind,
                &format!("id-{}", kind.as_str()),
                &cell,
                &cell,
                1_000_000,
                1_000_000,
            );
            assert_eq!(cert.outcome, TransportOutcome::FullTransport);
        }
    }
}

#[test]
fn enrichment_degradation_count_correlates_with_cell_difference() {
    let same = detect_degradation(&cell_x86_zen4(), &cell_x86_zen4());
    let same_arch = detect_degradation(&cell_x86_zen4(), &cell_x86_alder());
    let cross_arch = detect_degradation(&cell_x86_avx512(), &cell_arm_nv2());
    // More differences -> more degradation reasons
    assert!(same.len() <= same_arch.len());
    assert!(same_arch.len() <= cross_arch.len());
}

#[test]
fn enrichment_residual_ledger_balance_check_on_build() {
    // build_residual_ledger produces balanced ledgers (for simple cases)
    let cert = eval(
        ArtifactKind::CacheEntry,
        "balance",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let components = vec![
        ResidualComponent::new("a", 500_000, 400_000, "x"),
        ResidualComponent::new("b", 300_000, 250_000, "y"),
    ];
    let ledger = build_residual_ledger(&cert, components).unwrap();
    assert!(ledger.is_balanced());
}

#[test]
fn enrichment_performance_loss_zero_for_full_transport() {
    let cell = cell_arm_nv2();
    let cert = eval(
        ArtifactKind::RewriteRule,
        "zero-loss",
        &cell,
        &cell,
        1_000_000,
        1_000_000,
    );
    assert_eq!(cert.performance_loss_millionths(), 0);
}

#[test]
fn enrichment_performance_loss_saturates_at_million() {
    // Even if residual_fraction is 0, loss should be exactly 1_000_000
    let cert = eval(
        ArtifactKind::RewriteRule,
        "max-loss",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        0,
    );
    assert_eq!(cert.performance_loss_millionths(), 1_000_000);
    assert_eq!(cert.residual_fraction_millionths, 0);
}

// ===========================================================================
// Batch 2 enrichment tests — JSON field names, Clone/Debug, edge cases,
// ordering, error paths, determinism, advanced ledger scenarios
// ===========================================================================

// ---------------------------------------------------------------------------
// JSON field name validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hardware_cell_json_field_names() {
    let cell = cell_x86_zen4();
    let json = serde_json::to_string(&cell).unwrap();
    assert!(json.contains("\"cell_id\""));
    assert!(json.contains("\"arch_family\""));
    assert!(json.contains("\"microarch\""));
    assert!(json.contains("\"vector_width_bits\""));
    assert!(json.contains("\"cache_line_bytes\""));
}

#[test]
fn enrichment_transport_certificate_json_field_names() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "json-fields",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let json = serde_json::to_string(&cert).unwrap();
    assert!(json.contains("\"certificate_id\""));
    assert!(json.contains("\"artifact_kind\""));
    assert!(json.contains("\"artifact_hash\""));
    assert!(json.contains("\"source_cell\""));
    assert!(json.contains("\"target_cell\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"source_perf_millionths\""));
    assert!(json.contains("\"target_perf_millionths\""));
    assert!(json.contains("\"degradation_reasons\""));
    assert!(json.contains("\"residual_fraction_millionths\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_residual_component_json_field_names() {
    let comp = ResidualComponent::new("test_comp", 500_000, 400_000, "reason");
    let json = serde_json::to_string(&comp).unwrap();
    assert!(json.contains("\"component_name\""));
    assert!(json.contains("\"source_contribution_millionths\""));
    assert!(json.contains("\"transported_contribution_millionths\""));
    assert!(json.contains("\"explanation\""));
}

#[test]
fn enrichment_residual_ledger_json_field_names() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "led-json",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let ledger = build_residual_ledger(&cert, vec![]).unwrap();
    let json = serde_json::to_string(&ledger).unwrap();
    assert!(json.contains("\"ledger_id\""));
    assert!(json.contains("\"certificate_id\""));
    assert!(json.contains("\"components\""));
    assert!(json.contains("\"total_source_millionths\""));
    assert!(json.contains("\"total_transported_millionths\""));
    assert!(json.contains("\"unexplained_remainder_millionths\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_transport_manifest_summary_json_field_names() {
    let certs = franken_engine_transport_manifest();
    let summary = TransportManifestSummary::build(&certs);
    let json = serde_json::to_string(&summary).unwrap();
    assert!(json.contains("\"total_certificates\""));
    assert!(json.contains("\"full_transport_count\""));
    assert!(json.contains("\"partial_transport_count\""));
    assert!(json.contains("\"degraded_count\""));
    assert!(json.contains("\"failed_count\""));
    assert!(json.contains("\"incompatible_count\""));
    assert!(json.contains("\"avg_residual_fraction_millionths\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_transport_event_json_field_names() {
    let cert = eval(
        ArtifactKind::ProfileData,
        "evt-json",
        &cell_x86_zen4(),
        &cell_arm_nv2(),
        1_000_000,
        500_000,
    );
    let evt =
        TransportEvent::from_certificate(&cert, TransportEventKind::CertificateCreated, epoch(1));
    let json = serde_json::to_string(&evt).unwrap();
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"certificate_id\""));
    assert!(json.contains("\"artifact_kind\""));
    assert!(json.contains("\"source_cell_id\""));
    assert!(json.contains("\"target_cell_id\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"residual_fraction_millionths\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"content_hash\""));
}

// ---------------------------------------------------------------------------
// Clone trait verification
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_kind_clone() {
    let original = ArtifactKind::SynthesizedKernel;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_transport_outcome_clone() {
    let original = TransportOutcome::Degraded;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_degradation_reason_clone() {
    let original = DegradationReason::UnknownReason("test_clone".into());
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(cloned.as_str(), "test_clone");
}

#[test]
fn enrichment_hardware_cell_clone() {
    let original = cell_x86_avx512();
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.content_hash(), cloned.content_hash());
}

#[test]
fn enrichment_transport_error_clone() {
    let original = TransportError::InternalError("clone_test".into());
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_transport_certificate_clone() {
    let cert = eval(
        ArtifactKind::AotModule,
        "clone-cert",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        850_000,
    );
    let cloned = cert.clone();
    assert_eq!(cert, cloned);
    assert_eq!(cert.content_hash, cloned.content_hash);
}

#[test]
fn enrichment_residual_ledger_clone() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "clone-led",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let comps = vec![ResidualComponent::new("a", 300_000, 250_000, "x")];
    let ledger = build_residual_ledger(&cert, comps).unwrap();
    let cloned = ledger.clone();
    assert_eq!(ledger, cloned);
}

#[test]
fn enrichment_transport_manifest_summary_clone() {
    let certs = franken_engine_transport_manifest();
    let summary = TransportManifestSummary::build(&certs);
    let cloned = summary.clone();
    assert_eq!(summary, cloned);
}

#[test]
fn enrichment_transport_event_clone() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "clone-evt",
        &cell_arm_nv2(),
        &cell_arm_a78(),
        1_000_000,
        900_000,
    );
    let evt = TransportEvent::from_certificate(&cert, TransportEventKind::LedgerBuilt, epoch(7));
    let cloned = evt.clone();
    assert_eq!(evt, cloned);
}

// ---------------------------------------------------------------------------
// Debug trait verification
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_kind_debug_nonempty() {
    let dbg = format!("{:?}", ArtifactKind::SpeculationGuard);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("SpeculationGuard"));
}

#[test]
fn enrichment_transport_outcome_debug_nonempty() {
    let dbg = format!("{:?}", TransportOutcome::Incompatible);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Incompatible"));
}

#[test]
fn enrichment_degradation_reason_debug_unknown() {
    let dbg = format!("{:?}", DegradationReason::UnknownReason("dbg_test".into()));
    assert!(dbg.contains("UnknownReason"));
    assert!(dbg.contains("dbg_test"));
}

#[test]
fn enrichment_hardware_cell_debug_nonempty() {
    let dbg = format!("{:?}", cell_riscv());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("riscv-gen"));
}

#[test]
fn enrichment_transport_error_debug_nonempty() {
    let dbg = format!("{:?}", TransportError::LedgerInconsistent);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("LedgerInconsistent"));
}

#[test]
fn enrichment_transport_certificate_debug_nonempty() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "dbg-cert",
        &cell_x86_zen4(),
        &cell_arm_nv2(),
        1_000_000,
        400_000,
    );
    let dbg = format!("{:?}", cert);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("TransportCertificate"));
}

#[test]
fn enrichment_residual_ledger_debug_nonempty() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "dbg-led",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let ledger = build_residual_ledger(&cert, vec![]).unwrap();
    let dbg = format!("{:?}", ledger);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ResidualLedger"));
}

#[test]
fn enrichment_transport_event_kind_debug_nonempty() {
    let dbg = format!("{:?}", TransportEventKind::TransportReEvaluated);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("TransportReEvaluated"));
}

#[test]
fn enrichment_transport_manifest_summary_debug_nonempty() {
    let summary = TransportManifestSummary::build(&[]);
    let dbg = format!("{:?}", summary);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("TransportManifestSummary"));
}

// ---------------------------------------------------------------------------
// ArtifactKind — JSON serde values (snake_case rename)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_kind_serde_snake_case_values() {
    let expected = [
        (ArtifactKind::RewriteRule, "\"rewrite_rule\""),
        (ArtifactKind::SynthesizedKernel, "\"synthesized_kernel\""),
        (ArtifactKind::CacheEntry, "\"cache_entry\""),
        (ArtifactKind::AotModule, "\"aot_module\""),
        (ArtifactKind::CodeLayout, "\"code_layout\""),
        (ArtifactKind::ProfileData, "\"profile_data\""),
        (ArtifactKind::SpeculationGuard, "\"speculation_guard\""),
    ];
    for (kind, expected_json) in &expected {
        let json = serde_json::to_string(kind).unwrap();
        assert_eq!(
            &json, *expected_json,
            "ArtifactKind::{:?} serde mismatch",
            kind
        );
    }
}

#[test]
fn enrichment_transport_outcome_serde_snake_case_values() {
    let expected = [
        (TransportOutcome::FullTransport, "\"full_transport\""),
        (TransportOutcome::PartialTransport, "\"partial_transport\""),
        (TransportOutcome::Degraded, "\"degraded\""),
        (TransportOutcome::Failed, "\"failed\""),
        (TransportOutcome::Incompatible, "\"incompatible\""),
    ];
    for (outcome, expected_json) in &expected {
        let json = serde_json::to_string(outcome).unwrap();
        assert_eq!(
            &json, *expected_json,
            "TransportOutcome::{:?} serde mismatch",
            outcome
        );
    }
}

#[test]
fn enrichment_transport_event_kind_serde_snake_case_values() {
    let expected = [
        (
            TransportEventKind::CertificateCreated,
            "\"certificate_created\"",
        ),
        (TransportEventKind::LedgerBuilt, "\"ledger_built\""),
        (
            TransportEventKind::CertificateInvalidated,
            "\"certificate_invalidated\"",
        ),
        (
            TransportEventKind::TransportReEvaluated,
            "\"transport_re_evaluated\"",
        ),
    ];
    for (kind, expected_json) in &expected {
        let json = serde_json::to_string(kind).unwrap();
        assert_eq!(
            &json, *expected_json,
            "TransportEventKind::{:?} serde mismatch",
            kind
        );
    }
}

// ---------------------------------------------------------------------------
// DegradationReason — exact penalty values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_degradation_reason_exact_penalty_microarch_mismatch() {
    assert_eq!(
        DegradationReason::MicroarchMismatch.penalty_millionths(),
        100_000
    );
}

#[test]
fn enrichment_degradation_reason_exact_penalty_isa_missing() {
    assert_eq!(DegradationReason::IsaMissing.penalty_millionths(), 500_000);
}

#[test]
fn enrichment_degradation_reason_exact_penalty_cache_pressure() {
    assert_eq!(
        DegradationReason::CachePressure.penalty_millionths(),
        80_000
    );
}

#[test]
fn enrichment_degradation_reason_exact_penalty_alignment() {
    assert_eq!(
        DegradationReason::AlignmentPenalty.penalty_millionths(),
        50_000
    );
}

#[test]
fn enrichment_degradation_reason_exact_penalty_branch_prediction() {
    assert_eq!(
        DegradationReason::BranchPredictionDrift.penalty_millionths(),
        60_000
    );
}

#[test]
fn enrichment_degradation_reason_exact_penalty_vectorization() {
    assert_eq!(
        DegradationReason::VectorizationUnavailable.penalty_millionths(),
        200_000
    );
}

#[test]
fn enrichment_degradation_reason_exact_penalty_memory_model() {
    assert_eq!(
        DegradationReason::MemoryModelWeaker.penalty_millionths(),
        150_000
    );
}

// ---------------------------------------------------------------------------
// HardwareCell — edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hardware_cell_empty_strings() {
    let cell = HardwareCell::new("", "", "", 0, 0);
    assert_eq!(cell.cell_id, "");
    assert_eq!(cell.arch_family, "");
    assert_eq!(cell.microarch, "");
    assert_eq!(cell.vector_width_bits, 0);
    assert_eq!(cell.cache_line_bytes, 0);
    // Display should still work
    let s = cell.to_string();
    assert!(!s.is_empty());
}

#[test]
fn enrichment_hardware_cell_self_equivalence() {
    let cell = cell_x86_zen4();
    assert!(cell.hardware_equivalent(&cell));
    assert!(cell.same_arch_family(&cell));
    assert!(cell.same_microarch(&cell));
}

#[test]
fn enrichment_hardware_cell_content_hash_different_cell_id_different_hash() {
    let a = HardwareCell::new("id-a", "x86_64", "zen4", 256, 64);
    let b = HardwareCell::new("id-b", "x86_64", "zen4", 256, 64);
    // cell_id is included in content_hash, so different IDs => different hashes
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn enrichment_hardware_cell_riscv_to_arm_cross_arch() {
    let rv = cell_riscv();
    let arm = cell_arm_nv2();
    assert!(!rv.same_arch_family(&arm));
    assert!(!rv.hardware_equivalent(&arm));
}

// ---------------------------------------------------------------------------
// compute_residual_fraction — more edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_residual_fraction_one_millionth() {
    // 1 out of 1_000_000 => 1 millionth
    let f = compute_residual_fraction(1_000_000, 1);
    assert_eq!(f, 1);
}

#[test]
fn enrichment_residual_fraction_very_large_values_no_overflow() {
    // Use large but not overflowing values
    let source = u64::MAX / 2_000_000;
    let target = source / 2;
    let f = compute_residual_fraction(source, target);
    assert!(f > 0 && f <= 1_000_000);
}

#[test]
fn enrichment_residual_fraction_ninety_five_percent() {
    let f = compute_residual_fraction(1_000_000, 950_000);
    assert_eq!(f, 950_000);
}

#[test]
fn enrichment_residual_fraction_thirty_percent() {
    let f = compute_residual_fraction(1_000_000, 300_000);
    assert_eq!(f, 300_000);
}

// ---------------------------------------------------------------------------
// detect_degradation — additional scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_detect_degradation_arm_to_arm_same_microarch_empty() {
    let nv2_a = HardwareCell::new("arm-nv2-a", "aarch64", "neoverse_v2", 128, 64);
    let nv2_b = HardwareCell::new("arm-nv2-b", "aarch64", "neoverse_v2", 128, 64);
    let reasons = detect_degradation(&nv2_a, &nv2_b);
    assert!(reasons.is_empty());
}

#[test]
fn enrichment_detect_degradation_arm_to_arm_diff_microarch() {
    let reasons = detect_degradation(&cell_arm_nv2(), &cell_arm_a78());
    assert!(reasons.contains(&DegradationReason::MicroarchMismatch));
    assert!(reasons.contains(&DegradationReason::BranchPredictionDrift));
    assert!(!reasons.contains(&DegradationReason::IsaMissing));
}

#[test]
fn enrichment_detect_degradation_riscv_to_x86_cross_arch() {
    let reasons = detect_degradation(&cell_riscv(), &cell_x86_zen4());
    assert!(reasons.contains(&DegradationReason::IsaMissing));
    assert!(reasons.contains(&DegradationReason::MemoryModelWeaker));
}

#[test]
fn enrichment_detect_degradation_symmetric_same_arch_diff_microarch() {
    // Degradation should be the same in both directions for same-arch diff-microarch
    let r1 = detect_degradation(&cell_x86_zen4(), &cell_x86_alder());
    let r2 = detect_degradation(&cell_x86_alder(), &cell_x86_zen4());
    // Both should contain MicroarchMismatch and BranchPredictionDrift
    assert!(r1.contains(&DegradationReason::MicroarchMismatch));
    assert!(r2.contains(&DegradationReason::MicroarchMismatch));
    assert!(r1.contains(&DegradationReason::BranchPredictionDrift));
    assert!(r2.contains(&DegradationReason::BranchPredictionDrift));
}

#[test]
fn enrichment_detect_degradation_only_cache_line_diff() {
    // Same arch, same microarch, same vector, different cache line
    let a = HardwareCell::new("cell-a", "x86_64", "zen4", 256, 64);
    let b = HardwareCell::new("cell-b", "x86_64", "zen4", 256, 128);
    let reasons = detect_degradation(&a, &b);
    assert!(reasons.contains(&DegradationReason::CachePressure));
    assert!(reasons.contains(&DegradationReason::AlignmentPenalty));
    assert!(!reasons.contains(&DegradationReason::MicroarchMismatch));
}

// ---------------------------------------------------------------------------
// evaluate_transport — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_transport_all_artifact_kinds_partial() {
    let src = cell_x86_zen4();
    let tgt = cell_x86_alder();
    for kind in ArtifactKind::ALL {
        let cert = eval(
            *kind,
            &format!("partial-{}", kind.as_str()),
            &src,
            &tgt,
            1_000_000,
            800_000,
        );
        // 80% residual = PartialTransport
        assert_eq!(
            cert.outcome,
            TransportOutcome::PartialTransport,
            "{} at 80% should be PartialTransport",
            kind.as_str()
        );
        assert!(cert.is_usable());
    }
}

#[test]
fn enrichment_evaluate_transport_zero_source_perf() {
    // Zero source performance => residual fraction = 1_000_000 (full)
    let cert = eval(
        ArtifactKind::RewriteRule,
        "zero-src-perf",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        0,
        0,
    );
    assert_eq!(cert.residual_fraction_millionths, 1_000_000);
    assert_eq!(cert.outcome, TransportOutcome::FullTransport);
}

#[test]
fn enrichment_evaluate_transport_degradation_reasons_present_for_cross_arch() {
    let cert = eval(
        ArtifactKind::ProfileData,
        "deg-reasons",
        &cell_x86_zen4(),
        &cell_arm_nv2(),
        1_000_000,
        500_000,
    );
    assert!(cert.degradation_count() > 0);
    assert!(
        cert.degradation_reasons
            .contains(&DegradationReason::IsaMissing)
    );
}

#[test]
fn enrichment_evaluate_transport_cert_fields_all_populated() {
    let src = cell_x86_avx512();
    let tgt = cell_x86_zen4();
    let h = hash("field-check");
    let cert = evaluate_transport(
        ArtifactKind::SynthesizedKernel,
        h,
        &src,
        &tgt,
        1_000_000,
        600_000,
    )
    .unwrap();
    assert!(!cert.certificate_id.is_empty());
    assert_eq!(cert.artifact_kind, ArtifactKind::SynthesizedKernel);
    assert_eq!(cert.artifact_hash, h);
    assert_eq!(cert.source_cell.cell_id, "x86-avx512");
    assert_eq!(cert.target_cell.cell_id, "x86-zen4");
    assert_eq!(cert.source_perf_millionths, 1_000_000);
    assert_eq!(cert.target_perf_millionths, 600_000);
}

#[test]
fn enrichment_evaluate_transport_content_hash_changes_with_source_perf() {
    let c1 = eval(
        ArtifactKind::CacheEntry,
        "ch-perf",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        500_000,
    );
    let c2 = eval(
        ArtifactKind::CacheEntry,
        "ch-perf",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        2_000_000,
        1_000_000,
    );
    assert_ne!(c1.content_hash, c2.content_hash);
}

#[test]
fn enrichment_evaluate_transport_content_hash_changes_with_artifact_hash() {
    let src = cell_x86_zen4();
    let tgt = cell_x86_alder();
    let c1 = evaluate_transport(
        ArtifactKind::RewriteRule,
        hash("a"),
        &src,
        &tgt,
        1_000_000,
        800_000,
    )
    .unwrap();
    let c2 = evaluate_transport(
        ArtifactKind::RewriteRule,
        hash("b"),
        &src,
        &tgt,
        1_000_000,
        800_000,
    )
    .unwrap();
    assert_ne!(c1.content_hash, c2.content_hash);
    assert_ne!(c1.certificate_id, c2.certificate_id);
}

// ---------------------------------------------------------------------------
// TransportCertificate — Display format
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transport_certificate_display_contains_cert_prefix() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "disp-pf",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        900_000,
    );
    let s = cert.to_string();
    assert!(s.starts_with("cert:"));
}

#[test]
fn enrichment_transport_certificate_display_contains_outcome() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "disp-outcome",
        &cell_x86_zen4(),
        &cell_arm_nv2(),
        1_000_000,
        400_000,
    );
    let s = cert.to_string();
    // outcome should be in the display
    assert!(s.contains(&cert.outcome.to_string()));
}

// ---------------------------------------------------------------------------
// ResidualComponent — more edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_residual_component_transported_exceeds_source_saturating() {
    // This shouldn't normally happen but loss_millionths uses saturating_sub
    let comp = ResidualComponent::new("weird", 100_000, 200_000, "impossible in practice");
    assert_eq!(comp.loss_millionths(), 0); // saturating_sub means 0
}

#[test]
fn enrichment_residual_component_large_values() {
    let comp = ResidualComponent::new("big", u64::MAX / 2, u64::MAX / 4, "huge values");
    assert!(comp.loss_millionths() > 0);
}

#[test]
fn enrichment_residual_component_display_format() {
    let comp = ResidualComponent::new("vectorization", 600_000, 300_000, "halved");
    let s = comp.to_string();
    // Format: "name(src=X, xport=Y, loss=Z)"
    assert!(s.starts_with("vectorization("));
    assert!(s.contains("src=600000"));
    assert!(s.contains("xport=300000"));
    assert!(s.contains("loss=300000"));
}

// ---------------------------------------------------------------------------
// ResidualLedger — is_balanced edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_residual_ledger_is_balanced_empty_components() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "bal-empty",
        &cell_x86_zen4(),
        &cell_x86_zen4(),
        1_000_000,
        1_000_000,
    );
    let ledger = build_residual_ledger(&cert, vec![]).unwrap();
    assert!(ledger.is_balanced());
}

#[test]
fn enrichment_residual_ledger_is_balanced_single_component() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "bal-single",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let comps = vec![ResidualComponent::new("only", 500_000, 400_000, "x")];
    let ledger = build_residual_ledger(&cert, comps).unwrap();
    assert!(ledger.is_balanced());
}

#[test]
fn enrichment_residual_ledger_is_balanced_multiple_components() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "bal-multi",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let comps = vec![
        ResidualComponent::new("a", 300_000, 250_000, "x"),
        ResidualComponent::new("b", 200_000, 180_000, "y"),
        ResidualComponent::new("c", 100_000, 90_000, "z"),
    ];
    let ledger = build_residual_ledger(&cert, comps).unwrap();
    assert!(ledger.is_balanced());
}

// ---------------------------------------------------------------------------
// ResidualLedger — Display format
// ---------------------------------------------------------------------------

#[test]
fn enrichment_residual_ledger_display_format() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "led-disp-fmt",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let comps = vec![ResidualComponent::new("a", 400_000, 300_000, "x")];
    let ledger = build_residual_ledger(&cert, comps).unwrap();
    let s = ledger.to_string();
    assert!(s.starts_with("ledger:"));
    assert!(s.contains("cert="));
    assert!(s.contains("src="));
    assert!(s.contains("xport="));
    assert!(s.contains("unexplained="));
    assert!(s.contains("components="));
}

// ---------------------------------------------------------------------------
// build_residual_ledger — boundary at MAX_LEDGER_COMPONENTS
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_ledger_exactly_128_components_ok() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "128-comps",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        u64::MAX / 2,
        u64::MAX / 4,
    );
    let components: Vec<_> = (0..128)
        .map(|i| ResidualComponent::new(&format!("comp-{i}"), 1, 1, "tiny"))
        .collect();
    let result = build_residual_ledger(&cert, components);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().component_count(), 128);
}

// ---------------------------------------------------------------------------
// validate_ledger_consistency — more error scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_ledger_multiple_components_one_exceeds() {
    // One component has transported > source => should fail
    let ledger = ResidualLedger {
        ledger_id: "bad-comp".into(),
        certificate_id: "cert-w".into(),
        components: vec![
            ResidualComponent::new("good", 100_000, 80_000, "ok"),
            ResidualComponent::new("bad", 50_000, 60_000, "impossible"),
        ],
        total_source_millionths: 150_000,
        total_transported_millionths: 140_000,
        unexplained_remainder_millionths: 0,
        content_hash: ContentHash::compute(b"bad-comp"),
    };
    let result = validate_ledger_consistency(&ledger);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TransportError::LedgerInconsistent);
}

#[test]
fn enrichment_validate_ledger_empty_components_correct_totals() {
    let ledger = ResidualLedger {
        ledger_id: "empty-ok".into(),
        certificate_id: "cert-e".into(),
        components: vec![],
        total_source_millionths: 0,
        total_transported_millionths: 0,
        unexplained_remainder_millionths: 0,
        content_hash: ContentHash::compute(b"empty-ok"),
    };
    assert!(validate_ledger_consistency(&ledger).is_ok());
}

#[test]
fn enrichment_validate_ledger_empty_components_nonzero_totals_error() {
    let ledger = ResidualLedger {
        ledger_id: "empty-bad".into(),
        certificate_id: "cert-eb".into(),
        components: vec![],
        total_source_millionths: 100_000, // wrong: no components but nonzero total
        total_transported_millionths: 0,
        unexplained_remainder_millionths: 0,
        content_hash: ContentHash::compute(b"empty-bad"),
    };
    assert!(validate_ledger_consistency(&ledger).is_err());
}

// ---------------------------------------------------------------------------
// TransportManifestSummary — additional scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_summary_all_degraded() {
    let src = cell_x86_zen4();
    let tgt = cell_x86_alder();
    let certs: Vec<_> = (0..5)
        .map(|i| {
            eval(
                ArtifactKind::RewriteRule,
                &format!("degraded-{i}"),
                &src,
                &tgt,
                1_000_000,
                500_000,
            )
        })
        .collect();
    let summary = TransportManifestSummary::build(&certs);
    assert_eq!(summary.degraded_count, 5);
    assert_eq!(summary.total_certificates, 5);
    assert!(!summary.all_full_transport());
    assert!(!summary.has_failures());
    assert_eq!(summary.usability_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_manifest_summary_avg_residual_computation() {
    let cell = cell_x86_zen4();
    // Two certs: 1_000_000 and 500_000 residual => avg = 750_000
    let c1 = eval(
        ArtifactKind::RewriteRule,
        "avg-1",
        &cell,
        &cell,
        1_000_000,
        1_000_000,
    );
    let c2 = eval(
        ArtifactKind::CacheEntry,
        "avg-2",
        &cell,
        &cell_x86_alder(),
        1_000_000,
        500_000,
    );
    let summary = TransportManifestSummary::build(&[c1, c2]);
    assert_eq!(summary.avg_residual_fraction_millionths, 750_000);
}

#[test]
fn enrichment_manifest_summary_display_all_zeros_for_empty() {
    let summary = TransportManifestSummary::build(&[]);
    let s = summary.to_string();
    assert!(s.contains("total=0"));
    assert!(s.contains("full=0"));
    assert!(s.contains("failed=0"));
}

#[test]
fn enrichment_manifest_summary_content_hash_changes_with_different_certs() {
    let cell = cell_x86_zen4();
    let c1 = eval(
        ArtifactKind::RewriteRule,
        "hash-1",
        &cell,
        &cell,
        1_000_000,
        1_000_000,
    );
    let c2 = eval(
        ArtifactKind::CacheEntry,
        "hash-2",
        &cell,
        &cell_x86_alder(),
        1_000_000,
        500_000,
    );
    let s1 = TransportManifestSummary::build(std::slice::from_ref(&c1));
    let s2 = TransportManifestSummary::build(&[c1, c2]);
    assert_ne!(s1.content_hash, s2.content_hash);
}

// ---------------------------------------------------------------------------
// TransportEvent — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transport_event_epoch_zero() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "epoch-0",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        900_000,
    );
    let evt =
        TransportEvent::from_certificate(&cert, TransportEventKind::CertificateCreated, epoch(0));
    assert_eq!(evt.epoch, epoch(0));
}

#[test]
fn enrichment_transport_event_invalidated_kind() {
    let cert = eval(
        ArtifactKind::AotModule,
        "invalidated",
        &cell_x86_zen4(),
        &cell_arm_nv2(),
        1_000_000,
        200_000,
    );
    let evt = TransportEvent::from_certificate(
        &cert,
        TransportEventKind::CertificateInvalidated,
        epoch(5),
    );
    assert_eq!(evt.kind, TransportEventKind::CertificateInvalidated);
    assert_eq!(evt.outcome, TransportOutcome::Incompatible);
}

#[test]
fn enrichment_transport_event_re_evaluated_kind() {
    let cert = eval(
        ArtifactKind::ProfileData,
        "re-eval",
        &cell_arm_nv2(),
        &cell_arm_a78(),
        1_000_000,
        960_000,
    );
    let evt = TransportEvent::from_certificate(
        &cert,
        TransportEventKind::TransportReEvaluated,
        epoch(200),
    );
    assert_eq!(evt.kind, TransportEventKind::TransportReEvaluated);
    assert_eq!(evt.artifact_kind, ArtifactKind::ProfileData);
}

#[test]
fn enrichment_transport_event_display_format() {
    let cert = eval(
        ArtifactKind::RewriteRule,
        "evt-fmt",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        900_000,
    );
    let evt = TransportEvent::from_certificate(&cert, TransportEventKind::LedgerBuilt, epoch(10));
    let s = evt.to_string();
    assert!(s.starts_with("event:"));
    assert!(s.contains("ledger_built"));
    assert!(s.contains("cert="));
    assert!(s.contains("outcome="));
}

#[test]
fn enrichment_transport_event_deterministic_same_inputs() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "det-evt",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let e1 =
        TransportEvent::from_certificate(&cert, TransportEventKind::CertificateCreated, epoch(42));
    let e2 =
        TransportEvent::from_certificate(&cert, TransportEventKind::CertificateCreated, epoch(42));
    assert_eq!(e1.content_hash, e2.content_hash);
    assert_eq!(e1, e2);
}

// ---------------------------------------------------------------------------
// Ordering tests for enums
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_kind_ord_is_consistent() {
    let mut kinds: Vec<ArtifactKind> = ArtifactKind::ALL.to_vec();
    let mut kinds2 = kinds.clone();
    kinds.sort();
    kinds2.sort();
    assert_eq!(kinds, kinds2);
}

#[test]
fn enrichment_transport_outcome_ord_is_consistent() {
    let mut outcomes = vec![
        TransportOutcome::Failed,
        TransportOutcome::FullTransport,
        TransportOutcome::Incompatible,
        TransportOutcome::Degraded,
        TransportOutcome::PartialTransport,
    ];
    let mut outcomes2 = outcomes.clone();
    outcomes.sort();
    outcomes2.sort();
    assert_eq!(outcomes, outcomes2);
}

#[test]
fn enrichment_transport_event_kind_ord_is_consistent() {
    let mut kinds = vec![
        TransportEventKind::TransportReEvaluated,
        TransportEventKind::CertificateCreated,
        TransportEventKind::CertificateInvalidated,
        TransportEventKind::LedgerBuilt,
    ];
    let mut kinds2 = kinds.clone();
    kinds.sort();
    kinds2.sort();
    assert_eq!(kinds, kinds2);
}

// ---------------------------------------------------------------------------
// Serde edge cases — empty strings, special characters
// ---------------------------------------------------------------------------

#[test]
fn enrichment_degradation_reason_unknown_empty_string() {
    let r = DegradationReason::UnknownReason(String::new());
    assert_eq!(r.as_str(), "");
    let json = serde_json::to_string(&r).unwrap();
    let back: DegradationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_degradation_reason_unknown_special_chars() {
    let r = DegradationReason::UnknownReason("thermal/power:limit@99%".into());
    let json = serde_json::to_string(&r).unwrap();
    let back: DegradationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
    assert_eq!(back.as_str(), "thermal/power:limit@99%");
}

#[test]
fn enrichment_transport_error_internal_empty_message() {
    let e = TransportError::InternalError(String::new());
    let json = serde_json::to_string(&e).unwrap();
    let back: TransportError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    let s = e.to_string();
    assert!(s.contains("internal error"));
}

#[test]
fn enrichment_residual_component_empty_explanation() {
    let comp = ResidualComponent::new("test", 100_000, 80_000, "");
    let json = serde_json::to_string(&comp).unwrap();
    let back: ResidualComponent = serde_json::from_str(&json).unwrap();
    assert_eq!(comp, back);
    assert_eq!(back.explanation, "");
}

// ---------------------------------------------------------------------------
// Manifest — artifact kinds grouping
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_outcome_distribution_by_artifact_kind() {
    let certs = franken_engine_transport_manifest();
    let mut kind_outcomes: BTreeMap<String, Vec<TransportOutcome>> = BTreeMap::new();
    for cert in &certs {
        kind_outcomes
            .entry(cert.artifact_kind.as_str().to_string())
            .or_default()
            .push(cert.outcome);
    }
    // Every artifact kind in the manifest should have at least one certificate
    assert!(kind_outcomes.len() >= 5);
}

#[test]
fn enrichment_manifest_all_certificates_have_valid_residual() {
    let certs = franken_engine_transport_manifest();
    for cert in &certs {
        assert!(
            cert.residual_fraction_millionths <= 1_000_000,
            "cert {} has residual {} > 1M",
            cert.certificate_id,
            cert.residual_fraction_millionths
        );
    }
}

#[test]
fn enrichment_manifest_deterministic_content_hashes() {
    let certs1 = franken_engine_transport_manifest();
    let certs2 = franken_engine_transport_manifest();
    for (a, b) in certs1.iter().zip(certs2.iter()) {
        assert_eq!(a.content_hash, b.content_hash);
    }
}

#[test]
fn enrichment_manifest_all_content_hashes_unique() {
    let certs = franken_engine_transport_manifest();
    let hashes: BTreeSet<_> = certs
        .iter()
        .map(|c| format!("{:?}", c.content_hash))
        .collect();
    assert_eq!(
        hashes.len(),
        certs.len(),
        "all content hashes should be unique"
    );
}

// ---------------------------------------------------------------------------
// Full lifecycle — additional scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_full_lifecycle_arm_to_arm_partial_transport() {
    let src = cell_arm_nv2();
    let tgt = cell_arm_a78();
    let cert = eval(
        ArtifactKind::SpeculationGuard,
        "arm-arm-life",
        &src,
        &tgt,
        1_000_000,
        800_000,
    );
    assert_eq!(cert.outcome, TransportOutcome::PartialTransport);
    assert!(cert.same_arch_family());
    assert!(!cert.same_hardware());

    let comps = vec![
        ResidualComponent::new("spec_tables", 400_000, 320_000, "table portability"),
        ResidualComponent::new("deopt_points", 300_000, 260_000, "deopt re-profiling"),
    ];
    let ledger = build_residual_ledger(&cert, comps).unwrap();
    assert!(validate_ledger_consistency(&ledger).is_ok());
    assert_eq!(ledger.component_count(), 2);

    let evt =
        TransportEvent::from_certificate(&cert, TransportEventKind::CertificateCreated, epoch(50));
    assert_eq!(evt.outcome, TransportOutcome::PartialTransport);
}

#[test]
fn enrichment_full_lifecycle_failed_transport() {
    let src = cell_x86_zen4();
    let tgt = cell_x86_alder();
    let cert = eval(
        ArtifactKind::SynthesizedKernel,
        "fail-life",
        &src,
        &tgt,
        1_000_000,
        100_000,
    );
    assert_eq!(cert.outcome, TransportOutcome::Failed);
    assert!(!cert.is_usable());

    // Can still build a ledger for failed transport
    let comps = vec![ResidualComponent::new(
        "kernel_opt",
        800_000,
        80_000,
        "kernel highly specialized",
    )];
    let ledger = build_residual_ledger(&cert, comps).unwrap();
    assert!(validate_ledger_consistency(&ledger).is_ok());
}

#[test]
fn enrichment_full_lifecycle_incompatible_cross_arch_aot() {
    let src = cell_x86_avx512();
    let tgt = cell_riscv();
    let cert = eval(
        ArtifactKind::AotModule,
        "incompat-life",
        &src,
        &tgt,
        1_000_000,
        50_000,
    );
    assert_eq!(cert.outcome, TransportOutcome::Incompatible);
    assert!(!cert.is_usable());
    assert!(!cert.same_arch_family());

    let summary = TransportManifestSummary::build(std::slice::from_ref(&cert));
    assert!(summary.has_failures());
    assert_eq!(summary.incompatible_count, 1);
    assert_eq!(summary.usability_rate_millionths(), 0);
}

// ---------------------------------------------------------------------------
// Determinism tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_transport_fully_deterministic_across_calls() {
    for _ in 0..3 {
        let src = cell_x86_avx512();
        let tgt = cell_arm_nv2();
        let c = evaluate_transport(
            ArtifactKind::ProfileData,
            hash("det-multi"),
            &src,
            &tgt,
            1_000_000,
            600_000,
        )
        .unwrap();
        assert_eq!(c.residual_fraction_millionths, 600_000);
        assert_eq!(c.outcome, TransportOutcome::Degraded);
    }
}

#[test]
fn enrichment_build_ledger_fully_deterministic_across_calls() {
    let cert = eval(
        ArtifactKind::CacheEntry,
        "det-led-multi",
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let mut hashes = Vec::new();
    for _ in 0..3 {
        let comps = vec![ResidualComponent::new("comp", 400_000, 350_000, "reason")];
        let ledger = build_residual_ledger(&cert, comps).unwrap();
        hashes.push(ledger.content_hash);
    }
    assert_eq!(hashes[0], hashes[1]);
    assert_eq!(hashes[1], hashes[2]);
}

#[test]
fn enrichment_manifest_summary_fully_deterministic() {
    let certs = franken_engine_transport_manifest();
    let s1 = TransportManifestSummary::build(&certs);
    let s2 = TransportManifestSummary::build(&certs);
    let s3 = TransportManifestSummary::build(&certs);
    assert_eq!(s1, s2);
    assert_eq!(s2, s3);
}

// ---------------------------------------------------------------------------
// TransportManifestSummary — usability_rate edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_summary_usability_all_usable() {
    let cell = cell_x86_zen4();
    let c1 = eval(
        ArtifactKind::RewriteRule,
        "u1",
        &cell,
        &cell,
        1_000_000,
        1_000_000,
    );
    let c2 = eval(
        ArtifactKind::CacheEntry,
        "u2",
        &cell,
        &cell_x86_alder(),
        1_000_000,
        800_000,
    );
    let c3 = eval(
        ArtifactKind::ProfileData,
        "u3",
        &cell,
        &cell_x86_alder(),
        1_000_000,
        500_000,
    );
    let summary = TransportManifestSummary::build(&[c1, c2, c3]);
    assert_eq!(summary.usability_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_manifest_summary_usability_none_usable() {
    let src = cell_x86_zen4();
    let tgt = cell_x86_alder();
    let c1 = eval(
        ArtifactKind::RewriteRule,
        "nu1",
        &src,
        &tgt,
        1_000_000,
        100_000,
    );
    let c2 = eval(
        ArtifactKind::CacheEntry,
        "nu2",
        &src,
        &tgt,
        1_000_000,
        50_000,
    );
    let summary = TransportManifestSummary::build(&[c1, c2]);
    assert_eq!(summary.usability_rate_millionths(), 0);
    assert!(summary.has_failures());
}

// ---------------------------------------------------------------------------
// Cross-cutting: serde roundtrip of complex nested structures
// ---------------------------------------------------------------------------

#[test]
fn enrichment_full_serde_roundtrip_pipeline() {
    let src = cell_x86_avx512();
    let tgt = cell_x86_zen4();
    let cert = eval(
        ArtifactKind::SynthesizedKernel,
        "serde-pipe",
        &src,
        &tgt,
        1_000_000,
        700_000,
    );
    let comps = vec![
        ResidualComponent::new("vec", 400_000, 200_000, "width reduction"),
        ResidualComponent::new("bp", 300_000, 280_000, "cold tables"),
    ];
    let ledger = build_residual_ledger(&cert, comps).unwrap();
    let evt =
        TransportEvent::from_certificate(&cert, TransportEventKind::CertificateCreated, epoch(77));
    let summary = TransportManifestSummary::build(std::slice::from_ref(&cert));

    // Roundtrip each
    let cert_json = serde_json::to_string(&cert).unwrap();
    let cert_back: TransportCertificate = serde_json::from_str(&cert_json).unwrap();
    assert_eq!(cert, cert_back);

    let ledger_json = serde_json::to_string(&ledger).unwrap();
    let ledger_back: ResidualLedger = serde_json::from_str(&ledger_json).unwrap();
    assert_eq!(ledger, ledger_back);

    let evt_json = serde_json::to_string(&evt).unwrap();
    let evt_back: TransportEvent = serde_json::from_str(&evt_json).unwrap();
    assert_eq!(evt, evt_back);

    let summary_json = serde_json::to_string(&summary).unwrap();
    let summary_back: TransportManifestSummary = serde_json::from_str(&summary_json).unwrap();
    assert_eq!(summary, summary_back);
}
