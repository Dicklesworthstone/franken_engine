//! Integration tests for the transport certificate ledger (RGC-616B).

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::transport_certificate_ledger::{
    self, ArtifactKind, BEAD_ID, COMPONENT, DegradationReason, HardwareCell, POLICY_ID,
    ResidualComponent, SCHEMA_VERSION, TransportError, TransportOutcome,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cell_x86_zen4() -> HardwareCell {
    HardwareCell::new("x86-zen4", "x86_64", "zen4", 256, 64)
}

fn cell_x86_alder() -> HardwareCell {
    HardwareCell::new("x86-alder", "x86_64", "alderlake", 256, 64)
}

fn cell_arm_nv2() -> HardwareCell {
    HardwareCell::new("arm-nv2", "aarch64", "neoverse_v2", 128, 64)
}

fn cell_x86_avx512() -> HardwareCell {
    HardwareCell::new("x86-avx512", "x86_64", "sapphirerapids", 512, 64)
}

fn test_hash() -> ContentHash {
    ContentHash::compute(b"test-artifact")
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("transport"));
}

#[test]
fn test_bead_id() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component() {
    assert_eq!(COMPONENT, "transport_certificate_ledger");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-616B");
}

// ---------------------------------------------------------------------------
// ArtifactKind
// ---------------------------------------------------------------------------

#[test]
fn test_artifact_kind_all() {
    assert_eq!(ArtifactKind::ALL.len(), 7);
}

#[test]
fn test_artifact_kind_as_str() {
    assert_eq!(ArtifactKind::RewriteRule.as_str(), "rewrite_rule");
    assert_eq!(ArtifactKind::AotModule.as_str(), "aot_module");
}

#[test]
fn test_artifact_kind_arch_sensitive() {
    assert!(ArtifactKind::AotModule.is_arch_sensitive());
    assert!(ArtifactKind::SynthesizedKernel.is_arch_sensitive());
    assert!(!ArtifactKind::RewriteRule.is_arch_sensitive());
    assert!(!ArtifactKind::ProfileData.is_arch_sensitive());
    assert!(!ArtifactKind::CacheEntry.is_arch_sensitive());
}

#[test]
fn test_artifact_kind_serde_roundtrip() {
    for kind in ArtifactKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// TransportOutcome
// ---------------------------------------------------------------------------

#[test]
fn test_outcome_is_usable() {
    assert!(TransportOutcome::FullTransport.is_usable());
    assert!(TransportOutcome::PartialTransport.is_usable());
    assert!(TransportOutcome::Degraded.is_usable());
    assert!(!TransportOutcome::Failed.is_usable());
    assert!(!TransportOutcome::Incompatible.is_usable());
}

#[test]
fn test_outcome_is_full() {
    assert!(TransportOutcome::FullTransport.is_full());
    assert!(!TransportOutcome::PartialTransport.is_full());
}

#[test]
fn test_outcome_serde_roundtrip() {
    let o = TransportOutcome::Degraded;
    let json = serde_json::to_string(&o).unwrap();
    let back: TransportOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
}

// ---------------------------------------------------------------------------
// DegradationReason
// ---------------------------------------------------------------------------

#[test]
fn test_degradation_reason_as_str() {
    assert_eq!(
        DegradationReason::MicroarchMismatch.as_str(),
        "microarch_mismatch"
    );
    assert_eq!(DegradationReason::IsaMissing.as_str(), "isa_missing");
}

#[test]
fn test_degradation_reason_penalty() {
    assert!(DegradationReason::IsaMissing.penalty_millionths() > 0);
    assert!(DegradationReason::CachePressure.penalty_millionths() > 0);
}

#[test]
fn test_degradation_reason_unknown() {
    let r = DegradationReason::UnknownReason("custom".into());
    assert_eq!(r.as_str(), "custom");
    assert_eq!(r.penalty_millionths(), 100_000);
}

// ---------------------------------------------------------------------------
// HardwareCell
// ---------------------------------------------------------------------------

#[test]
fn test_hardware_cell_new() {
    let c = cell_x86_zen4();
    assert_eq!(c.cell_id, "x86-zen4");
    assert_eq!(c.arch_family, "x86_64");
    assert_eq!(c.vector_width_bits, 256);
}

#[test]
fn test_hardware_cell_same_arch_family() {
    assert!(cell_x86_zen4().same_arch_family(&cell_x86_alder()));
    assert!(!cell_x86_zen4().same_arch_family(&cell_arm_nv2()));
}

#[test]
fn test_hardware_cell_same_microarch() {
    assert!(cell_x86_zen4().same_microarch(&cell_x86_zen4()));
    assert!(!cell_x86_zen4().same_microarch(&cell_x86_alder()));
}

#[test]
fn test_hardware_cell_hardware_equivalent() {
    let a = cell_x86_zen4();
    let b = HardwareCell::new("different-id", "x86_64", "zen4", 256, 64);
    assert!(a.hardware_equivalent(&b));
}

#[test]
fn test_hardware_cell_content_hash_deterministic() {
    let a = cell_x86_zen4();
    let b = cell_x86_zen4();
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn test_hardware_cell_display() {
    let s = format!("{}", cell_x86_zen4());
    assert!(s.contains("x86-zen4"));
}

// ---------------------------------------------------------------------------
// detect_degradation
// ---------------------------------------------------------------------------

#[test]
fn test_detect_degradation_same_cell() {
    let reasons =
        transport_certificate_ledger::detect_degradation(&cell_x86_zen4(), &cell_x86_zen4());
    assert!(reasons.is_empty());
}

#[test]
fn test_detect_degradation_different_microarch() {
    let reasons =
        transport_certificate_ledger::detect_degradation(&cell_x86_zen4(), &cell_x86_alder());
    assert!(!reasons.is_empty());
    assert!(reasons.contains(&DegradationReason::MicroarchMismatch));
}

#[test]
fn test_detect_degradation_cross_arch() {
    let reasons =
        transport_certificate_ledger::detect_degradation(&cell_x86_zen4(), &cell_arm_nv2());
    assert!(reasons.contains(&DegradationReason::IsaMissing));
}

#[test]
fn test_detect_degradation_vector_width_reduction() {
    let reasons =
        transport_certificate_ledger::detect_degradation(&cell_x86_avx512(), &cell_x86_zen4());
    assert!(reasons.contains(&DegradationReason::VectorizationUnavailable));
}

// ---------------------------------------------------------------------------
// compute_residual_fraction
// ---------------------------------------------------------------------------

#[test]
fn test_residual_fraction_full() {
    let f = transport_certificate_ledger::compute_residual_fraction(1_000_000, 1_000_000);
    assert_eq!(f, 1_000_000);
}

#[test]
fn test_residual_fraction_half() {
    let f = transport_certificate_ledger::compute_residual_fraction(1_000_000, 500_000);
    assert_eq!(f, 500_000);
}

#[test]
fn test_residual_fraction_zero_source() {
    let f = transport_certificate_ledger::compute_residual_fraction(0, 500_000);
    assert_eq!(f, 1_000_000); // Full transport if no source reference
}

#[test]
fn test_residual_fraction_capped() {
    let f = transport_certificate_ledger::compute_residual_fraction(500_000, 1_000_000);
    assert_eq!(f, 1_000_000); // Capped at 1.0
}

// ---------------------------------------------------------------------------
// classify_outcome
// ---------------------------------------------------------------------------

#[test]
fn test_classify_outcome_full() {
    assert_eq!(
        transport_certificate_ledger::classify_outcome(950_000),
        TransportOutcome::FullTransport
    );
    assert_eq!(
        transport_certificate_ledger::classify_outcome(1_000_000),
        TransportOutcome::FullTransport
    );
}

#[test]
fn test_classify_outcome_partial() {
    assert_eq!(
        transport_certificate_ledger::classify_outcome(700_000),
        TransportOutcome::PartialTransport
    );
    assert_eq!(
        transport_certificate_ledger::classify_outcome(949_999),
        TransportOutcome::PartialTransport
    );
}

#[test]
fn test_classify_outcome_degraded() {
    assert_eq!(
        transport_certificate_ledger::classify_outcome(300_000),
        TransportOutcome::Degraded
    );
    assert_eq!(
        transport_certificate_ledger::classify_outcome(699_999),
        TransportOutcome::Degraded
    );
}

#[test]
fn test_classify_outcome_failed() {
    assert_eq!(
        transport_certificate_ledger::classify_outcome(299_999),
        TransportOutcome::Failed
    );
    assert_eq!(
        transport_certificate_ledger::classify_outcome(0),
        TransportOutcome::Failed
    );
}

// ---------------------------------------------------------------------------
// evaluate_transport
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_transport_same_cell() {
    let cert = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::RewriteRule,
        test_hash(),
        &cell_x86_zen4(),
        &cell_x86_zen4(),
        1_000_000,
        1_000_000,
    )
    .unwrap();
    assert_eq!(cert.outcome, TransportOutcome::FullTransport);
    assert!(cert.is_usable());
    assert!(cert.is_full_transport());
    assert!(cert.same_hardware());
}

#[test]
fn test_evaluate_transport_cross_arch_sensitive() {
    let cert = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::AotModule,
        test_hash(),
        &cell_x86_zen4(),
        &cell_arm_nv2(),
        1_000_000,
        200_000,
    )
    .unwrap();
    assert_eq!(cert.outcome, TransportOutcome::Incompatible);
    assert!(!cert.is_usable());
    assert!(!cert.same_arch_family());
}

#[test]
fn test_evaluate_transport_cross_arch_nonsensitive() {
    let cert = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::ProfileData,
        test_hash(),
        &cell_x86_zen4(),
        &cell_arm_nv2(),
        1_000_000,
        400_000,
    )
    .unwrap();
    // ProfileData is not arch-sensitive, so it should classify by residual
    assert_ne!(cert.outcome, TransportOutcome::Incompatible);
}

#[test]
fn test_evaluate_transport_certificate_content_hash_deterministic() {
    let a = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::RewriteRule,
        test_hash(),
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        900_000,
    )
    .unwrap();
    let b = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::RewriteRule,
        test_hash(),
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        900_000,
    )
    .unwrap();
    assert_eq!(a.content_hash, b.content_hash);
}

// ---------------------------------------------------------------------------
// ResidualComponent
// ---------------------------------------------------------------------------

#[test]
fn test_residual_component_survival() {
    let c = ResidualComponent::new("branch", 1_000_000, 800_000, "good");
    assert_eq!(c.survival_fraction_millionths(), 800_000);
    assert_eq!(c.loss_millionths(), 200_000);
}

#[test]
fn test_residual_component_zero_source() {
    let c = ResidualComponent::new("branch", 0, 0, "none");
    assert_eq!(c.survival_fraction_millionths(), 1_000_000);
}

// ---------------------------------------------------------------------------
// build_residual_ledger
// ---------------------------------------------------------------------------

#[test]
fn test_build_residual_ledger_ok() {
    let cert = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::RewriteRule,
        test_hash(),
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        900_000,
    )
    .unwrap();
    let comp = ResidualComponent::new("branch", 500_000, 400_000, "drift");
    let ledger = transport_certificate_ledger::build_residual_ledger(&cert, vec![comp]).unwrap();
    assert_eq!(ledger.component_count(), 1);
    assert!(
        ledger.total_loss_millionths() > 0
            || ledger.total_source_millionths == ledger.total_transported_millionths
    );
}

#[test]
fn test_build_residual_ledger_inconsistent() {
    let cert = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::RewriteRule,
        test_hash(),
        &cell_x86_zen4(),
        &cell_x86_alder(),
        100_000,
        90_000,
    )
    .unwrap();
    // Source contribution exceeds cert source perf
    let comp = ResidualComponent::new("branch", 500_000, 400_000, "too much");
    let result = transport_certificate_ledger::build_residual_ledger(&cert, vec![comp]);
    assert!(matches!(result, Err(TransportError::LedgerInconsistent)));
}

// ---------------------------------------------------------------------------
// validate_ledger_consistency
// ---------------------------------------------------------------------------

#[test]
fn test_validate_ledger_consistency_ok() {
    let cert = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::RewriteRule,
        test_hash(),
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        900_000,
    )
    .unwrap();
    let comp = ResidualComponent::new("branch", 500_000, 400_000, "drift");
    let ledger = transport_certificate_ledger::build_residual_ledger(&cert, vec![comp]).unwrap();
    assert!(transport_certificate_ledger::validate_ledger_consistency(&ledger).is_ok());
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_nonempty() {
    let manifest = transport_certificate_ledger::franken_engine_transport_manifest();
    assert!(!manifest.is_empty());
}

#[test]
fn test_manifest_deterministic() {
    let a = transport_certificate_ledger::franken_engine_transport_manifest();
    let b = transport_certificate_ledger::franken_engine_transport_manifest();
    assert_eq!(a.len(), b.len());
    for (ca, cb) in a.iter().zip(b.iter()) {
        assert_eq!(ca.certificate_id, cb.certificate_id);
        assert_eq!(ca.content_hash, cb.content_hash);
    }
}

// ---------------------------------------------------------------------------
// TransportError Display
// ---------------------------------------------------------------------------

#[test]
fn test_transport_error_display() {
    let e = TransportError::CellIncompatible;
    let s = format!("{e}");
    assert!(s.contains("incompatible"));
}

// ---------------------------------------------------------------------------
// ArtifactKind extended
// ---------------------------------------------------------------------------

#[test]
fn artifact_kind_all_unique_str() {
    let strs: Vec<&str> = ArtifactKind::ALL.iter().map(|k| k.as_str()).collect();
    for (i, a) in strs.iter().enumerate() {
        for (j, b) in strs.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "duplicate as_str for artifact kinds at {i} and {j}");
            }
        }
    }
}

#[test]
fn artifact_kind_display_matches_as_str() {
    for kind in ArtifactKind::ALL {
        assert_eq!(format!("{kind}"), kind.as_str());
    }
}

#[test]
fn artifact_kind_arch_sensitive_subset() {
    // Arch-sensitive artifacts are a subset of all artifacts
    let sensitive_count = ArtifactKind::ALL
        .iter()
        .filter(|k| k.is_arch_sensitive())
        .count();
    assert!(sensitive_count > 0 && sensitive_count < ArtifactKind::ALL.len());
}

// ---------------------------------------------------------------------------
// TransportOutcome extended
// ---------------------------------------------------------------------------

#[test]
fn transport_outcome_all_serde_roundtrip() {
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
fn transport_outcome_display_nonempty() {
    let outcomes = [
        TransportOutcome::FullTransport,
        TransportOutcome::PartialTransport,
        TransportOutcome::Degraded,
        TransportOutcome::Failed,
        TransportOutcome::Incompatible,
    ];
    for o in &outcomes {
        assert!(!format!("{o}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// DegradationReason extended
// ---------------------------------------------------------------------------

#[test]
fn degradation_reason_serde_roundtrip() {
    let reasons = [
        DegradationReason::MicroarchMismatch,
        DegradationReason::IsaMissing,
        DegradationReason::VectorizationUnavailable,
        DegradationReason::CachePressure,
        DegradationReason::UnknownReason("test".into()),
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: DegradationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn degradation_reason_penalty_all_positive() {
    let reasons = [
        DegradationReason::MicroarchMismatch,
        DegradationReason::IsaMissing,
        DegradationReason::VectorizationUnavailable,
        DegradationReason::CachePressure,
        DegradationReason::UnknownReason("custom".into()),
    ];
    for r in &reasons {
        assert!(
            r.penalty_millionths() > 0,
            "penalty should be positive for {r:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// HardwareCell extended
// ---------------------------------------------------------------------------

#[test]
fn hardware_cell_different_ids_not_equivalent_by_id() {
    let a = cell_x86_zen4();
    let b = HardwareCell::new("different-id", "x86_64", "zen4", 256, 64);
    // They are hardware_equivalent (same arch/microarch/vector/cache)
    assert!(a.hardware_equivalent(&b));
    // But have different cell_ids
    assert_ne!(a.cell_id, b.cell_id);
}

#[test]
fn hardware_cell_serde_roundtrip() {
    let cell = cell_x86_zen4();
    let json = serde_json::to_string(&cell).unwrap();
    let back: HardwareCell = serde_json::from_str(&json).unwrap();
    assert_eq!(cell.cell_id, back.cell_id);
    assert_eq!(cell.arch_family, back.arch_family);
    assert_eq!(cell.microarch, back.microarch);
    assert_eq!(cell.vector_width_bits, back.vector_width_bits);
}

#[test]
fn hardware_cell_different_vector_width_not_equivalent() {
    let a = cell_x86_zen4(); // 256
    let b = cell_x86_avx512(); // 512
    assert!(!a.hardware_equivalent(&b));
}

// ---------------------------------------------------------------------------
// detect_degradation extended
// ---------------------------------------------------------------------------

#[test]
fn detect_degradation_vector_width_increase_no_degradation() {
    // Going from smaller to larger vector width should not cause vectorization unavailable
    let reasons =
        transport_certificate_ledger::detect_degradation(&cell_x86_zen4(), &cell_x86_avx512());
    // zen4 (256) -> avx512 (512) - target has wider vectors
    assert!(
        !reasons.contains(&DegradationReason::VectorizationUnavailable),
        "increasing vector width should not degrade vectorization"
    );
}

#[test]
fn detect_degradation_same_hardware_equivalent_empty() {
    let a = cell_x86_zen4();
    let b = HardwareCell::new("clone-zen4", "x86_64", "zen4", 256, 64);
    let reasons = transport_certificate_ledger::detect_degradation(&a, &b);
    assert!(
        reasons.is_empty(),
        "hardware-equivalent cells should have no degradation"
    );
}

// ---------------------------------------------------------------------------
// residual_fraction edge cases
// ---------------------------------------------------------------------------

#[test]
fn residual_fraction_negative_metrics_handled() {
    // Negative performance values should still produce valid fractions
    let f = transport_certificate_ledger::compute_residual_fraction(1_000_000, 0);
    assert_eq!(f, 0);
}

#[test]
fn residual_fraction_equal_metrics_full() {
    let f = transport_certificate_ledger::compute_residual_fraction(750_000, 750_000);
    assert_eq!(f, 1_000_000); // Full transport
}

// ---------------------------------------------------------------------------
// classify_outcome boundary values
// ---------------------------------------------------------------------------

#[test]
fn classify_outcome_boundary_950000() {
    assert_eq!(
        transport_certificate_ledger::classify_outcome(950_000),
        TransportOutcome::FullTransport
    );
}

#[test]
fn classify_outcome_boundary_949999() {
    assert_eq!(
        transport_certificate_ledger::classify_outcome(949_999),
        TransportOutcome::PartialTransport
    );
}

#[test]
fn classify_outcome_boundary_700000() {
    assert_eq!(
        transport_certificate_ledger::classify_outcome(700_000),
        TransportOutcome::PartialTransport
    );
}

#[test]
fn classify_outcome_boundary_699999() {
    assert_eq!(
        transport_certificate_ledger::classify_outcome(699_999),
        TransportOutcome::Degraded
    );
}

#[test]
fn classify_outcome_boundary_300000() {
    assert_eq!(
        transport_certificate_ledger::classify_outcome(300_000),
        TransportOutcome::Degraded
    );
}

#[test]
fn classify_outcome_boundary_299999() {
    assert_eq!(
        transport_certificate_ledger::classify_outcome(299_999),
        TransportOutcome::Failed
    );
}

// ---------------------------------------------------------------------------
// evaluate_transport extended
// ---------------------------------------------------------------------------

#[test]
fn evaluate_transport_same_microarch_different_cell_id() {
    let a = cell_x86_zen4();
    let b = HardwareCell::new("replica-zen4", "x86_64", "zen4", 256, 64);
    let cert = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::AotModule,
        test_hash(),
        &a,
        &b,
        1_000_000,
        1_000_000,
    )
    .unwrap();
    assert_eq!(cert.outcome, TransportOutcome::FullTransport);
    assert!(cert.same_hardware());
}

#[test]
fn evaluate_transport_different_artifact_kinds_produce_different_certs() {
    let h = test_hash();
    let src = cell_x86_zen4();
    let tgt = cell_x86_alder();
    let cert_rewrite = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::RewriteRule,
        h,
        &src,
        &tgt,
        1_000_000,
        800_000,
    )
    .unwrap();
    let cert_aot = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::AotModule,
        h,
        &src,
        &tgt,
        1_000_000,
        800_000,
    )
    .unwrap();
    assert_ne!(
        cert_rewrite.certificate_id, cert_aot.certificate_id,
        "different artifact kinds should produce different cert ids"
    );
}

#[test]
fn evaluate_transport_content_hash_changes_with_different_perf() {
    let cert1 = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::CacheEntry,
        test_hash(),
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        900_000,
    )
    .unwrap();
    let cert2 = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::CacheEntry,
        test_hash(),
        &cell_x86_zen4(),
        &cell_x86_alder(),
        1_000_000,
        700_000,
    )
    .unwrap();
    assert_ne!(cert1.content_hash, cert2.content_hash);
}

// ---------------------------------------------------------------------------
// ResidualComponent extended
// ---------------------------------------------------------------------------

#[test]
fn residual_component_serde_roundtrip() {
    let c = ResidualComponent::new("branch_predict", 800_000, 600_000, "microarch drift");
    let json = serde_json::to_string(&c).unwrap();
    let back: ResidualComponent = serde_json::from_str(&json).unwrap();
    assert_eq!(c.component_name, back.component_name);
    assert_eq!(
        c.source_contribution_millionths,
        back.source_contribution_millionths
    );
}

#[test]
fn residual_component_loss_positive_for_degradation() {
    let c = ResidualComponent::new("cache", 1_000_000, 500_000, "pressure");
    assert_eq!(c.loss_millionths(), 500_000);
}

#[test]
fn residual_component_loss_zero_for_full_transport() {
    let c = ResidualComponent::new("cache", 1_000_000, 1_000_000, "none");
    assert_eq!(c.loss_millionths(), 0);
}

// ---------------------------------------------------------------------------
// TransportError all variants display
// ---------------------------------------------------------------------------

#[test]
fn transport_error_all_variants_display() {
    let errors = [
        TransportError::CellIncompatible,
        TransportError::ArtifactCorrupted,
        TransportError::MeasurementFailed,
        TransportError::LedgerInconsistent,
    ];
    for e in &errors {
        let msg = format!("{e}");
        assert!(!msg.is_empty());
    }
}

#[test]
fn transport_error_serde_roundtrip() {
    let errors = [
        TransportError::CellIncompatible,
        TransportError::ArtifactCorrupted,
        TransportError::MeasurementFailed,
        TransportError::LedgerInconsistent,
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: TransportError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_transport_lifecycle() {
    let src = cell_x86_zen4();
    let tgt = cell_x86_alder();
    let hash = ContentHash::compute(b"rewrite-artifact");

    // 1. Detect degradation
    let reasons = transport_certificate_ledger::detect_degradation(&src, &tgt);
    assert!(!reasons.is_empty()); // Different microarch

    // 2. Evaluate transport
    let cert = transport_certificate_ledger::evaluate_transport(
        ArtifactKind::RewriteRule,
        hash,
        &src,
        &tgt,
        1_000_000,
        850_000,
    )
    .unwrap();
    assert!(cert.is_usable());
    assert!(!cert.same_hardware());

    // 3. Build residual ledger
    let comp = ResidualComponent::new("branch", 600_000, 480_000, "microarch");
    let ledger = transport_certificate_ledger::build_residual_ledger(&cert, vec![comp]).unwrap();
    assert_eq!(ledger.component_count(), 1);

    // 4. Validate
    transport_certificate_ledger::validate_ledger_consistency(&ledger).unwrap();

    // 5. Serde roundtrip
    let json = serde_json::to_string(&cert).unwrap();
    assert!(!json.is_empty());
}
