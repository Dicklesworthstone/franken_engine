//! Integration tests for the hardware_board_claim_gate module (RGC-616C).
//!
//! Bead: bd-1lsy.7.16.3

use frankenengine_engine::hardware_board_claim_gate::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn make_claim(
    kind: HardwareClaimKind,
    source: &str,
    target: &str,
    residual: u64,
    samples: u64,
) -> HardwareClaim {
    HardwareClaim::new(
        kind,
        source,
        target,
        2_000_000,
        1_200_000,
        residual,
        samples,
        epoch(),
    )
}

fn confirmed_claim() -> HardwareClaim {
    make_claim(
        HardwareClaimKind::Throughput,
        "src-x86",
        "dst-x86",
        960_000,
        100,
    )
}

fn downgraded_claim() -> HardwareClaim {
    make_claim(
        HardwareClaimKind::Latency,
        "src-x86",
        "dst-arm",
        800_000,
        50,
    )
}

fn requires_local_claim() -> HardwareClaim {
    make_claim(
        HardwareClaimKind::MemoryEfficiency,
        "src-a",
        "dst-b",
        400_000,
        30,
    )
}

fn unsupported_claim() -> HardwareClaim {
    make_claim(
        HardwareClaimKind::StartupTime,
        "src-a",
        "dst-c",
        100_000,
        25,
    )
}

fn insufficient_claim() -> HardwareClaim {
    make_claim(HardwareClaimKind::TailLatency, "src-a", "dst-d", 960_000, 5)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_starts_with_prefix() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn test_schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("hardware-board-claim-gate"));
}

#[test]
fn test_bead_id_value() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.16.3");
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "hardware_board_claim_gate");
}

#[test]
fn test_policy_id_value() {
    assert_eq!(POLICY_ID, "RGC-616C");
}

#[test]
fn test_policy_id_prefix() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

// ---------------------------------------------------------------------------
// HardwareClaimKind — enum
// ---------------------------------------------------------------------------

#[test]
fn test_hardware_claim_kind_all_has_six_variants() {
    assert_eq!(HardwareClaimKind::ALL.len(), 6);
}

#[test]
fn test_hardware_claim_kind_all_names_unique() {
    let names: std::collections::BTreeSet<&str> =
        HardwareClaimKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(names.len(), HardwareClaimKind::ALL.len());
}

#[test]
fn test_hardware_claim_kind_display_matches_as_str() {
    for k in HardwareClaimKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn test_hardware_claim_kind_serde_roundtrip() {
    for k in HardwareClaimKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: HardwareClaimKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn test_hardware_claim_kind_serde_snake_case() {
    let json = serde_json::to_string(&HardwareClaimKind::MemoryEfficiency).unwrap();
    assert_eq!(json, "\"memory_efficiency\"");
    let json2 = serde_json::to_string(&HardwareClaimKind::EnergyEfficiency).unwrap();
    assert_eq!(json2, "\"energy_efficiency\"");
}

#[test]
fn test_hardware_claim_kind_specific_names() {
    assert_eq!(HardwareClaimKind::Throughput.as_str(), "throughput");
    assert_eq!(HardwareClaimKind::Latency.as_str(), "latency");
    assert_eq!(HardwareClaimKind::StartupTime.as_str(), "startup_time");
    assert_eq!(HardwareClaimKind::TailLatency.as_str(), "tail_latency");
}

// ---------------------------------------------------------------------------
// ClaimVerdict — enum
// ---------------------------------------------------------------------------

#[test]
fn test_claim_verdict_all_has_five_variants() {
    assert_eq!(ClaimVerdict::ALL.len(), 5);
}

#[test]
fn test_claim_verdict_all_names_unique() {
    let names: std::collections::BTreeSet<&str> =
        ClaimVerdict::ALL.iter().map(|v| v.as_str()).collect();
    assert_eq!(names.len(), ClaimVerdict::ALL.len());
}

#[test]
fn test_claim_verdict_display_matches_as_str() {
    for v in ClaimVerdict::ALL {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn test_claim_verdict_serde_roundtrip() {
    for v in ClaimVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: ClaimVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn test_claim_verdict_is_usable() {
    assert!(ClaimVerdict::Confirmed.is_usable());
    assert!(ClaimVerdict::Downgraded.is_usable());
    assert!(!ClaimVerdict::RequiresLocal.is_usable());
    assert!(!ClaimVerdict::Unsupported.is_usable());
    assert!(!ClaimVerdict::InsufficientEvidence.is_usable());
}

#[test]
fn test_claim_verdict_specific_names() {
    assert_eq!(ClaimVerdict::Confirmed.as_str(), "confirmed");
    assert_eq!(ClaimVerdict::RequiresLocal.as_str(), "requires_local");
    assert_eq!(
        ClaimVerdict::InsufficientEvidence.as_str(),
        "insufficient_evidence"
    );
}

// ---------------------------------------------------------------------------
// PromotionDecision — enum
// ---------------------------------------------------------------------------

#[test]
fn test_promotion_decision_all_has_four_variants() {
    assert_eq!(PromotionDecision::ALL.len(), 4);
}

#[test]
fn test_promotion_decision_all_names_unique() {
    let names: std::collections::BTreeSet<&str> =
        PromotionDecision::ALL.iter().map(|d| d.as_str()).collect();
    assert_eq!(names.len(), PromotionDecision::ALL.len());
}

#[test]
fn test_promotion_decision_display_matches_as_str() {
    for d in PromotionDecision::ALL {
        assert_eq!(d.to_string(), d.as_str());
    }
}

#[test]
fn test_promotion_decision_serde_roundtrip() {
    for d in PromotionDecision::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: PromotionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn test_promotion_decision_specific_names() {
    assert_eq!(PromotionDecision::Promote.as_str(), "promote");
    assert_eq!(PromotionDecision::Hold.as_str(), "hold");
    assert_eq!(PromotionDecision::Rollback.as_str(), "rollback");
    assert_eq!(
        PromotionDecision::RequireFreshMeasurement.as_str(),
        "require_fresh_measurement"
    );
}

// ---------------------------------------------------------------------------
// DegradationReason — enum
// ---------------------------------------------------------------------------

#[test]
fn test_degradation_reason_all_has_six_variants() {
    assert_eq!(DegradationReason::ALL.len(), 6);
}

#[test]
fn test_degradation_reason_all_names_unique() {
    let names: std::collections::BTreeSet<&str> =
        DegradationReason::ALL.iter().map(|r| r.as_str()).collect();
    assert_eq!(names.len(), DegradationReason::ALL.len());
}

#[test]
fn test_degradation_reason_display_matches_as_str() {
    for r in DegradationReason::ALL {
        assert_eq!(r.to_string(), r.as_str());
    }
}

#[test]
fn test_degradation_reason_serde_roundtrip() {
    for r in DegradationReason::ALL {
        let json = serde_json::to_string(r).unwrap();
        let back: DegradationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// HardwareClaim — struct
// ---------------------------------------------------------------------------

#[test]
fn test_hardware_claim_construction() {
    let c = confirmed_claim();
    assert_eq!(c.kind, HardwareClaimKind::Throughput);
    assert_eq!(c.source_cell_id, "src-x86");
    assert_eq!(c.target_cell_id, "dst-x86");
    assert_eq!(c.measured_value, 2_000_000);
    assert_eq!(c.claimed_improvement, 1_200_000);
    assert_eq!(c.transport_residual, 960_000);
    assert_eq!(c.sample_count, 100);
    assert_eq!(c.epoch, epoch());
}

#[test]
fn test_hardware_claim_is_same_cell_true() {
    let c = make_claim(
        HardwareClaimKind::Throughput,
        "cell-x",
        "cell-x",
        900_000,
        20,
    );
    assert!(c.is_same_cell());
}

#[test]
fn test_hardware_claim_is_same_cell_false() {
    let c = confirmed_claim();
    assert!(!c.is_same_cell());
}

#[test]
fn test_hardware_claim_content_hash_deterministic() {
    let c1 = confirmed_claim();
    let c2 = confirmed_claim();
    assert_eq!(c1.content_hash(), c2.content_hash());
}

#[test]
fn test_hardware_claim_content_hash_differs_by_residual() {
    let c1 = make_claim(HardwareClaimKind::Throughput, "a", "b", 900_000, 20);
    let c2 = make_claim(HardwareClaimKind::Throughput, "a", "b", 900_001, 20);
    assert_ne!(c1.content_hash(), c2.content_hash());
}

#[test]
fn test_hardware_claim_content_hash_differs_by_kind() {
    let c1 = make_claim(HardwareClaimKind::Throughput, "a", "b", 900_000, 20);
    let c2 = make_claim(HardwareClaimKind::Latency, "a", "b", 900_000, 20);
    assert_ne!(c1.content_hash(), c2.content_hash());
}

#[test]
fn test_hardware_claim_display() {
    let c = confirmed_claim();
    let s = c.to_string();
    assert!(s.contains("throughput"));
    assert!(s.contains("src-x86"));
    assert!(s.contains("dst-x86"));
    assert!(s.contains("960000"));
}

#[test]
fn test_hardware_claim_serde_roundtrip() {
    let c = confirmed_claim();
    let json = serde_json::to_string(&c).unwrap();
    let back: HardwareClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// GateConfig — struct
// ---------------------------------------------------------------------------

#[test]
fn test_gate_config_default() {
    let cfg = GateConfig::default();
    assert_eq!(cfg.full_transport_threshold, 950_000);
    assert_eq!(cfg.partial_transport_threshold, 700_000);
    assert_eq!(cfg.degraded_threshold, 300_000);
    assert_eq!(cfg.min_samples, 10);
    assert_eq!(cfg.rollback_regression_threshold, 50_000);
}

#[test]
fn test_gate_config_default_config_equals_default_trait() {
    assert_eq!(GateConfig::default_config(), GateConfig::default());
}

#[test]
fn test_gate_config_permissive() {
    let cfg = GateConfig::permissive();
    assert_eq!(cfg.full_transport_threshold, 0);
    assert_eq!(cfg.partial_transport_threshold, 0);
    assert_eq!(cfg.degraded_threshold, 0);
    assert_eq!(cfg.min_samples, 0);
    assert_eq!(cfg.rollback_regression_threshold, 1_000_000);
}

#[test]
fn test_gate_config_strict() {
    let cfg = GateConfig::strict();
    assert_eq!(cfg.full_transport_threshold, 980_000);
    assert_eq!(cfg.partial_transport_threshold, 800_000);
    assert_eq!(cfg.degraded_threshold, 500_000);
    assert_eq!(cfg.min_samples, 50);
    assert_eq!(cfg.rollback_regression_threshold, 20_000);
}

#[test]
fn test_gate_config_threshold_ordering_default() {
    let cfg = GateConfig::default();
    assert!(cfg.full_transport_threshold > cfg.partial_transport_threshold);
    assert!(cfg.partial_transport_threshold > cfg.degraded_threshold);
}

#[test]
fn test_gate_config_serde_roundtrip() {
    let cfg = GateConfig::strict();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn test_gate_config_custom_values() {
    let cfg = GateConfig {
        full_transport_threshold: 990_000,
        partial_transport_threshold: 850_000,
        degraded_threshold: 400_000,
        min_samples: 25,
        rollback_regression_threshold: 30_000,
    };
    assert_eq!(cfg.full_transport_threshold, 990_000);
    assert_eq!(cfg.min_samples, 25);
}

// ---------------------------------------------------------------------------
// evaluate — Confirmed verdict
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_confirmed() {
    let cfg = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
    assert!(ev.is_supported());
    assert_eq!(ev.residual_fraction, 960_000);
}

#[test]
fn test_evaluate_confirmed_no_degradation_reasons_from_residual() {
    let cfg = GateConfig::default();
    // Residual at exactly full threshold
    let c = make_claim(HardwareClaimKind::Throughput, "a", "b", 950_000, 100);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
}

#[test]
fn test_evaluate_confirmed_max_residual() {
    let cfg = GateConfig::default();
    let c = make_claim(HardwareClaimKind::Throughput, "a", "b", 1_000_000, 100);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
    assert!(ev.degradation_reasons.is_empty());
}

#[test]
fn test_evaluate_confirmed_explanation_contains_confirmed() {
    let cfg = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &cfg);
    assert!(ev.explanation.contains("confirmed"));
}

// ---------------------------------------------------------------------------
// evaluate — Downgraded verdict
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_downgraded() {
    let cfg = GateConfig::default();
    let ev = evaluate(&downgraded_claim(), &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
    assert!(ev.is_supported());
    assert_eq!(ev.residual_fraction, 800_000);
}

#[test]
fn test_evaluate_downgraded_at_boundary() {
    let cfg = GateConfig::default();
    let c = make_claim(HardwareClaimKind::Latency, "a", "b", 700_000, 50);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
}

#[test]
fn test_evaluate_downgraded_has_microarch_variance_reason() {
    let cfg = GateConfig::default();
    let ev = evaluate(&downgraded_claim(), &cfg);
    assert!(
        ev.degradation_reasons
            .contains(&DegradationReason::MicroarchVariance)
    );
}

#[test]
fn test_evaluate_downgraded_explanation_mentions_downgraded() {
    let cfg = GateConfig::default();
    let ev = evaluate(&downgraded_claim(), &cfg);
    assert!(ev.explanation.contains("downgraded"));
}

// ---------------------------------------------------------------------------
// evaluate — RequiresLocal verdict
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_requires_local() {
    let cfg = GateConfig::default();
    let ev = evaluate(&requires_local_claim(), &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::RequiresLocal);
    assert!(!ev.is_supported());
    assert_eq!(ev.residual_fraction, 400_000);
}

#[test]
fn test_evaluate_requires_local_at_boundary() {
    let cfg = GateConfig::default();
    let c = make_claim(HardwareClaimKind::MemoryEfficiency, "a", "b", 300_000, 50);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::RequiresLocal);
}

#[test]
fn test_evaluate_requires_local_has_arch_mismatch_reason() {
    let cfg = GateConfig::default();
    let ev = evaluate(&requires_local_claim(), &cfg);
    assert!(
        ev.degradation_reasons
            .contains(&DegradationReason::ArchMismatch)
    );
}

#[test]
fn test_evaluate_requires_local_explanation() {
    let cfg = GateConfig::default();
    let ev = evaluate(&requires_local_claim(), &cfg);
    assert!(ev.explanation.contains("fresh local measurement"));
}

// ---------------------------------------------------------------------------
// evaluate — Unsupported verdict
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_unsupported() {
    let cfg = GateConfig::default();
    let ev = evaluate(&unsupported_claim(), &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Unsupported);
    assert!(!ev.is_supported());
    assert_eq!(ev.residual_fraction, 100_000);
}

#[test]
fn test_evaluate_unsupported_zero_residual() {
    let cfg = GateConfig::default();
    let c = make_claim(HardwareClaimKind::StartupTime, "a", "b", 0, 50);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Unsupported);
    assert!(
        ev.degradation_reasons
            .contains(&DegradationReason::ResidualTooLow)
    );
}

#[test]
fn test_evaluate_unsupported_has_vector_width_loss() {
    let cfg = GateConfig::default();
    let ev = evaluate(&unsupported_claim(), &cfg);
    assert!(
        ev.degradation_reasons
            .contains(&DegradationReason::VectorWidthLoss)
    );
}

#[test]
fn test_evaluate_unsupported_has_cache_size_difference() {
    let cfg = GateConfig::default();
    let ev = evaluate(&unsupported_claim(), &cfg);
    assert!(
        ev.degradation_reasons
            .contains(&DegradationReason::CacheSizeDifference)
    );
}

#[test]
fn test_evaluate_unsupported_explanation_mentions_unsupported() {
    let cfg = GateConfig::default();
    let ev = evaluate(&unsupported_claim(), &cfg);
    assert!(ev.explanation.contains("unsupported"));
}

// ---------------------------------------------------------------------------
// evaluate — InsufficientEvidence verdict
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_insufficient_evidence() {
    let cfg = GateConfig::default();
    let ev = evaluate(&insufficient_claim(), &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::InsufficientEvidence);
    assert!(!ev.is_supported());
}

#[test]
fn test_evaluate_insufficient_has_insufficient_samples_reason() {
    let cfg = GateConfig::default();
    let ev = evaluate(&insufficient_claim(), &cfg);
    assert!(
        ev.degradation_reasons
            .contains(&DegradationReason::InsufficientSamples)
    );
}

#[test]
fn test_evaluate_insufficient_with_zero_samples() {
    let cfg = GateConfig::default();
    let c = make_claim(HardwareClaimKind::Throughput, "a", "b", 1_000_000, 0);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::InsufficientEvidence);
}

#[test]
fn test_evaluate_insufficient_explanation_mentions_sample_count() {
    let cfg = GateConfig::default();
    let ev = evaluate(&insufficient_claim(), &cfg);
    assert!(ev.explanation.contains("insufficient evidence"));
}

// ---------------------------------------------------------------------------
// evaluate — boundary threshold values
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_just_below_full_threshold() {
    let cfg = GateConfig::default();
    let c = make_claim(HardwareClaimKind::Throughput, "a", "b", 949_999, 100);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
}

#[test]
fn test_evaluate_just_below_partial_threshold() {
    let cfg = GateConfig::default();
    let c = make_claim(HardwareClaimKind::Throughput, "a", "b", 699_999, 100);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::RequiresLocal);
}

#[test]
fn test_evaluate_just_below_degraded_threshold() {
    let cfg = GateConfig::default();
    let c = make_claim(HardwareClaimKind::Throughput, "a", "b", 299_999, 100);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Unsupported);
}

#[test]
fn test_evaluate_at_min_samples_boundary() {
    let cfg = GateConfig::default();
    // Exactly at min_samples=10 should pass
    let c = make_claim(HardwareClaimKind::Throughput, "a", "b", 960_000, 10);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
    // One below should fail
    let c2 = make_claim(HardwareClaimKind::Throughput, "a", "b", 960_000, 9);
    let ev2 = evaluate(&c2, &cfg);
    assert_eq!(ev2.verdict, ClaimVerdict::InsufficientEvidence);
}

// ---------------------------------------------------------------------------
// evaluate — permissive and strict configs
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_permissive_confirms_everything() {
    let cfg = GateConfig::permissive();
    let c = make_claim(HardwareClaimKind::Throughput, "a", "b", 1, 0);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
}

#[test]
fn test_evaluate_strict_requires_more_samples() {
    let cfg = GateConfig::strict();
    let c = make_claim(HardwareClaimKind::Throughput, "a", "b", 990_000, 30);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::InsufficientEvidence);
}

// ---------------------------------------------------------------------------
// ClaimEvidence — content hash, display
// ---------------------------------------------------------------------------

#[test]
fn test_claim_evidence_content_hash_deterministic() {
    let cfg = GateConfig::default();
    let ev1 = evaluate(&confirmed_claim(), &cfg);
    let ev2 = evaluate(&confirmed_claim(), &cfg);
    assert_eq!(ev1.content_hash(), ev2.content_hash());
}

#[test]
fn test_claim_evidence_content_hash_differs_by_verdict() {
    let cfg = GateConfig::default();
    let ev_confirmed = evaluate(&confirmed_claim(), &cfg);
    let ev_downgraded = evaluate(&downgraded_claim(), &cfg);
    assert_ne!(ev_confirmed.content_hash(), ev_downgraded.content_hash());
}

#[test]
fn test_claim_evidence_display() {
    let cfg = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &cfg);
    let s = ev.to_string();
    assert!(s.contains("confirmed"));
    assert!(s.contains("residual="));
}

#[test]
fn test_claim_evidence_serde_roundtrip() {
    let cfg = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &cfg);
    let json = serde_json::to_string(&ev).unwrap();
    let back: ClaimEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn test_claim_evidence_transport_certificate_hash_equals_claim_hash() {
    let cfg = GateConfig::default();
    let c = confirmed_claim();
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.transport_certificate_hash, c.content_hash());
}

// ---------------------------------------------------------------------------
// evaluate_promotion — all decision paths
// ---------------------------------------------------------------------------

#[test]
fn test_promote_on_confirmed() {
    let cfg = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &cfg);
    let pr = evaluate_promotion(&ev, &cfg);
    assert_eq!(pr.decision, PromotionDecision::Promote);
    assert!(pr.reason.contains("fully supports"));
}

#[test]
fn test_promote_on_downgraded_within_tolerance() {
    let cfg = GateConfig::default();
    // residual 910_000 is >= full_threshold(950k) - rollback_regression(50k) = 900k
    let c = make_claim(HardwareClaimKind::Latency, "a", "b", 910_000, 50);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
    let pr = evaluate_promotion(&ev, &cfg);
    assert_eq!(pr.decision, PromotionDecision::Promote);
    assert!(pr.reason.contains("within regression tolerance"));
}

#[test]
fn test_hold_on_downgraded_outside_tolerance() {
    let cfg = GateConfig::default();
    // residual 800_000 is below full_threshold(950k) - rollback_regression(50k) = 900k
    let ev = evaluate(&downgraded_claim(), &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
    let pr = evaluate_promotion(&ev, &cfg);
    assert_eq!(pr.decision, PromotionDecision::Hold);
    assert!(pr.reason.contains("holding pending"));
}

#[test]
fn test_require_fresh_measurement_on_requires_local() {
    let cfg = GateConfig::default();
    let ev = evaluate(&requires_local_claim(), &cfg);
    let pr = evaluate_promotion(&ev, &cfg);
    assert_eq!(pr.decision, PromotionDecision::RequireFreshMeasurement);
    assert!(pr.reason.contains("fresh local measurement"));
}

#[test]
fn test_rollback_on_unsupported() {
    let cfg = GateConfig::default();
    let ev = evaluate(&unsupported_claim(), &cfg);
    let pr = evaluate_promotion(&ev, &cfg);
    assert_eq!(pr.decision, PromotionDecision::Rollback);
    assert!(pr.reason.contains("rolling back"));
}

#[test]
fn test_hold_on_insufficient_evidence() {
    let cfg = GateConfig::default();
    let ev = evaluate(&insufficient_claim(), &cfg);
    let pr = evaluate_promotion(&ev, &cfg);
    assert_eq!(pr.decision, PromotionDecision::Hold);
    assert!(pr.reason.contains("insufficient"));
}

#[test]
fn test_promotion_record_claim_id_format() {
    let cfg = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &cfg);
    let pr = evaluate_promotion(&ev, &cfg);
    assert!(pr.claim_id.contains("throughput"));
    assert!(pr.claim_id.contains("src-x86"));
    assert!(pr.claim_id.contains("dst-x86"));
}

#[test]
fn test_promotion_record_epoch_propagated() {
    let cfg = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &cfg);
    let pr = evaluate_promotion(&ev, &cfg);
    assert_eq!(pr.epoch, epoch());
}

#[test]
fn test_promotion_record_content_hash_deterministic() {
    let cfg = GateConfig::default();
    let ev1 = evaluate(&confirmed_claim(), &cfg);
    let ev2 = evaluate(&confirmed_claim(), &cfg);
    let pr1 = evaluate_promotion(&ev1, &cfg);
    let pr2 = evaluate_promotion(&ev2, &cfg);
    assert_eq!(pr1.content_hash(), pr2.content_hash());
}

#[test]
fn test_promotion_record_display() {
    let cfg = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &cfg);
    let pr = evaluate_promotion(&ev, &cfg);
    let s = pr.to_string();
    assert!(s.contains("promotion["));
    assert!(s.contains("promote"));
}

#[test]
fn test_promotion_record_serde_roundtrip() {
    let cfg = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &cfg);
    let pr = evaluate_promotion(&ev, &cfg);
    let json = serde_json::to_string(&pr).unwrap();
    let back: PromotionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(pr, back);
}

// ---------------------------------------------------------------------------
// evaluate_batch — mixed claims
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_batch_mixed_claims() {
    let cfg = GateConfig::default();
    let claims = vec![
        confirmed_claim(),
        downgraded_claim(),
        requires_local_claim(),
        unsupported_claim(),
        insufficient_claim(),
    ];
    let (evidence, summary) = evaluate_batch(&claims, &cfg);
    assert_eq!(evidence.len(), 5);
    assert_eq!(summary.total_claims, 5);
    assert_eq!(summary.confirmed, 1);
    assert_eq!(summary.downgraded, 1);
    assert_eq!(summary.requires_local, 1);
    assert_eq!(summary.unsupported, 1);
    assert_eq!(summary.insufficient, 1);
}

#[test]
fn test_evaluate_batch_all_confirmed() {
    let cfg = GateConfig::default();
    let claims = vec![confirmed_claim(), confirmed_claim(), confirmed_claim()];
    let (evidence, summary) = evaluate_batch(&claims, &cfg);
    assert_eq!(evidence.len(), 3);
    assert_eq!(summary.confirmed, 3);
    assert!(summary.all_passed());
    assert_eq!(summary.pass_rate, 1_000_000);
}

#[test]
fn test_evaluate_batch_empty() {
    let cfg = GateConfig::default();
    let (evidence, summary) = evaluate_batch(&[], &cfg);
    assert!(evidence.is_empty());
    assert_eq!(summary.total_claims, 0);
    assert_eq!(summary.pass_rate, 0);
    assert!(!summary.all_passed());
}

#[test]
fn test_evaluate_batch_all_unsupported() {
    let cfg = GateConfig::default();
    let claims = vec![unsupported_claim(), unsupported_claim()];
    let (_, summary) = evaluate_batch(&claims, &cfg);
    assert!(!summary.all_passed());
    assert!(summary.has_unsupported());
    assert_eq!(summary.pass_rate, 0);
}

// ---------------------------------------------------------------------------
// GateSummary — pass rate calculation
// ---------------------------------------------------------------------------

#[test]
fn test_gate_summary_from_verdicts_all_confirmed() {
    let verdicts = vec![ClaimVerdict::Confirmed; 4];
    let s = GateSummary::from_verdicts(&verdicts);
    assert_eq!(s.pass_rate, 1_000_000);
    assert!(s.all_passed());
}

#[test]
fn test_gate_summary_from_verdicts_half_pass() {
    let verdicts = vec![ClaimVerdict::Confirmed, ClaimVerdict::Unsupported];
    let s = GateSummary::from_verdicts(&verdicts);
    assert_eq!(s.pass_rate, 500_000);
}

#[test]
fn test_gate_summary_from_verdicts_empty() {
    let s = GateSummary::from_verdicts(&[]);
    assert_eq!(s.pass_rate, 0);
    assert_eq!(s.total_claims, 0);
}

#[test]
fn test_gate_summary_has_unsupported() {
    let verdicts = vec![ClaimVerdict::Confirmed, ClaimVerdict::Unsupported];
    let s = GateSummary::from_verdicts(&verdicts);
    assert!(s.has_unsupported());
}

#[test]
fn test_gate_summary_no_unsupported() {
    let verdicts = vec![ClaimVerdict::Confirmed, ClaimVerdict::Downgraded];
    let s = GateSummary::from_verdicts(&verdicts);
    assert!(!s.has_unsupported());
}

#[test]
fn test_gate_summary_all_passed_requires_no_failures() {
    let verdicts = vec![ClaimVerdict::Confirmed, ClaimVerdict::Downgraded];
    let s = GateSummary::from_verdicts(&verdicts);
    assert!(s.all_passed());
}

#[test]
fn test_gate_summary_all_passed_false_with_requires_local() {
    let verdicts = vec![ClaimVerdict::Confirmed, ClaimVerdict::RequiresLocal];
    let s = GateSummary::from_verdicts(&verdicts);
    assert!(!s.all_passed());
}

#[test]
fn test_gate_summary_all_passed_false_with_insufficient() {
    let verdicts = vec![ClaimVerdict::Confirmed, ClaimVerdict::InsufficientEvidence];
    let s = GateSummary::from_verdicts(&verdicts);
    assert!(!s.all_passed());
}

#[test]
fn test_gate_summary_content_hash_deterministic() {
    let v1 = vec![ClaimVerdict::Confirmed, ClaimVerdict::Unsupported];
    let v2 = vec![ClaimVerdict::Confirmed, ClaimVerdict::Unsupported];
    let s1 = GateSummary::from_verdicts(&v1);
    let s2 = GateSummary::from_verdicts(&v2);
    assert_eq!(s1.content_hash(), s2.content_hash());
}

#[test]
fn test_gate_summary_display() {
    let verdicts = vec![ClaimVerdict::Confirmed, ClaimVerdict::Downgraded];
    let s = GateSummary::from_verdicts(&verdicts);
    let display = s.to_string();
    assert!(display.contains("claims=2"));
    assert!(display.contains("confirmed=1"));
    assert!(display.contains("downgraded=1"));
}

#[test]
fn test_gate_summary_serde_roundtrip() {
    let verdicts = vec![ClaimVerdict::Confirmed, ClaimVerdict::Unsupported];
    let s = GateSummary::from_verdicts(&verdicts);
    let json = serde_json::to_string(&s).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_decision_receipt_construction() {
    let ch = ContentHash::compute(b"test-claim");
    let r = DecisionReceipt::new(epoch(), ClaimVerdict::Confirmed, ch);
    assert_eq!(r.epoch, epoch());
    assert_eq!(r.verdict, ClaimVerdict::Confirmed);
    assert_eq!(r.claim_hash, ch);
    assert_eq!(r.component, COMPONENT);
}

#[test]
fn test_decision_receipt_hash_deterministic() {
    let ch = ContentHash::compute(b"test-claim");
    let r1 = DecisionReceipt::new(epoch(), ClaimVerdict::Confirmed, ch);
    let r2 = DecisionReceipt::new(epoch(), ClaimVerdict::Confirmed, ch);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_decision_receipt_hash_differs_by_verdict() {
    let ch = ContentHash::compute(b"test-claim");
    let r1 = DecisionReceipt::new(epoch(), ClaimVerdict::Confirmed, ch);
    let r2 = DecisionReceipt::new(epoch(), ClaimVerdict::Unsupported, ch);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_decision_receipt_hash_differs_by_epoch() {
    let ch = ContentHash::compute(b"test-claim");
    let r1 = DecisionReceipt::new(SecurityEpoch::from_raw(1), ClaimVerdict::Confirmed, ch);
    let r2 = DecisionReceipt::new(SecurityEpoch::from_raw(2), ClaimVerdict::Confirmed, ch);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_decision_receipt_display() {
    let ch = ContentHash::compute(b"test-claim");
    let r = DecisionReceipt::new(epoch(), ClaimVerdict::Confirmed, ch);
    let s = r.to_string();
    assert!(s.contains("receipt["));
    assert!(s.contains("confirmed"));
}

#[test]
fn test_decision_receipt_serde_roundtrip() {
    let ch = ContentHash::compute(b"test-claim");
    let r = DecisionReceipt::new(epoch(), ClaimVerdict::Confirmed, ch);
    let json = serde_json::to_string(&r).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// RollbackRecord
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_record_construction() {
    let r = RollbackRecord::new(
        "claim-1",
        ClaimVerdict::Downgraded,
        ClaimVerdict::Unsupported,
        "regression detected",
        epoch(),
    );
    assert_eq!(r.claim_id, "claim-1");
    assert_eq!(r.original_verdict, ClaimVerdict::Downgraded);
    assert_eq!(r.rollback_verdict, ClaimVerdict::Unsupported);
    assert_eq!(r.trigger, "regression detected");
    assert_eq!(r.epoch, epoch());
}

#[test]
fn test_rollback_record_receipt_hash_deterministic() {
    let r1 = RollbackRecord::new(
        "c1",
        ClaimVerdict::Confirmed,
        ClaimVerdict::Unsupported,
        "t",
        epoch(),
    );
    let r2 = RollbackRecord::new(
        "c1",
        ClaimVerdict::Confirmed,
        ClaimVerdict::Unsupported,
        "t",
        epoch(),
    );
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_rollback_record_receipt_hash_differs_by_trigger() {
    let r1 = RollbackRecord::new(
        "c1",
        ClaimVerdict::Confirmed,
        ClaimVerdict::Unsupported,
        "t1",
        epoch(),
    );
    let r2 = RollbackRecord::new(
        "c1",
        ClaimVerdict::Confirmed,
        ClaimVerdict::Unsupported,
        "t2",
        epoch(),
    );
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_rollback_record_display() {
    let r = RollbackRecord::new(
        "claim-x",
        ClaimVerdict::Confirmed,
        ClaimVerdict::RequiresLocal,
        "perf regression",
        epoch(),
    );
    let s = r.to_string();
    assert!(s.contains("rollback[claim-x]"));
    assert!(s.contains("confirmed"));
    assert!(s.contains("requires_local"));
    assert!(s.contains("perf regression"));
}

#[test]
fn test_rollback_record_serde_roundtrip() {
    let r = RollbackRecord::new(
        "c1",
        ClaimVerdict::Confirmed,
        ClaimVerdict::Unsupported,
        "t",
        epoch(),
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// Edge cases — large batches, all claim kinds
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_all_claim_kinds() {
    let cfg = GateConfig::default();
    for kind in HardwareClaimKind::ALL {
        let c = make_claim(*kind, "src", "dst", 960_000, 100);
        let ev = evaluate(&c, &cfg);
        assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
        assert_eq!(ev.claim.kind, *kind);
    }
}

#[test]
fn test_evaluate_batch_many_claims() {
    let cfg = GateConfig::default();
    let mut claims = Vec::new();
    for i in 0..20 {
        let residual = 50_000 * (i + 1);
        claims.push(make_claim(
            HardwareClaimKind::Throughput,
            &format!("src-{}", i),
            &format!("dst-{}", i),
            residual,
            100,
        ));
    }
    let (evidence, summary) = evaluate_batch(&claims, &cfg);
    assert_eq!(evidence.len(), 20);
    assert_eq!(summary.total_claims, 20);
    assert_eq!(
        summary.confirmed
            + summary.downgraded
            + summary.requires_local
            + summary.unsupported
            + summary.insufficient,
        20
    );
}

#[test]
fn test_evaluate_with_max_residual() {
    let cfg = GateConfig::default();
    let c = make_claim(HardwareClaimKind::Throughput, "a", "b", u64::MAX, 100);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
}

#[test]
fn test_gate_summary_pass_rate_third() {
    let verdicts = vec![
        ClaimVerdict::Confirmed,
        ClaimVerdict::Unsupported,
        ClaimVerdict::Unsupported,
    ];
    let s = GateSummary::from_verdicts(&verdicts);
    assert_eq!(s.pass_rate, 333_333);
}

#[test]
fn test_promotion_downgraded_at_regression_tolerance_boundary() {
    let cfg = GateConfig::default();
    // Exactly at full_threshold - rollback_regression = 950k - 50k = 900k
    let c = make_claim(HardwareClaimKind::Latency, "a", "b", 900_000, 50);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
    let pr = evaluate_promotion(&ev, &cfg);
    assert_eq!(pr.decision, PromotionDecision::Promote);
}

#[test]
fn test_promotion_downgraded_just_below_regression_tolerance() {
    let cfg = GateConfig::default();
    // 899_999 is below 900k threshold
    let c = make_claim(HardwareClaimKind::Latency, "a", "b", 899_999, 50);
    let ev = evaluate(&c, &cfg);
    assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
    let pr = evaluate_promotion(&ev, &cfg);
    assert_eq!(pr.decision, PromotionDecision::Hold);
}
