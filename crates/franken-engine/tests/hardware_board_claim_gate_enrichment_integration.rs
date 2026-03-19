// Enrichment integration tests for hardware_board_claim_gate module.
//
// Covers: HardwareClaimKind ALL completeness, as_str values, Display uniqueness,
// serde roundtrips, ClaimVerdict/PromotionDecision/DegradationReason enums,
// GateConfig presets, evaluate/evaluate_promotion/evaluate_batch functions,
// GateSummary, DecisionReceipt, RollbackRecord, hash determinism, constants.
//
// Bead: bd-1lsy.7.16.3 [RGC-616C]

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::hardware_board_claim_gate::{
    ClaimEvidence, ClaimVerdict, DecisionReceipt, DegradationReason, GateConfig, GateSummary,
    HardwareClaim, HardwareClaimKind, PromotionDecision, PromotionRecord, RollbackRecord,
    BEAD_ID, COMPONENT, POLICY_ID, SCHEMA_VERSION, evaluate, evaluate_batch, evaluate_promotion,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn confirmed_claim() -> HardwareClaim {
    HardwareClaim::new(
        HardwareClaimKind::Throughput,
        "cell-a",
        "cell-b",
        2_000_000,
        1_200_000,
        960_000,
        100,
        ep(500),
    )
}

fn downgraded_claim() -> HardwareClaim {
    HardwareClaim::new(
        HardwareClaimKind::Latency,
        "cell-a",
        "cell-c",
        1_500_000,
        1_100_000,
        800_000,
        50,
        ep(500),
    )
}

fn requires_local_claim() -> HardwareClaim {
    HardwareClaim::new(
        HardwareClaimKind::MemoryEfficiency,
        "cell-a",
        "cell-d",
        1_000_000,
        1_050_000,
        400_000,
        30,
        ep(500),
    )
}

fn unsupported_claim() -> HardwareClaim {
    HardwareClaim::new(
        HardwareClaimKind::StartupTime,
        "cell-a",
        "cell-e",
        800_000,
        1_300_000,
        100_000,
        25,
        ep(500),
    )
}

fn insufficient_claim() -> HardwareClaim {
    HardwareClaim::new(
        HardwareClaimKind::TailLatency,
        "cell-a",
        "cell-f",
        900_000,
        1_150_000,
        950_000,
        5, // below default min_samples=10
        ep(500),
    )
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_version_non_empty() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("hardware-board-claim-gate"));
}

#[test]
fn enrichment_bead_id_starts_with_bd() {
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(!BEAD_ID.is_empty());
}

#[test]
fn enrichment_component_value() {
    assert_eq!(COMPONENT, "hardware_board_claim_gate");
}

#[test]
fn enrichment_policy_id_starts_with_rgc() {
    assert!(POLICY_ID.starts_with("RGC-"));
    assert!(!POLICY_ID.is_empty());
}

// ===========================================================================
// HardwareClaimKind
// ===========================================================================

#[test]
fn enrichment_claim_kind_all_has_six_entries() {
    assert_eq!(HardwareClaimKind::ALL.len(), 6);
}

#[test]
fn enrichment_claim_kind_all_unique() {
    let set: BTreeSet<HardwareClaimKind> = HardwareClaimKind::ALL.iter().copied().collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_claim_kind_as_str_values() {
    assert_eq!(HardwareClaimKind::Throughput.as_str(), "throughput");
    assert_eq!(HardwareClaimKind::Latency.as_str(), "latency");
    assert_eq!(HardwareClaimKind::MemoryEfficiency.as_str(), "memory_efficiency");
    assert_eq!(HardwareClaimKind::StartupTime.as_str(), "startup_time");
    assert_eq!(HardwareClaimKind::TailLatency.as_str(), "tail_latency");
    assert_eq!(HardwareClaimKind::EnergyEfficiency.as_str(), "energy_efficiency");
}

#[test]
fn enrichment_claim_kind_display_matches_as_str() {
    for kind in HardwareClaimKind::ALL {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

#[test]
fn enrichment_claim_kind_display_unique() {
    let displays: BTreeSet<String> = HardwareClaimKind::ALL
        .iter()
        .map(|k| format!("{k}"))
        .collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_claim_kind_serde_roundtrip_all() {
    for kind in HardwareClaimKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: HardwareClaimKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn enrichment_claim_kind_ordering_deterministic() {
    let mut kinds: Vec<HardwareClaimKind> = HardwareClaimKind::ALL.to_vec();
    kinds.sort();
    let mut kinds2 = kinds.clone();
    kinds2.sort();
    assert_eq!(kinds, kinds2);
}

// ===========================================================================
// ClaimVerdict
// ===========================================================================

#[test]
fn enrichment_verdict_all_has_five_entries() {
    assert_eq!(ClaimVerdict::ALL.len(), 5);
}

#[test]
fn enrichment_verdict_all_unique() {
    let set: BTreeSet<ClaimVerdict> = ClaimVerdict::ALL.iter().copied().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_verdict_as_str_values() {
    assert_eq!(ClaimVerdict::Confirmed.as_str(), "confirmed");
    assert_eq!(ClaimVerdict::Downgraded.as_str(), "downgraded");
    assert_eq!(ClaimVerdict::RequiresLocal.as_str(), "requires_local");
    assert_eq!(ClaimVerdict::Unsupported.as_str(), "unsupported");
    assert_eq!(ClaimVerdict::InsufficientEvidence.as_str(), "insufficient_evidence");
}

#[test]
fn enrichment_verdict_is_usable() {
    assert!(ClaimVerdict::Confirmed.is_usable());
    assert!(ClaimVerdict::Downgraded.is_usable());
    assert!(!ClaimVerdict::RequiresLocal.is_usable());
    assert!(!ClaimVerdict::Unsupported.is_usable());
    assert!(!ClaimVerdict::InsufficientEvidence.is_usable());
}

#[test]
fn enrichment_verdict_serde_roundtrip_all() {
    for v in ClaimVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: ClaimVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_verdict_display_matches_as_str() {
    for v in ClaimVerdict::ALL {
        assert_eq!(v.to_string(), v.as_str());
    }
}

// ===========================================================================
// PromotionDecision
// ===========================================================================

#[test]
fn enrichment_promotion_all_has_four_entries() {
    assert_eq!(PromotionDecision::ALL.len(), 4);
}

#[test]
fn enrichment_promotion_as_str_values() {
    assert_eq!(PromotionDecision::Promote.as_str(), "promote");
    assert_eq!(PromotionDecision::Hold.as_str(), "hold");
    assert_eq!(PromotionDecision::Rollback.as_str(), "rollback");
    assert_eq!(PromotionDecision::RequireFreshMeasurement.as_str(), "require_fresh_measurement");
}

#[test]
fn enrichment_promotion_display_unique() {
    let displays: BTreeSet<String> = PromotionDecision::ALL
        .iter()
        .map(|d| format!("{d}"))
        .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_promotion_serde_roundtrip_all() {
    for d in PromotionDecision::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: PromotionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

// ===========================================================================
// DegradationReason
// ===========================================================================

#[test]
fn enrichment_degradation_all_has_six_entries() {
    assert_eq!(DegradationReason::ALL.len(), 6);
}

#[test]
fn enrichment_degradation_as_str_values() {
    assert_eq!(DegradationReason::ArchMismatch.as_str(), "arch_mismatch");
    assert_eq!(DegradationReason::VectorWidthLoss.as_str(), "vector_width_loss");
    assert_eq!(DegradationReason::CacheSizeDifference.as_str(), "cache_size_difference");
    assert_eq!(DegradationReason::MicroarchVariance.as_str(), "microarch_variance");
    assert_eq!(DegradationReason::InsufficientSamples.as_str(), "insufficient_samples");
    assert_eq!(DegradationReason::ResidualTooLow.as_str(), "residual_too_low");
}

#[test]
fn enrichment_degradation_names_unique() {
    let names: BTreeSet<&str> = DegradationReason::ALL.iter().map(|r| r.as_str()).collect();
    assert_eq!(names.len(), DegradationReason::ALL.len());
}

#[test]
fn enrichment_degradation_serde_roundtrip_all() {
    for r in DegradationReason::ALL {
        let json = serde_json::to_string(r).unwrap();
        let back: DegradationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ===========================================================================
// HardwareClaim
// ===========================================================================

#[test]
fn enrichment_claim_construction_and_fields() {
    let c = confirmed_claim();
    assert_eq!(c.kind, HardwareClaimKind::Throughput);
    assert_eq!(c.source_cell_id, "cell-a");
    assert_eq!(c.target_cell_id, "cell-b");
    assert_eq!(c.transport_residual, 960_000);
    assert_eq!(c.sample_count, 100);
}

#[test]
fn enrichment_claim_content_hash_deterministic() {
    let h1 = confirmed_claim().content_hash();
    let h2 = confirmed_claim().content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_claim_content_hash_varies_by_kind() {
    let h1 = confirmed_claim().content_hash();
    let h2 = downgraded_claim().content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn enrichment_claim_is_same_cell_true() {
    let c = HardwareClaim::new(
        HardwareClaimKind::Throughput, "cell-x", "cell-x",
        1_000_000, 1_000_000, 1_000_000, 10, ep(1),
    );
    assert!(c.is_same_cell());
}

#[test]
fn enrichment_claim_is_same_cell_false() {
    assert!(!confirmed_claim().is_same_cell());
}

#[test]
fn enrichment_claim_serde_roundtrip() {
    let c = confirmed_claim();
    let json = serde_json::to_string(&c).unwrap();
    let back: HardwareClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_claim_display_contains_kind() {
    let s = confirmed_claim().to_string();
    assert!(s.contains("throughput"));
    assert!(s.contains("cell-a"));
}

// ===========================================================================
// evaluate
// ===========================================================================

#[test]
fn enrichment_evaluate_confirmed_verdict() {
    let ev = evaluate(&confirmed_claim(), &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
    assert!(ev.is_supported());
}

#[test]
fn enrichment_evaluate_downgraded_verdict() {
    let ev = evaluate(&downgraded_claim(), &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
    assert!(ev.is_supported());
}

#[test]
fn enrichment_evaluate_requires_local_verdict() {
    let ev = evaluate(&requires_local_claim(), &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::RequiresLocal);
    assert!(!ev.is_supported());
}

#[test]
fn enrichment_evaluate_unsupported_verdict() {
    let ev = evaluate(&unsupported_claim(), &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::Unsupported);
    assert!(!ev.is_supported());
}

#[test]
fn enrichment_evaluate_insufficient_verdict() {
    let ev = evaluate(&insufficient_claim(), &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::InsufficientEvidence);
    assert!(!ev.is_supported());
}

#[test]
fn enrichment_evaluate_evidence_hash_deterministic() {
    let config = GateConfig::default();
    let h1 = evaluate(&confirmed_claim(), &config).content_hash();
    let h2 = evaluate(&confirmed_claim(), &config).content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_evaluate_evidence_serde_roundtrip() {
    let ev = evaluate(&downgraded_claim(), &GateConfig::default());
    let json = serde_json::to_string(&ev).unwrap();
    let back: ClaimEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_evaluate_permissive_always_confirmed() {
    let config = GateConfig::permissive();
    for claim in &[confirmed_claim(), downgraded_claim(), requires_local_claim(), unsupported_claim()] {
        let ev = evaluate(claim, &config);
        assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
    }
}

#[test]
fn enrichment_evaluate_strict_tighter_than_default() {
    let claim = confirmed_claim();
    let default_ev = evaluate(&claim, &GateConfig::default());
    let strict_ev = evaluate(&claim, &GateConfig::strict());
    assert_eq!(default_ev.verdict, ClaimVerdict::Confirmed);
    assert_eq!(strict_ev.verdict, ClaimVerdict::Downgraded);
}

// ===========================================================================
// evaluate_promotion
// ===========================================================================

#[test]
fn enrichment_promotion_confirmed_promotes() {
    let config = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &config);
    let pr = evaluate_promotion(&ev, &config);
    assert_eq!(pr.decision, PromotionDecision::Promote);
}

#[test]
fn enrichment_promotion_unsupported_rollback() {
    let config = GateConfig::default();
    let ev = evaluate(&unsupported_claim(), &config);
    let pr = evaluate_promotion(&ev, &config);
    assert_eq!(pr.decision, PromotionDecision::Rollback);
}

#[test]
fn enrichment_promotion_record_hash_deterministic() {
    let config = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &config);
    let pr = evaluate_promotion(&ev, &config);
    let h1 = pr.content_hash();
    let h2 = pr.content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_promotion_record_serde_roundtrip() {
    let config = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &config);
    let pr = evaluate_promotion(&ev, &config);
    let json = serde_json::to_string(&pr).unwrap();
    let back: PromotionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(pr, back);
}

// ===========================================================================
// evaluate_batch
// ===========================================================================

#[test]
fn enrichment_batch_mixed_verdicts() {
    let claims = vec![
        confirmed_claim(), downgraded_claim(), requires_local_claim(),
        unsupported_claim(), insufficient_claim(),
    ];
    let (evidence, summary) = evaluate_batch(&claims, &GateConfig::default());
    assert_eq!(evidence.len(), 5);
    assert_eq!(summary.total_claims, 5);
    assert_eq!(summary.confirmed, 1);
    assert_eq!(summary.downgraded, 1);
    assert_eq!(summary.pass_rate, 400_000);
}

#[test]
fn enrichment_batch_all_confirmed() {
    let claims = vec![confirmed_claim(); 3];
    let (_, summary) = evaluate_batch(&claims, &GateConfig::default());
    assert!(summary.all_passed());
    assert_eq!(summary.pass_rate, 1_000_000);
}

#[test]
fn enrichment_batch_empty() {
    let (evidence, summary) = evaluate_batch(&[], &GateConfig::default());
    assert!(evidence.is_empty());
    assert_eq!(summary.total_claims, 0);
    assert!(!summary.all_passed());
}

// ===========================================================================
// GateSummary
// ===========================================================================

#[test]
fn enrichment_summary_has_unsupported() {
    let s = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed, ClaimVerdict::Unsupported]);
    assert!(s.has_unsupported());
}

#[test]
fn enrichment_summary_content_hash_deterministic() {
    let s1 = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed]);
    let s2 = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed]);
    assert_eq!(s1.content_hash(), s2.content_hash());
}

#[test]
fn enrichment_summary_serde_roundtrip() {
    let s = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed, ClaimVerdict::RequiresLocal]);
    let json = serde_json::to_string(&s).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ===========================================================================
// GateConfig
// ===========================================================================

#[test]
fn enrichment_gate_config_default_serde_roundtrip() {
    let config = GateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_gate_config_strict_higher_thresholds() {
    let strict = GateConfig::strict();
    let default = GateConfig::default();
    assert!(strict.full_transport_threshold >= default.full_transport_threshold);
    assert!(strict.min_samples >= default.min_samples);
}

// ===========================================================================
// RollbackRecord
// ===========================================================================

#[test]
fn enrichment_rollback_record_creation() {
    let rb = RollbackRecord::new(
        "claim-1", ClaimVerdict::Downgraded, ClaimVerdict::Unsupported,
        "regression detected", ep(500),
    );
    assert_eq!(rb.claim_id, "claim-1");
    assert_eq!(rb.original_verdict, ClaimVerdict::Downgraded);
    assert_eq!(rb.rollback_verdict, ClaimVerdict::Unsupported);
}

#[test]
fn enrichment_rollback_record_hash_deterministic() {
    let rb1 = RollbackRecord::new("c1", ClaimVerdict::Confirmed, ClaimVerdict::RequiresLocal, "d", ep(1));
    let rb2 = RollbackRecord::new("c1", ClaimVerdict::Confirmed, ClaimVerdict::RequiresLocal, "d", ep(1));
    assert_eq!(rb1.receipt_hash, rb2.receipt_hash);
}

#[test]
fn enrichment_rollback_record_serde_roundtrip() {
    let rb = RollbackRecord::new("c3", ClaimVerdict::Downgraded, ClaimVerdict::RequiresLocal, "spike", ep(1));
    let json = serde_json::to_string(&rb).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rb, back);
}

// ===========================================================================
// DecisionReceipt
// ===========================================================================

#[test]
fn enrichment_decision_receipt_creation() {
    let hash = ContentHash::compute(b"test");
    let receipt = DecisionReceipt::new(ep(1), ClaimVerdict::Confirmed, hash);
    assert_eq!(receipt.verdict, ClaimVerdict::Confirmed);
    assert_eq!(receipt.component, COMPONENT);
}

#[test]
fn enrichment_decision_receipt_hash_deterministic() {
    let hash = ContentHash::compute(b"x");
    let r1 = DecisionReceipt::new(ep(1), ClaimVerdict::Downgraded, hash);
    let r2 = DecisionReceipt::new(ep(1), ClaimVerdict::Downgraded, hash);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_decision_receipt_different_verdicts_different_hashes() {
    let hash = ContentHash::compute(b"y");
    let r1 = DecisionReceipt::new(ep(1), ClaimVerdict::Confirmed, hash);
    let r2 = DecisionReceipt::new(ep(1), ClaimVerdict::Unsupported, hash);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_decision_receipt_serde_roundtrip() {
    let receipt = DecisionReceipt::new(ep(1), ClaimVerdict::Confirmed, ContentHash::compute(b"serde"));
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}
