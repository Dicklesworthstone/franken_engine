//! Enrichment integration tests for `hardware_board_claim_gate`.
//!
//! Covers: HardwareClaimKind, ClaimVerdict, PromotionDecision, DegradationReason
//! serde/display/ordering, HardwareClaim construction/hashing, ClaimEvidence
//! lifecycle, PromotionRecord, RollbackRecord, GateConfig variants, GateSummary
//! computation, DecisionReceipt, evaluate/evaluate_promotion/evaluate_batch
//! integration, boundary conditions, and determinism.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
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
fn constants_schema_version() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("hardware-board-claim-gate"));
}

#[test]
fn constants_bead_id() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn constants_component() {
    assert_eq!(COMPONENT, "hardware_board_claim_gate");
}

#[test]
fn constants_policy_id() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

// ===========================================================================
// HardwareClaimKind
// ===========================================================================

#[test]
fn claim_kind_all_variants() {
    assert_eq!(HardwareClaimKind::ALL.len(), 6);
    let names: BTreeSet<&str> = HardwareClaimKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(names.len(), 6);
}

#[test]
fn claim_kind_serde_roundtrip_all() {
    for kind in HardwareClaimKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: HardwareClaimKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn claim_kind_display_matches_as_str() {
    for kind in HardwareClaimKind::ALL {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

// ===========================================================================
// ClaimVerdict
// ===========================================================================

#[test]
fn verdict_all_variants() {
    assert_eq!(ClaimVerdict::ALL.len(), 5);
}

#[test]
fn verdict_serde_roundtrip_all() {
    for v in ClaimVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: ClaimVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn verdict_is_usable() {
    assert!(ClaimVerdict::Confirmed.is_usable());
    assert!(ClaimVerdict::Downgraded.is_usable());
    assert!(!ClaimVerdict::RequiresLocal.is_usable());
    assert!(!ClaimVerdict::Unsupported.is_usable());
    assert!(!ClaimVerdict::InsufficientEvidence.is_usable());
}

#[test]
fn verdict_display_matches_as_str() {
    for v in ClaimVerdict::ALL {
        assert_eq!(v.to_string(), v.as_str());
    }
}

// ===========================================================================
// PromotionDecision
// ===========================================================================

#[test]
fn promotion_all_variants() {
    assert_eq!(PromotionDecision::ALL.len(), 4);
}

#[test]
fn promotion_serde_roundtrip_all() {
    for d in PromotionDecision::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: PromotionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn promotion_display_matches_as_str() {
    for d in PromotionDecision::ALL {
        assert_eq!(d.to_string(), d.as_str());
    }
}

// ===========================================================================
// DegradationReason
// ===========================================================================

#[test]
fn degradation_all_variants() {
    assert_eq!(DegradationReason::ALL.len(), 6);
}

#[test]
fn degradation_serde_roundtrip_all() {
    for r in DegradationReason::ALL {
        let json = serde_json::to_string(r).unwrap();
        let back: DegradationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn degradation_names_unique() {
    let names: BTreeSet<&str> = DegradationReason::ALL.iter().map(|r| r.as_str()).collect();
    assert_eq!(names.len(), DegradationReason::ALL.len());
}

// ===========================================================================
// HardwareClaim
// ===========================================================================

#[test]
fn claim_construction_and_fields() {
    let c = confirmed_claim();
    assert_eq!(c.kind, HardwareClaimKind::Throughput);
    assert_eq!(c.source_cell_id, "cell-a");
    assert_eq!(c.target_cell_id, "cell-b");
    assert_eq!(c.transport_residual, 960_000);
    assert_eq!(c.sample_count, 100);
}

#[test]
fn claim_content_hash_deterministic() {
    let h1 = confirmed_claim().content_hash();
    let h2 = confirmed_claim().content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn claim_content_hash_differs_between_claims() {
    let h1 = confirmed_claim().content_hash();
    let h2 = downgraded_claim().content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn claim_is_same_cell_true() {
    let c = HardwareClaim::new(
        HardwareClaimKind::Throughput,
        "cell-x",
        "cell-x",
        1_000_000,
        1_000_000,
        1_000_000,
        10,
        ep(1),
    );
    assert!(c.is_same_cell());
}

#[test]
fn claim_is_same_cell_false() {
    assert!(!confirmed_claim().is_same_cell());
}

#[test]
fn claim_display_contains_fields() {
    let s = confirmed_claim().to_string();
    assert!(s.contains("throughput"));
    assert!(s.contains("cell-a"));
    assert!(s.contains("cell-b"));
}

#[test]
fn claim_serde_roundtrip() {
    let c = confirmed_claim();
    let json = serde_json::to_string(&c).unwrap();
    let back: HardwareClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// evaluate
// ===========================================================================

#[test]
fn evaluate_confirmed_verdict() {
    let ev = evaluate(&confirmed_claim(), &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
    assert!(ev.is_supported());
    assert!(ev.explanation.contains("confirmed"));
}

#[test]
fn evaluate_downgraded_verdict() {
    let ev = evaluate(&downgraded_claim(), &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
    assert!(ev.is_supported());
    assert!(!ev.degradation_reasons.is_empty());
}

#[test]
fn evaluate_requires_local_verdict() {
    let ev = evaluate(&requires_local_claim(), &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::RequiresLocal);
    assert!(!ev.is_supported());
}

#[test]
fn evaluate_unsupported_verdict() {
    let ev = evaluate(&unsupported_claim(), &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::Unsupported);
    assert!(!ev.is_supported());
}

#[test]
fn evaluate_insufficient_verdict() {
    let ev = evaluate(&insufficient_claim(), &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::InsufficientEvidence);
    assert!(!ev.is_supported());
}

#[test]
fn evaluate_evidence_hash_deterministic() {
    let config = GateConfig::default();
    let h1 = evaluate(&confirmed_claim(), &config).content_hash();
    let h2 = evaluate(&confirmed_claim(), &config).content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn evaluate_evidence_display() {
    let ev = evaluate(&confirmed_claim(), &GateConfig::default());
    let s = ev.to_string();
    assert!(s.contains("confirmed"));
}

#[test]
fn evaluate_evidence_serde_roundtrip() {
    let ev = evaluate(&downgraded_claim(), &GateConfig::default());
    let json = serde_json::to_string(&ev).unwrap();
    let back: ClaimEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ===========================================================================
// evaluate — boundary conditions
// ===========================================================================

#[test]
fn evaluate_boundary_at_full_threshold() {
    let claim = HardwareClaim::new(
        HardwareClaimKind::Latency,
        "src",
        "dst",
        1_000_000,
        1_050_000,
        950_000,
        100,
        ep(1),
    );
    let ev = evaluate(&claim, &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
}

#[test]
fn evaluate_boundary_just_below_full_threshold() {
    let claim = HardwareClaim::new(
        HardwareClaimKind::Latency,
        "src",
        "dst",
        1_000_000,
        1_050_000,
        949_999,
        100,
        ep(1),
    );
    let ev = evaluate(&claim, &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
}

#[test]
fn evaluate_boundary_at_partial_threshold() {
    let claim = HardwareClaim::new(
        HardwareClaimKind::Latency,
        "src",
        "dst",
        1_000_000,
        1_050_000,
        700_000,
        100,
        ep(1),
    );
    let ev = evaluate(&claim, &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
}

#[test]
fn evaluate_boundary_at_degraded_threshold() {
    let claim = HardwareClaim::new(
        HardwareClaimKind::Latency,
        "src",
        "dst",
        1_000_000,
        1_050_000,
        300_000,
        100,
        ep(1),
    );
    let ev = evaluate(&claim, &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::RequiresLocal);
}

#[test]
fn evaluate_zero_residual() {
    let claim = HardwareClaim::new(
        HardwareClaimKind::EnergyEfficiency,
        "src",
        "dst",
        1_000_000,
        1_100_000,
        0,
        100,
        ep(1),
    );
    let ev = evaluate(&claim, &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::Unsupported);
}

#[test]
fn evaluate_max_residual() {
    let claim = HardwareClaim::new(
        HardwareClaimKind::Throughput,
        "src",
        "dst",
        1_000_000,
        1_500_000,
        1_000_000,
        100,
        ep(1),
    );
    let ev = evaluate(&claim, &GateConfig::default());
    assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
}

// ===========================================================================
// evaluate — config variations
// ===========================================================================

#[test]
fn evaluate_permissive_config_always_confirmed() {
    let config = GateConfig::permissive();
    for claim in &[
        confirmed_claim(),
        downgraded_claim(),
        requires_local_claim(),
        unsupported_claim(),
    ] {
        let ev = evaluate(claim, &config);
        assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
    }
}

#[test]
fn evaluate_strict_config_tighter() {
    let claim = HardwareClaim::new(
        HardwareClaimKind::Throughput,
        "src",
        "dst",
        1_000_000,
        1_200_000,
        960_000,
        100,
        ep(1),
    );
    let default_ev = evaluate(&claim, &GateConfig::default());
    let strict_ev = evaluate(&claim, &GateConfig::strict());
    assert_eq!(default_ev.verdict, ClaimVerdict::Confirmed);
    assert_eq!(strict_ev.verdict, ClaimVerdict::Downgraded);
}

// ===========================================================================
// evaluate_promotion
// ===========================================================================

#[test]
fn promotion_confirmed_promotes() {
    let config = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &config);
    let pr = evaluate_promotion(&ev, &config);
    assert_eq!(pr.decision, PromotionDecision::Promote);
}

#[test]
fn promotion_downgraded_holds() {
    let config = GateConfig::default();
    let ev = evaluate(&downgraded_claim(), &config);
    let pr = evaluate_promotion(&ev, &config);
    assert_eq!(pr.decision, PromotionDecision::Hold);
}

#[test]
fn promotion_requires_local_fresh_measurement() {
    let config = GateConfig::default();
    let ev = evaluate(&requires_local_claim(), &config);
    let pr = evaluate_promotion(&ev, &config);
    assert_eq!(pr.decision, PromotionDecision::RequireFreshMeasurement);
}

#[test]
fn promotion_unsupported_rollback() {
    let config = GateConfig::default();
    let ev = evaluate(&unsupported_claim(), &config);
    let pr = evaluate_promotion(&ev, &config);
    assert_eq!(pr.decision, PromotionDecision::Rollback);
}

#[test]
fn promotion_insufficient_holds() {
    let config = GateConfig::default();
    let ev = evaluate(&insufficient_claim(), &config);
    let pr = evaluate_promotion(&ev, &config);
    assert_eq!(pr.decision, PromotionDecision::Hold);
}

#[test]
fn promotion_record_content_hash_deterministic() {
    let config = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &config);
    let pr = evaluate_promotion(&ev, &config);
    let h1 = pr.content_hash();
    let h2 = pr.content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn promotion_record_display() {
    let config = GateConfig::default();
    let ev = evaluate(&confirmed_claim(), &config);
    let pr = evaluate_promotion(&ev, &config);
    let s = pr.to_string();
    assert!(s.contains("promotion"));
}

#[test]
fn promotion_record_serde_roundtrip() {
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
fn batch_mixed_verdicts() {
    let claims = vec![
        confirmed_claim(),
        downgraded_claim(),
        requires_local_claim(),
        unsupported_claim(),
        insufficient_claim(),
    ];
    let (evidence, summary) = evaluate_batch(&claims, &GateConfig::default());
    assert_eq!(evidence.len(), 5);
    assert_eq!(summary.total_claims, 5);
    assert_eq!(summary.confirmed, 1);
    assert_eq!(summary.downgraded, 1);
    assert_eq!(summary.requires_local, 1);
    assert_eq!(summary.unsupported, 1);
    assert_eq!(summary.insufficient, 1);
    assert_eq!(summary.pass_rate, 400_000);
}

#[test]
fn batch_all_confirmed() {
    let claims = vec![confirmed_claim(); 3];
    let (_, summary) = evaluate_batch(&claims, &GateConfig::default());
    assert!(summary.all_passed());
    assert_eq!(summary.pass_rate, 1_000_000);
}

#[test]
fn batch_empty() {
    let (evidence, summary) = evaluate_batch(&[], &GateConfig::default());
    assert!(evidence.is_empty());
    assert_eq!(summary.total_claims, 0);
    assert_eq!(summary.pass_rate, 0);
    assert!(!summary.all_passed());
}

// ===========================================================================
// GateSummary
// ===========================================================================

#[test]
fn summary_has_unsupported() {
    let s = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed, ClaimVerdict::Unsupported]);
    assert!(s.has_unsupported());
}

#[test]
fn summary_content_hash_deterministic() {
    let s1 = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed]);
    let s2 = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed]);
    assert_eq!(s1.content_hash(), s2.content_hash());
}

#[test]
fn summary_display() {
    let s = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed, ClaimVerdict::Downgraded]);
    let d = s.to_string();
    assert!(d.contains("claims=2"));
    assert!(d.contains("confirmed=1"));
}

#[test]
fn summary_serde_roundtrip() {
    let s = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed, ClaimVerdict::RequiresLocal]);
    let json = serde_json::to_string(&s).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ===========================================================================
// RollbackRecord
// ===========================================================================

#[test]
fn rollback_record_creation() {
    let rb = RollbackRecord::new(
        "claim-1",
        ClaimVerdict::Downgraded,
        ClaimVerdict::Unsupported,
        "regression detected",
        ep(500),
    );
    assert_eq!(rb.claim_id, "claim-1");
    assert_eq!(rb.original_verdict, ClaimVerdict::Downgraded);
    assert_eq!(rb.rollback_verdict, ClaimVerdict::Unsupported);
}

#[test]
fn rollback_record_hash_deterministic() {
    let rb1 = RollbackRecord::new("c1", ClaimVerdict::Confirmed, ClaimVerdict::RequiresLocal, "d", ep(1));
    let rb2 = RollbackRecord::new("c1", ClaimVerdict::Confirmed, ClaimVerdict::RequiresLocal, "d", ep(1));
    assert_eq!(rb1.receipt_hash, rb2.receipt_hash);
}

#[test]
fn rollback_record_display() {
    let rb = RollbackRecord::new("c2", ClaimVerdict::Confirmed, ClaimVerdict::Unsupported, "arch", ep(1));
    let s = rb.to_string();
    assert!(s.contains("rollback"));
    assert!(s.contains("c2"));
}

#[test]
fn rollback_record_serde_roundtrip() {
    let rb = RollbackRecord::new("c3", ClaimVerdict::Downgraded, ClaimVerdict::RequiresLocal, "spike", ep(1));
    let json = serde_json::to_string(&rb).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rb, back);
}

// ===========================================================================
// DecisionReceipt
// ===========================================================================

#[test]
fn decision_receipt_creation() {
    let hash = ContentHash::compute(b"test");
    let receipt = DecisionReceipt::new(ep(1), ClaimVerdict::Confirmed, hash);
    assert_eq!(receipt.verdict, ClaimVerdict::Confirmed);
    assert_eq!(receipt.component, COMPONENT);
}

#[test]
fn decision_receipt_hash_deterministic() {
    let hash = ContentHash::compute(b"x");
    let r1 = DecisionReceipt::new(ep(1), ClaimVerdict::Downgraded, hash);
    let r2 = DecisionReceipt::new(ep(1), ClaimVerdict::Downgraded, hash);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn decision_receipt_different_verdicts_different_hashes() {
    let hash = ContentHash::compute(b"y");
    let r1 = DecisionReceipt::new(ep(1), ClaimVerdict::Confirmed, hash);
    let r2 = DecisionReceipt::new(ep(1), ClaimVerdict::Unsupported, hash);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn decision_receipt_display() {
    let receipt = DecisionReceipt::new(ep(1), ClaimVerdict::RequiresLocal, ContentHash::compute(b"abc"));
    let s = receipt.to_string();
    assert!(s.contains("receipt"));
    assert!(s.contains("requires_local"));
}

#[test]
fn decision_receipt_serde_roundtrip() {
    let receipt = DecisionReceipt::new(ep(1), ClaimVerdict::Confirmed, ContentHash::compute(b"serde"));
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ===========================================================================
// GateConfig
// ===========================================================================

#[test]
fn gate_config_default_serde_roundtrip() {
    let config = GateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn gate_config_permissive_serde_roundtrip() {
    let config = GateConfig::permissive();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn gate_config_strict_serde_roundtrip() {
    let config = GateConfig::strict();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}
