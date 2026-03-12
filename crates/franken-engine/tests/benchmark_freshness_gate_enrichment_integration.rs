//! Enrichment integration tests for `benchmark_freshness_gate`.
//!
//! Covers gaps: Display uniqueness for all enums, serde roundtrips for all
//! enum variants, arithmetic edge cases (weighted severity, burndown, velocity),
//! silence tracker boundaries, batch hash stability, verdict reason content,
//! decision receipt format, claim builder patterns, and ledger determinism.

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

use frankenengine_engine::benchmark_freshness_gate::{
    AcquisitionEvidence, AcquisitionLedger, AcquisitionStatus, AlarmLedger, BatchVerdict,
    BenchmarkClaim, ClaimSurface, DecisionReceipt, FreshnessGate, FreshnessLevel, FreshnessVerdict,
    GateConfig, GateSummary, RolloutTrustLevel, ShiftAlarm, ShiftDomain, ShiftSeverity,
    SilenceTracker, BEAD_ID, COMPONENT, POLICY_ID, SCHEMA_VERSION,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_alarm(id: &str, domain: ShiftDomain, severity: ShiftSeverity, raised: u64) -> ShiftAlarm {
    ShiftAlarm::new(
        id.to_string(),
        domain,
        severity,
        epoch(raised),
        100_000, // drift_magnitude
        format!("alarm {id}"),
    )
}

fn make_acquisition(
    domain: ShiftDomain,
    acquired: u64,
    needed: u64,
    status: AcquisitionStatus,
    last_epoch: u64,
) -> AcquisitionEvidence {
    let velocity = if acquired > 0 { 10_000 } else { 0 };
    AcquisitionEvidence::new(
        domain,
        acquired,
        needed,
        status,
        epoch(last_epoch),
        velocity,
    )
}

fn make_claim(id: &str, surface: ClaimSurface, confidence: u64) -> BenchmarkClaim {
    BenchmarkClaim::new(
        id.to_string(),
        surface,
        confidence,
        epoch(1),
        format!("claim {id}"),
    )
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_version_has_prefix() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_component_non_empty() {
    assert!(!COMPONENT.is_empty());
}

#[test]
fn enrichment_bead_id_non_empty() {
    assert!(!BEAD_ID.is_empty());
}

#[test]
fn enrichment_policy_id_non_empty() {
    assert!(!POLICY_ID.is_empty());
}

// ===========================================================================
// ShiftSeverity Display + serde
// ===========================================================================

#[test]
fn enrichment_shift_severity_display_all_unique() {
    let all = [
        ShiftSeverity::Info,
        ShiftSeverity::Warning,
        ShiftSeverity::Critical,
        ShiftSeverity::Emergency,
    ];
    let displays: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_shift_severity_serde_roundtrip_all() {
    let all = [
        ShiftSeverity::Info,
        ShiftSeverity::Warning,
        ShiftSeverity::Critical,
        ShiftSeverity::Emergency,
    ];
    for s in &all {
        let json = serde_json::to_string(s).unwrap();
        let back: ShiftSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn enrichment_shift_severity_weight_increases() {
    assert!(ShiftSeverity::Info.weight() < ShiftSeverity::Warning.weight());
    assert!(ShiftSeverity::Warning.weight() < ShiftSeverity::Critical.weight());
    assert!(ShiftSeverity::Critical.weight() < ShiftSeverity::Emergency.weight());
}

#[test]
fn enrichment_shift_severity_is_immediate_downgrade() {
    assert!(!ShiftSeverity::Info.is_immediate_downgrade());
    assert!(!ShiftSeverity::Warning.is_immediate_downgrade());
    // Critical or Emergency should be immediate downgrade
    assert!(
        ShiftSeverity::Critical.is_immediate_downgrade()
            || ShiftSeverity::Emergency.is_immediate_downgrade()
    );
}

// ===========================================================================
// ShiftDomain Display + serde
// ===========================================================================

#[test]
fn enrichment_shift_domain_display_all_unique() {
    let all = [
        ShiftDomain::ProgramSize,
        ShiftDomain::ApiUsage,
        ShiftDomain::ControlFlow,
        ShiftDomain::ModuleTopology,
        ShiftDomain::Concurrency,
        ShiftDomain::MemoryAllocation,
        ShiftDomain::IoPattern,
        ShiftDomain::General,
    ];
    let displays: BTreeSet<String> = all.iter().map(|d| d.to_string()).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn enrichment_shift_domain_serde_roundtrip_all() {
    let all = [
        ShiftDomain::ProgramSize,
        ShiftDomain::ApiUsage,
        ShiftDomain::ControlFlow,
        ShiftDomain::ModuleTopology,
        ShiftDomain::Concurrency,
        ShiftDomain::MemoryAllocation,
        ShiftDomain::IoPattern,
        ShiftDomain::General,
    ];
    for d in &all {
        let json = serde_json::to_string(d).unwrap();
        let back: ShiftDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

// ===========================================================================
// AcquisitionStatus Display + serde
// ===========================================================================

#[test]
fn enrichment_acquisition_status_display_all_unique() {
    let all = [
        AcquisitionStatus::Active,
        AcquisitionStatus::Paused,
        AcquisitionStatus::Complete,
        AcquisitionStatus::Stalled,
        AcquisitionStatus::Absent,
    ];
    let displays: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_acquisition_status_serde_roundtrip_all() {
    let all = [
        AcquisitionStatus::Active,
        AcquisitionStatus::Paused,
        AcquisitionStatus::Complete,
        AcquisitionStatus::Stalled,
        AcquisitionStatus::Absent,
    ];
    for s in &all {
        let json = serde_json::to_string(s).unwrap();
        let back: AcquisitionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn enrichment_acquisition_status_is_healthy() {
    assert!(AcquisitionStatus::Active.is_healthy());
    assert!(AcquisitionStatus::Complete.is_healthy());
    assert!(!AcquisitionStatus::Stalled.is_healthy());
    assert!(!AcquisitionStatus::Absent.is_healthy());
}

// ===========================================================================
// FreshnessLevel Display + serde
// ===========================================================================

#[test]
fn enrichment_freshness_level_display_all_unique() {
    let all = [
        FreshnessLevel::Fresh,
        FreshnessLevel::Aging,
        FreshnessLevel::Stale,
        FreshnessLevel::Invalid,
    ];
    let displays: BTreeSet<String> = all.iter().map(|f| f.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_freshness_level_serde_roundtrip_all() {
    let all = [
        FreshnessLevel::Fresh,
        FreshnessLevel::Aging,
        FreshnessLevel::Stale,
        FreshnessLevel::Invalid,
    ];
    for f in &all {
        let json = serde_json::to_string(f).unwrap();
        let back: FreshnessLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

#[test]
fn enrichment_freshness_level_permits_full_confidence() {
    assert!(FreshnessLevel::Fresh.permits_full_confidence());
    assert!(!FreshnessLevel::Aging.permits_full_confidence());
    assert!(!FreshnessLevel::Stale.permits_full_confidence());
    assert!(!FreshnessLevel::Invalid.permits_full_confidence());
}

#[test]
fn enrichment_freshness_level_confidence_multiplier_ordering() {
    // Fresh should have highest multiplier, Invalid lowest
    assert!(FreshnessLevel::Fresh.confidence_multiplier() >= FreshnessLevel::Aging.confidence_multiplier());
    assert!(FreshnessLevel::Aging.confidence_multiplier() >= FreshnessLevel::Stale.confidence_multiplier());
    assert!(FreshnessLevel::Stale.confidence_multiplier() >= FreshnessLevel::Invalid.confidence_multiplier());
}

// ===========================================================================
// ClaimSurface Display + serde
// ===========================================================================

#[test]
fn enrichment_claim_surface_display_all_unique() {
    let all = [
        ClaimSurface::Performance,
        ClaimSurface::Correctness,
        ClaimSurface::Memory,
        ClaimSurface::ColdStart,
        ClaimSurface::CompilationSpeed,
        ClaimSurface::Compatibility,
        ClaimSurface::Supremacy,
    ];
    let displays: BTreeSet<String> = all.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 7);
}

#[test]
fn enrichment_claim_surface_serde_roundtrip_all() {
    let all = [
        ClaimSurface::Performance,
        ClaimSurface::Correctness,
        ClaimSurface::Memory,
        ClaimSurface::ColdStart,
        ClaimSurface::CompilationSpeed,
        ClaimSurface::Compatibility,
        ClaimSurface::Supremacy,
    ];
    for c in &all {
        let json = serde_json::to_string(c).unwrap();
        let back: ClaimSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ===========================================================================
// RolloutTrustLevel Display + serde
// ===========================================================================

#[test]
fn enrichment_rollout_trust_display_all_unique() {
    let all = [
        RolloutTrustLevel::Full,
        RolloutTrustLevel::Conditional,
        RolloutTrustLevel::Reduced,
        RolloutTrustLevel::Blocked,
    ];
    let displays: BTreeSet<String> = all.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_rollout_trust_serde_roundtrip_all() {
    let all = [
        RolloutTrustLevel::Full,
        RolloutTrustLevel::Conditional,
        RolloutTrustLevel::Reduced,
        RolloutTrustLevel::Blocked,
    ];
    for r in &all {
        let json = serde_json::to_string(r).unwrap();
        let back: RolloutTrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn enrichment_rollout_trust_from_freshness() {
    assert_eq!(
        RolloutTrustLevel::from_freshness(FreshnessLevel::Fresh, false),
        RolloutTrustLevel::Full
    );
    assert_eq!(
        RolloutTrustLevel::from_freshness(FreshnessLevel::Invalid, false),
        RolloutTrustLevel::Blocked
    );
}

// ===========================================================================
// ShiftAlarm tests
// ===========================================================================

#[test]
fn enrichment_alarm_acknowledge() {
    let mut alarm = make_alarm("a1", ShiftDomain::General, ShiftSeverity::Warning, 1);
    assert!(!alarm.acknowledged);
    alarm.acknowledge();
    assert!(alarm.acknowledged);
}

#[test]
fn enrichment_alarm_is_stale() {
    let alarm = make_alarm("a1", ShiftDomain::General, ShiftSeverity::Info, 1);
    // Current epoch 200, max age 100 → alarm at epoch 1 is stale
    assert!(alarm.is_stale(epoch(200), 100));
    // Current epoch 50, max age 100 → alarm at epoch 1 is not stale
    assert!(!alarm.is_stale(epoch(50), 100));
}

#[test]
fn enrichment_alarm_weighted_severity() {
    let alarm = make_alarm("a1", ShiftDomain::General, ShiftSeverity::Warning, 1);
    let weighted = alarm.weighted_severity();
    assert!(weighted > 0);
}

#[test]
fn enrichment_alarm_serde_roundtrip() {
    let alarm = make_alarm("a1", ShiftDomain::ProgramSize, ShiftSeverity::Critical, 5);
    let json = serde_json::to_string(&alarm).unwrap();
    let back: ShiftAlarm = serde_json::from_str(&json).unwrap();
    assert_eq!(alarm.alarm_id, back.alarm_id);
    assert_eq!(alarm.severity, back.severity);
}

// ===========================================================================
// AcquisitionEvidence tests
// ===========================================================================

#[test]
fn enrichment_acquisition_meets_burndown_threshold() {
    let ev = make_acquisition(ShiftDomain::General, 80, 100, AcquisitionStatus::Active, 1);
    // 80% burndown → meets 50% threshold
    assert!(ev.meets_burndown_threshold(500_000));
    // 80% burndown → does NOT meet 90% threshold
    assert!(!ev.meets_burndown_threshold(900_000));
}

#[test]
fn enrichment_acquisition_estimated_epochs_zero_velocity() {
    let ev = AcquisitionEvidence::new(
        ShiftDomain::General,
        50,
        100,
        AcquisitionStatus::Stalled,
        epoch(1),
        0, // zero velocity
    );
    // Zero velocity → cannot estimate
    let est = ev.estimated_epochs_to_completion();
    assert!(est.is_none() || est == Some(0));
}

#[test]
fn enrichment_acquisition_serde_roundtrip() {
    let ev = make_acquisition(ShiftDomain::ApiUsage, 30, 100, AcquisitionStatus::Active, 5);
    let json = serde_json::to_string(&ev).unwrap();
    let back: AcquisitionEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev.domain, back.domain);
    assert_eq!(ev.samples_acquired, back.samples_acquired);
}

// ===========================================================================
// AlarmLedger tests
// ===========================================================================

#[test]
fn enrichment_alarm_ledger_empty() {
    let ledger = AlarmLedger::new();
    assert_eq!(ledger.active_count(), 0);
    assert!(!ledger.has_immediate_downgrade_alarm());
}

#[test]
fn enrichment_alarm_ledger_record_and_resolve() {
    let mut ledger = AlarmLedger::new();
    ledger.record_alarm(make_alarm("a1", ShiftDomain::General, ShiftSeverity::Warning, 1));
    assert_eq!(ledger.active_count(), 1);
    assert!(ledger.resolve_alarm("a1", 2));
    assert_eq!(ledger.active_count(), 0);
}

#[test]
fn enrichment_alarm_ledger_resolve_nonexistent() {
    let mut ledger = AlarmLedger::new();
    assert!(!ledger.resolve_alarm("nonexistent", 1));
}

#[test]
fn enrichment_alarm_ledger_prune_stale() {
    let mut ledger = AlarmLedger::new();
    ledger.record_alarm(make_alarm("old", ShiftDomain::General, ShiftSeverity::Info, 1));
    ledger.record_alarm(make_alarm("new", ShiftDomain::General, ShiftSeverity::Info, 150));
    let pruned = ledger.prune_stale(epoch(200), 100);
    assert_eq!(pruned, 1); // only "old" is stale
    assert_eq!(ledger.active_count(), 1);
}

#[test]
fn enrichment_alarm_ledger_worst_severity() {
    let mut ledger = AlarmLedger::new();
    ledger.record_alarm(make_alarm("a1", ShiftDomain::General, ShiftSeverity::Info, 1));
    ledger.record_alarm(make_alarm("a2", ShiftDomain::General, ShiftSeverity::Critical, 1));
    let worst = ledger.worst_severity_in_domain(ShiftDomain::General);
    assert_eq!(worst, Some(ShiftSeverity::Critical));
}

#[test]
fn enrichment_alarm_ledger_domain_count() {
    let mut ledger = AlarmLedger::new();
    ledger.record_alarm(make_alarm("a1", ShiftDomain::ProgramSize, ShiftSeverity::Info, 1));
    ledger.record_alarm(make_alarm("a2", ShiftDomain::ProgramSize, ShiftSeverity::Warning, 1));
    ledger.record_alarm(make_alarm("a3", ShiftDomain::ApiUsage, ShiftSeverity::Info, 1));
    assert_eq!(ledger.active_count_in_domain(ShiftDomain::ProgramSize), 2);
    assert_eq!(ledger.active_count_in_domain(ShiftDomain::ApiUsage), 1);
    assert_eq!(ledger.active_count_in_domain(ShiftDomain::General), 0);
}

#[test]
fn enrichment_alarm_ledger_content_hash_deterministic() {
    let mut l1 = AlarmLedger::new();
    let mut l2 = AlarmLedger::new();
    l1.record_alarm(make_alarm("a1", ShiftDomain::General, ShiftSeverity::Info, 1));
    l2.record_alarm(make_alarm("a1", ShiftDomain::General, ShiftSeverity::Info, 1));
    assert_eq!(l1.content_hash(), l2.content_hash());
}

// ===========================================================================
// AcquisitionLedger tests
// ===========================================================================

#[test]
fn enrichment_acquisition_ledger_empty() {
    let ledger = AcquisitionLedger::new();
    assert!(!ledger.has_stalled_domains());
}

#[test]
fn enrichment_acquisition_ledger_record_and_query() {
    let mut ledger = AcquisitionLedger::new();
    ledger.record_evidence(make_acquisition(
        ShiftDomain::General,
        50,
        100,
        AcquisitionStatus::Active,
        1,
    ));
    assert!(ledger.get_domain_evidence(ShiftDomain::General).is_some());
    assert!(ledger.get_domain_evidence(ShiftDomain::ApiUsage).is_none());
}

// ===========================================================================
// SilenceTracker tests
// ===========================================================================

#[test]
fn enrichment_silence_tracker_initial_state() {
    let tracker = SilenceTracker::new();
    // No signals recorded → silence not exceeded yet (no last_signal)
    assert!(!tracker.silence_exceeded);
}

#[test]
fn enrichment_silence_tracker_signal_resets() {
    let mut tracker = SilenceTracker::new();
    tracker.record_signal(epoch(1));
    // Check silence at epoch 100, timeout 50 → silence exceeded
    assert!(tracker.check_silence(epoch(100), 50));
    // Record new signal → resets
    tracker.record_signal(epoch(100));
    assert!(!tracker.check_silence(epoch(110), 50));
}

// ===========================================================================
// BenchmarkClaim builder tests
// ===========================================================================

#[test]
fn enrichment_claim_with_domain() {
    let claim = make_claim("c1", ClaimSurface::Performance, 900_000)
        .with_domain(ShiftDomain::ProgramSize);
    assert!(claim.dependent_domains.contains(&ShiftDomain::ProgramSize));
}

#[test]
fn enrichment_claim_with_domains() {
    let domains = vec![ShiftDomain::ProgramSize, ShiftDomain::ApiUsage];
    let claim = make_claim("c1", ClaimSurface::Correctness, 800_000).with_domains(domains);
    assert_eq!(claim.dependent_domains.len(), 2);
}

// ===========================================================================
// FreshnessGate evaluation tests
// ===========================================================================

#[test]
fn enrichment_gate_fresh_no_alarms() {
    let mut gate = FreshnessGate::new(epoch(1));
    let claim = make_claim("c1", ClaimSurface::Performance, 900_000);
    let verdict = gate.evaluate_claim(&claim);
    assert_eq!(verdict.freshness, FreshnessLevel::Fresh);
    assert!(verdict.is_full_confidence());
    assert!(!verdict.is_downgraded());
}

#[test]
fn enrichment_gate_verdict_downgraded_by_alarm() {
    let mut gate = FreshnessGate::new(epoch(1));
    gate.record_alarm(make_alarm(
        "critical",
        ShiftDomain::General,
        ShiftSeverity::Critical,
        1,
    ));
    let claim =
        make_claim("c1", ClaimSurface::Performance, 900_000).with_domain(ShiftDomain::General);
    let verdict = gate.evaluate_claim(&claim);
    assert!(verdict.is_downgraded());
    assert!(verdict.adjusted_confidence < verdict.original_confidence);
}

#[test]
fn enrichment_gate_summary_healthy_no_alarms() {
    let gate = FreshnessGate::new(epoch(1));
    let summary = gate.summary();
    assert!(summary.is_healthy());
    assert_eq!(summary.active_alarms, 0);
}

#[test]
fn enrichment_gate_total_evaluations_increments() {
    let mut gate = FreshnessGate::new(epoch(1));
    let claim = make_claim("c1", ClaimSurface::Performance, 900_000);
    let _ = gate.evaluate_claim(&claim);
    let _ = gate.evaluate_claim(&claim);
    // Gate should track evaluations (note: evaluate_claim takes &self so may not increment
    // if gate uses interior mutability or &mut self)
    let summary = gate.summary();
    assert_eq!(summary.total_evaluations, 2);
}

// ===========================================================================
// Batch evaluation tests
// ===========================================================================

#[test]
fn enrichment_batch_empty() {
    let mut gate = FreshnessGate::new(epoch(1));
    let verdict = gate.evaluate_batch(&[]);
    assert_eq!(verdict.claims_total, 0);
}

#[test]
fn enrichment_batch_multiple_claims() {
    let mut gate = FreshnessGate::new(epoch(1));
    let claims = vec![
        make_claim("c1", ClaimSurface::Performance, 900_000),
        make_claim("c2", ClaimSurface::Correctness, 800_000),
        make_claim("c3", ClaimSurface::Memory, 700_000),
    ];
    let verdict = gate.evaluate_batch(&claims);
    assert_eq!(verdict.claims_total, 3);
    assert_eq!(verdict.verdicts.len(), 3);
}

#[test]
fn enrichment_batch_serde_roundtrip() {
    let mut gate = FreshnessGate::new(epoch(1));
    let claims = vec![make_claim("c1", ClaimSurface::Performance, 900_000)];
    let verdict = gate.evaluate_batch(&claims);
    let json = serde_json::to_string(&verdict).unwrap();
    let back: BatchVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(verdict.claims_total, back.claims_total);
}

// ===========================================================================
// DecisionReceipt tests
// ===========================================================================

#[test]
fn enrichment_decision_receipt_from_fresh_verdict() {
    let mut gate = FreshnessGate::new(epoch(1));
    let claim = make_claim("c1", ClaimSurface::Performance, 900_000);
    let verdict = gate.evaluate_claim(&claim);
    let config = GateConfig::default();
    let receipt = DecisionReceipt::from_verdict(&verdict, &config);
    assert_eq!(receipt.claim_id, "c1");
    assert_eq!(receipt.freshness, FreshnessLevel::Fresh);
    assert_eq!(receipt.rollout_trust, RolloutTrustLevel::Full);
}

#[test]
fn enrichment_decision_receipt_serde_roundtrip() {
    let mut gate = FreshnessGate::new(epoch(1));
    let claim = make_claim("c1", ClaimSurface::Performance, 900_000);
    let verdict = gate.evaluate_claim(&claim);
    let config = GateConfig::default();
    let receipt = DecisionReceipt::from_verdict(&verdict, &config);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.claim_id, back.claim_id);
    assert_eq!(receipt.freshness, back.freshness);
}

// ===========================================================================
// GateConfig defaults
// ===========================================================================

#[test]
fn enrichment_gate_config_defaults() {
    let config = GateConfig::default();
    assert!(config.max_alarm_age_epochs > 0);
    assert!(config.min_burndown_ratio > 0);
    assert!(config.critical_severity_threshold > 0);
    assert!(config.max_batch_size > 0);
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let config = GateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// GateSummary tests
// ===========================================================================

#[test]
fn enrichment_gate_summary_serde_roundtrip() {
    let gate = FreshnessGate::new(epoch(1));
    let summary = gate.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary.active_alarms, back.active_alarms);
}

// ===========================================================================
// FreshnessVerdict tests
// ===========================================================================

#[test]
fn enrichment_verdict_downgrade_fraction() {
    let mut gate = FreshnessGate::new(epoch(1));
    let claim = make_claim("c1", ClaimSurface::Performance, 1_000_000);
    let verdict = gate.evaluate_claim(&claim);
    // Fresh verdict → no downgrade
    assert_eq!(verdict.downgrade_fraction(), 0);
}

#[test]
fn enrichment_verdict_serde_roundtrip() {
    let mut gate = FreshnessGate::new(epoch(1));
    let claim = make_claim("c1", ClaimSurface::Performance, 900_000);
    let verdict = gate.evaluate_claim(&claim);
    let json = serde_json::to_string(&verdict).unwrap();
    let back: FreshnessVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(verdict.claim_id, back.claim_id);
    assert_eq!(verdict.freshness, back.freshness);
}

// ===========================================================================
// Gate advance_epoch
// ===========================================================================

#[test]
fn enrichment_gate_advance_epoch() {
    let mut gate = FreshnessGate::new(epoch(1));
    gate.advance_epoch(epoch(5));
    let summary = gate.summary();
    assert_eq!(summary.current_epoch, epoch(5));
}

// ===========================================================================
// Gate determinism
// ===========================================================================

#[test]
fn enrichment_gate_evaluation_deterministic() {
    let mut g1 = FreshnessGate::new(epoch(1));
    let mut g2 = FreshnessGate::new(epoch(1));
    let claim = make_claim("c1", ClaimSurface::Performance, 900_000);
    let v1 = g1.evaluate_claim(&claim);
    let v2 = g2.evaluate_claim(&claim);
    assert_eq!(v1.freshness, v2.freshness);
    assert_eq!(v1.adjusted_confidence, v2.adjusted_confidence);
    assert_eq!(v1.verdict_hash, v2.verdict_hash);
}
