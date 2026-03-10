//! Integration tests for benchmark freshness gate — shift alarms, acquisition
//! evidence, freshness verdicts, batch evaluation, silence detection, alarm
//! lifecycle, decision receipts, and serde roundtrips (RGC-706C).

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
    BenchmarkClaim, COMPONENT, ClaimSurface, DecisionReceipt, FIXED_ONE, FreshnessGate,
    FreshnessLevel, FreshnessVerdict, GateConfig, GateSummary, POLICY_ID, RolloutTrustLevel,
    SCHEMA_VERSION, ShiftAlarm, ShiftDomain, ShiftSeverity, SilenceTracker,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_alarm(id: &str, domain: ShiftDomain, severity: ShiftSeverity, ep: u64) -> ShiftAlarm {
    ShiftAlarm::new(id, domain, severity, epoch(ep), 500_000, "test alarm")
}

fn make_claim(id: &str, surface: ClaimSurface, domains: &[ShiftDomain]) -> BenchmarkClaim {
    let mut claim = BenchmarkClaim::new(id, surface, 900_000, epoch(1), "test claim");
    for d in domains {
        claim.dependent_domains.insert(*d);
    }
    claim
}

fn make_acquisition(
    domain: ShiftDomain,
    acquired: u64,
    needed: u64,
    status: AcquisitionStatus,
) -> AcquisitionEvidence {
    AcquisitionEvidence::new(domain, acquired, needed, status, epoch(10), 100_000)
}

fn make_gate_with_signal(ep: u64) -> FreshnessGate {
    let mut gate = FreshnessGate::new(epoch(ep));
    gate.silence_tracker.record_signal(epoch(ep));
    gate
}

// ---------------------------------------------------------------------------
// 1. Constants and schema
// ---------------------------------------------------------------------------

#[test]
fn test_constants_are_well_formed() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!POLICY_ID.is_empty());
    assert_eq!(FIXED_ONE, 1_000_000);
}

// ---------------------------------------------------------------------------
// 2. ShiftAlarm lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_alarm_creation_acknowledge_and_evidence_hash() {
    let mut alarm = make_alarm("alarm-1", ShiftDomain::ApiUsage, ShiftSeverity::Warning, 5);
    assert_eq!(alarm.alarm_id, "alarm-1");
    assert!(!alarm.acknowledged);
    alarm.acknowledge();
    assert!(alarm.acknowledged);

    // Deterministic hash
    let other = make_alarm("alarm-1", ShiftDomain::ApiUsage, ShiftSeverity::Warning, 5);
    assert_eq!(alarm.evidence_hash, other.evidence_hash);

    // Different id => different hash
    let diff = make_alarm("alarm-2", ShiftDomain::ApiUsage, ShiftSeverity::Warning, 5);
    assert_ne!(alarm.evidence_hash, diff.evidence_hash);
}

#[test]
fn test_alarm_weighted_severity_and_staleness() {
    // drift_magnitude = 500_000 (50%), warning weight = 400_000
    // weighted = 400_000 * 500_000 / 1_000_000 = 200_000
    let alarm = make_alarm("a1", ShiftDomain::General, ShiftSeverity::Warning, 10);
    assert_eq!(alarm.weighted_severity(), 200_000);

    // Staleness boundary: age 100, max_age 100 => not stale; age 101 => stale
    assert!(!alarm.is_stale(epoch(110), 100));
    assert!(alarm.is_stale(epoch(111), 100));
}

// ---------------------------------------------------------------------------
// 3. AcquisitionEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_acquisition_burndown_and_completion_estimate() {
    let ev = make_acquisition(ShiftDomain::General, 30, 100, AcquisitionStatus::Active);
    assert_eq!(ev.burndown_ratio, 300_000);
    assert!(ev.meets_burndown_threshold(300_000));
    assert!(!ev.meets_burndown_threshold(400_000));
    // remaining=70, velocity=100_000 => 70*1M/100_000 = 700
    assert_eq!(ev.estimated_epochs_to_completion(), Some(700));
}

#[test]
fn test_acquisition_zero_needed_and_zero_velocity() {
    let full = make_acquisition(ShiftDomain::General, 0, 0, AcquisitionStatus::Complete);
    assert_eq!(full.burndown_ratio, FIXED_ONE);

    let stalled = AcquisitionEvidence::new(
        ShiftDomain::General,
        10,
        100,
        AcquisitionStatus::Stalled,
        epoch(5),
        0,
    );
    assert_eq!(stalled.estimated_epochs_to_completion(), None);
}

// ---------------------------------------------------------------------------
// 4. AlarmLedger
// ---------------------------------------------------------------------------

#[test]
fn test_alarm_ledger_record_resolve_and_prune() {
    let mut ledger = AlarmLedger::new();
    assert_eq!(ledger.active_count(), 0);

    ledger.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Warning,
        1,
    ));
    ledger.record_alarm(make_alarm(
        "a2",
        ShiftDomain::ApiUsage,
        ShiftSeverity::Info,
        50,
    ));
    assert_eq!(ledger.active_count(), 2);
    assert_eq!(ledger.total_alarms_recorded, 2);
    assert!(ledger.cumulative_severity > 0);

    // Resolve one
    assert!(ledger.resolve_alarm("a1", 60));
    assert_eq!(ledger.active_count(), 1);
    assert!(!ledger.resolve_alarm("a1", 61)); // already resolved

    // Prune stale: a2 raised at 50, current 200, max_age 100 => 200-50=150>100 => pruned
    let pruned = ledger.prune_stale(epoch(200), 100);
    assert_eq!(pruned, 1);
    assert_eq!(ledger.active_count(), 0);
}

#[test]
fn test_alarm_ledger_domain_queries_and_immediate_downgrade() {
    let mut ledger = AlarmLedger::new();
    ledger.record_alarm(make_alarm(
        "a1",
        ShiftDomain::ApiUsage,
        ShiftSeverity::Info,
        1,
    ));
    ledger.record_alarm(make_alarm(
        "a2",
        ShiftDomain::ApiUsage,
        ShiftSeverity::Critical,
        2,
    ));
    ledger.record_alarm(make_alarm(
        "a3",
        ShiftDomain::ControlFlow,
        ShiftSeverity::Warning,
        3,
    ));

    assert_eq!(ledger.active_count_in_domain(ShiftDomain::ApiUsage), 2);
    assert_eq!(ledger.active_count_in_domain(ShiftDomain::IoPattern), 0);
    assert_eq!(
        ledger.worst_severity_in_domain(ShiftDomain::ApiUsage),
        Some(ShiftSeverity::Critical)
    );
    assert!(ledger.has_immediate_downgrade_alarm());
}

#[test]
fn test_alarm_ledger_content_hash_determinism() {
    let build = || {
        let mut l = AlarmLedger::new();
        l.record_alarm(make_alarm(
            "x",
            ShiftDomain::General,
            ShiftSeverity::Info,
            1,
        ));
        l.content_hash()
    };
    assert_eq!(build(), build());
}

// ---------------------------------------------------------------------------
// 5. AcquisitionLedger
// ---------------------------------------------------------------------------

#[test]
fn test_acquisition_ledger_record_replace_and_average() {
    let mut ledger = AcquisitionLedger::new();
    assert_eq!(ledger.overall_burndown_ratio, FIXED_ONE);

    ledger.record_evidence(make_acquisition(
        ShiftDomain::General,
        10,
        100,
        AcquisitionStatus::Active,
    ));
    assert_eq!(ledger.overall_burndown_ratio, 100_000);

    // Replace same domain
    ledger.record_evidence(make_acquisition(
        ShiftDomain::General,
        80,
        100,
        AcquisitionStatus::Active,
    ));
    assert_eq!(ledger.evidence.len(), 1);
    assert_eq!(ledger.overall_burndown_ratio, 800_000);

    // Add second domain => average
    ledger.record_evidence(make_acquisition(
        ShiftDomain::ApiUsage,
        0,
        100,
        AcquisitionStatus::Active,
    ));
    assert_eq!(ledger.overall_burndown_ratio, 400_000); // (800_000+0)/2
}

#[test]
fn test_acquisition_ledger_stalled_and_healthy() {
    let mut ledger = AcquisitionLedger::new();
    let mut required = BTreeSet::new();
    required.insert(ShiftDomain::General);

    assert!(!ledger.all_domains_healthy(&required));

    ledger.record_evidence(make_acquisition(
        ShiftDomain::General,
        10,
        100,
        AcquisitionStatus::Stalled,
    ));
    assert!(ledger.has_stalled_domains());
    assert!(!ledger.all_domains_healthy(&required));

    ledger.record_evidence(make_acquisition(
        ShiftDomain::General,
        50,
        100,
        AcquisitionStatus::Active,
    ));
    assert!(!ledger.has_stalled_domains());
    assert!(ledger.all_domains_healthy(&required));
}

// ---------------------------------------------------------------------------
// 6. SilenceTracker
// ---------------------------------------------------------------------------

#[test]
fn test_silence_tracker_lifecycle() {
    let mut tracker = SilenceTracker::new();
    assert!(tracker.last_signal_epoch.is_none());

    // No signal ever => exceeded after timeout
    assert!(tracker.check_silence(epoch(100), 50));
    assert!(tracker.silence_exceeded);

    // Signal resets
    tracker.record_signal(epoch(100));
    assert!(!tracker.silence_exceeded);
    assert_eq!(tracker.silent_epochs, 0);

    // Within timeout
    assert!(!tracker.check_silence(epoch(130), 50));
    // Exactly at boundary (150-100=50, not > 50)
    assert!(!tracker.check_silence(epoch(150), 50));
    // Past boundary
    assert!(tracker.check_silence(epoch(151), 50));
}

// ---------------------------------------------------------------------------
// 7. FreshnessLevel and RolloutTrustLevel
// ---------------------------------------------------------------------------

#[test]
fn test_freshness_level_ordering_and_multipliers() {
    assert!(FreshnessLevel::Fresh < FreshnessLevel::Aging);
    assert!(FreshnessLevel::Aging < FreshnessLevel::Stale);
    assert!(FreshnessLevel::Stale < FreshnessLevel::Invalid);

    assert_eq!(FreshnessLevel::Fresh.confidence_multiplier(), FIXED_ONE);
    assert_eq!(FreshnessLevel::Invalid.confidence_multiplier(), 0);
    assert!(FreshnessLevel::Fresh.permits_full_confidence());
    assert!(!FreshnessLevel::Aging.permits_full_confidence());
}

#[test]
fn test_rollout_trust_mapping() {
    assert_eq!(
        RolloutTrustLevel::from_freshness(FreshnessLevel::Fresh, true),
        RolloutTrustLevel::Full
    );
    assert_eq!(
        RolloutTrustLevel::from_freshness(FreshnessLevel::Aging, true),
        RolloutTrustLevel::Conditional
    );
    assert_eq!(
        RolloutTrustLevel::from_freshness(FreshnessLevel::Aging, false),
        RolloutTrustLevel::Reduced
    );
    assert_eq!(
        RolloutTrustLevel::from_freshness(FreshnessLevel::Stale, true),
        RolloutTrustLevel::Reduced
    );
    assert_eq!(
        RolloutTrustLevel::from_freshness(FreshnessLevel::Invalid, true),
        RolloutTrustLevel::Blocked
    );
}

// ---------------------------------------------------------------------------
// 8. FreshnessGate — core evaluation workflows
// ---------------------------------------------------------------------------

#[test]
fn test_gate_fresh_when_no_alarms() {
    let mut gate = make_gate_with_signal(10);
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
    let verdict = gate.evaluate_claim(&claim);
    assert_eq!(verdict.freshness, FreshnessLevel::Fresh);
    assert_eq!(verdict.adjusted_confidence, 900_000);
    assert!(verdict.rollout_permitted);
    assert!(verdict.is_full_confidence());
    assert!(!verdict.is_downgraded());
    assert_eq!(verdict.downgrade_fraction(), 0);
}

#[test]
fn test_gate_info_alarm_gives_aging() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::ApiUsage,
        ShiftSeverity::Info,
        9,
    ));
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::ApiUsage]);
    let verdict = gate.evaluate_claim(&claim);
    assert_eq!(verdict.freshness, FreshnessLevel::Aging);
    assert_eq!(verdict.adjusted_confidence, 675_000); // 900k * 750k / 1M
    assert!(verdict.is_downgraded());
    assert_eq!(verdict.downgrade_fraction(), 250_000);
}

#[test]
fn test_gate_warning_without_acquisition_gives_stale() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Warning,
        9,
    ));
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
    let verdict = gate.evaluate_claim(&claim);
    assert_eq!(verdict.freshness, FreshnessLevel::Stale);
    assert_eq!(verdict.adjusted_confidence, 360_000); // 900k * 400k / 1M
}

#[test]
fn test_gate_warning_with_healthy_acquisition_gives_aging() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Warning,
        9,
    ));
    gate.record_acquisition(make_acquisition(
        ShiftDomain::General,
        60,
        100,
        AcquisitionStatus::Active,
    ));
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
    let verdict = gate.evaluate_claim(&claim);
    assert_eq!(verdict.freshness, FreshnessLevel::Aging);
}

#[test]
fn test_gate_critical_with_good_acquisition_gives_aging() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Critical,
        9,
    ));
    gate.record_acquisition(make_acquisition(
        ShiftDomain::General,
        60,
        100,
        AcquisitionStatus::Active,
    ));
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
    let verdict = gate.evaluate_claim(&claim);
    assert_eq!(verdict.freshness, FreshnessLevel::Aging);
}

#[test]
fn test_gate_critical_without_acquisition_gives_invalid() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Critical,
        9,
    ));
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
    let verdict = gate.evaluate_claim(&claim);
    assert_eq!(verdict.freshness, FreshnessLevel::Invalid);
    assert_eq!(verdict.adjusted_confidence, 0);
    assert!(!verdict.rollout_permitted);
}

#[test]
fn test_gate_emergency_alarm_always_invalid() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Emergency,
        9,
    ));
    let claim = make_claim("c1", ClaimSurface::Supremacy, &[ShiftDomain::General]);
    let verdict = gate.evaluate_claim(&claim);
    assert_eq!(verdict.freshness, FreshnessLevel::Invalid);
    assert!(!verdict.rollout_permitted);
}

// ---------------------------------------------------------------------------
// 9. Multi-domain scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_multi_domain_worst_freshness_wins() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::ApiUsage,
        ShiftSeverity::Info,
        9,
    ));
    let claim = make_claim(
        "c1",
        ClaimSurface::Performance,
        &[ShiftDomain::ApiUsage, ShiftDomain::General],
    );
    let verdict = gate.evaluate_claim(&claim);
    assert_eq!(verdict.freshness, FreshnessLevel::Aging);
    assert_eq!(
        verdict.domain_freshness.get("api_usage"),
        Some(&FreshnessLevel::Aging)
    );
    assert_eq!(
        verdict.domain_freshness.get("general"),
        Some(&FreshnessLevel::Fresh)
    );
}

#[test]
fn test_multi_domain_mixed_severities() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::ApiUsage,
        ShiftSeverity::Info,
        9,
    ));
    gate.record_alarm(make_alarm(
        "a2",
        ShiftDomain::ControlFlow,
        ShiftSeverity::Warning,
        9,
    ));
    let claim = make_claim(
        "c1",
        ClaimSurface::Performance,
        &[ShiftDomain::ApiUsage, ShiftDomain::ControlFlow],
    );
    let verdict = gate.evaluate_claim(&claim);
    // Warning without acquisition => Stale is worse than Aging
    assert_eq!(verdict.freshness, FreshnessLevel::Stale);
}

// ---------------------------------------------------------------------------
// 10. Silence detection
// ---------------------------------------------------------------------------

#[test]
fn test_silence_degrades_freshness() {
    let mut gate = FreshnessGate::new(epoch(100));
    gate.silence_tracker
        .check_silence(epoch(100), gate.config.silence_timeout_epochs);
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
    let verdict = gate.evaluate_claim(&claim);
    assert_eq!(verdict.freshness, FreshnessLevel::Stale);
    assert!(verdict.reasons.iter().any(|r| r.contains("Silence")));
}

#[test]
fn test_silence_reset_by_alarm_and_acquisition() {
    let mut gate = FreshnessGate::new(epoch(100));
    gate.silence_tracker.check_silence(epoch(100), 50);
    assert!(gate.silence_tracker.silence_exceeded);

    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Info,
        100,
    ));
    assert!(!gate.silence_tracker.silence_exceeded);

    // Re-trigger silence
    gate.silence_tracker.check_silence(epoch(200), 50);
    assert!(gate.silence_tracker.silence_exceeded);

    gate.record_acquisition(make_acquisition(
        ShiftDomain::General,
        50,
        100,
        AcquisitionStatus::Active,
    ));
    assert!(!gate.silence_tracker.silence_exceeded);
}

// ---------------------------------------------------------------------------
// 11. Alarm lifecycle — resolve and epoch advance
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_alarm_restores_freshness() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Warning,
        9,
    ));
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);

    assert_eq!(gate.evaluate_claim(&claim).freshness, FreshnessLevel::Stale);
    assert!(gate.resolve_alarm("a1"));
    assert_eq!(gate.evaluate_claim(&claim).freshness, FreshnessLevel::Fresh);
    assert!(!gate.resolve_alarm("nonexistent"));
}

#[test]
fn test_advance_epoch_prunes_stale_alarms() {
    let mut gate = FreshnessGate::new(epoch(1));
    gate.record_alarm(make_alarm(
        "old",
        ShiftDomain::General,
        ShiftSeverity::Info,
        1,
    ));
    gate.advance_epoch(epoch(200));
    assert_eq!(gate.current_epoch, epoch(200));
    assert_eq!(gate.alarm_ledger.active_count(), 0);
}

#[test]
fn test_cumulative_severity_decreases_on_resolve() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Warning,
        9,
    ));
    assert!(gate.alarm_ledger.cumulative_severity > 0);
    gate.resolve_alarm("a1");
    assert_eq!(gate.alarm_ledger.cumulative_severity, 0);
}

// ---------------------------------------------------------------------------
// 12. Batch evaluation
// ---------------------------------------------------------------------------

#[test]
fn test_batch_evaluation_mixed_claims() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::ApiUsage,
        ShiftSeverity::Warning,
        9,
    ));

    let claims = vec![
        make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]),
        make_claim("c2", ClaimSurface::Memory, &[ShiftDomain::ApiUsage]),
    ];
    let batch = gate.evaluate_batch(&claims);
    assert_eq!(batch.claims_total, 2);
    assert_eq!(batch.claims_full_confidence, 1);
    assert_eq!(batch.claims_downgraded, 1);
    assert!(batch.verdicts.contains_key("c1"));
    assert!(batch.verdicts.contains_key("c2"));
}

#[test]
fn test_batch_respects_max_size() {
    let mut gate = make_gate_with_signal(1);
    gate.config.max_batch_size = 3;
    let claims: Vec<BenchmarkClaim> = (0..10)
        .map(|i| make_claim(&format!("c{}", i), ClaimSurface::Performance, &[]))
        .collect();
    let batch = gate.evaluate_batch(&claims);
    assert_eq!(batch.claims_total, 3);
}

#[test]
fn test_batch_overall_freshness_is_worst() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::ApiUsage,
        ShiftSeverity::Emergency,
        9,
    ));
    let claims = vec![
        make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]),
        make_claim("c2", ClaimSurface::Memory, &[ShiftDomain::ApiUsage]),
    ];
    let batch = gate.evaluate_batch(&claims);
    assert_eq!(batch.overall_freshness, FreshnessLevel::Invalid);
    assert_eq!(batch.rollout_trust, RolloutTrustLevel::Blocked);
}

#[test]
fn test_batch_empty_claims() {
    let mut gate = make_gate_with_signal(10);
    let batch = gate.evaluate_batch(&[]);
    assert_eq!(batch.claims_total, 0);
    assert_eq!(batch.overall_freshness, FreshnessLevel::Fresh);
}

// ---------------------------------------------------------------------------
// 13. Acquisition progression
// ---------------------------------------------------------------------------

#[test]
fn test_acquisition_progression_through_stages() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Critical,
        9,
    ));
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);

    // No acquisition => Invalid
    assert_eq!(
        gate.evaluate_claim(&claim).freshness,
        FreshnessLevel::Invalid
    );

    // Low burndown (20%) < min 50% => still Invalid via immediate downgrade check
    gate.record_acquisition(make_acquisition(
        ShiftDomain::General,
        20,
        100,
        AcquisitionStatus::Active,
    ));
    assert_eq!(
        gate.evaluate_claim(&claim).freshness,
        FreshnessLevel::Invalid
    );

    // Good burndown (60%) >= 50% => Aging
    gate.record_acquisition(make_acquisition(
        ShiftDomain::General,
        60,
        100,
        AcquisitionStatus::Active,
    ));
    assert_eq!(gate.evaluate_claim(&claim).freshness, FreshnessLevel::Aging);
}

// ---------------------------------------------------------------------------
// 14. Decision receipts
// ---------------------------------------------------------------------------

#[test]
fn test_decision_receipt_fresh_verdict() {
    let mut gate = make_gate_with_signal(10);
    let claim = make_claim("c1", ClaimSurface::Performance, &[]);
    let verdict = gate.evaluate_claim(&claim);
    let receipt = DecisionReceipt::from_verdict(&verdict, &gate.config);

    assert_eq!(receipt.claim_id, "c1");
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.policy_id, POLICY_ID);
    assert_eq!(receipt.freshness, FreshnessLevel::Fresh);
    assert_eq!(receipt.rollout_trust, RolloutTrustLevel::Full);
    assert_eq!(receipt.alarm_count, 0);
    assert_eq!(receipt.epoch, epoch(10));
    assert!(receipt.receipt_id.contains("c1"));
}

#[test]
fn test_decision_receipt_downgraded_verdict() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Warning,
        9,
    ));
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
    let verdict = gate.evaluate_claim(&claim);
    let receipt = DecisionReceipt::from_verdict(&verdict, &gate.config);

    assert_eq!(receipt.freshness, FreshnessLevel::Stale);
    assert_eq!(receipt.rollout_trust, RolloutTrustLevel::Reduced);
    assert_eq!(receipt.alarm_count, 1);
}

// ---------------------------------------------------------------------------
// 15. GateSummary
// ---------------------------------------------------------------------------

#[test]
fn test_gate_summary_healthy_and_unhealthy() {
    let mut gate = make_gate_with_signal(1);
    let healthy = gate.summary();
    assert!(healthy.is_healthy());
    assert_eq!(healthy.active_alarms, 0);

    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Warning,
        1,
    ));
    let claim = make_claim("c1", ClaimSurface::Performance, &[]);
    gate.evaluate_claim(&claim);

    let unhealthy = gate.summary();
    assert!(!unhealthy.is_healthy());
    assert_eq!(unhealthy.active_alarms, 1);
    assert!(unhealthy.cumulative_severity > 0);
    assert_eq!(unhealthy.total_evaluations, 1);
}

// ---------------------------------------------------------------------------
// 16. Config: required active domains
// ---------------------------------------------------------------------------

#[test]
fn test_required_active_domains_degrade_and_satisfy() {
    let mut config = GateConfig::default();
    config.required_active_domains.insert(ShiftDomain::ApiUsage);
    let mut gate = FreshnessGate::with_config(config, epoch(10));
    gate.silence_tracker.record_signal(epoch(10));

    let claim = make_claim("c1", ClaimSurface::Performance, &[]);

    // Required domain not covered => at least Aging
    assert!(gate.evaluate_claim(&claim).freshness >= FreshnessLevel::Aging);

    // Satisfy the requirement
    gate.record_acquisition(make_acquisition(
        ShiftDomain::ApiUsage,
        80,
        100,
        AcquisitionStatus::Active,
    ));
    assert_eq!(gate.evaluate_claim(&claim).freshness, FreshnessLevel::Fresh);
}

// ---------------------------------------------------------------------------
// 17. Config: permit rollout when aging
// ---------------------------------------------------------------------------

#[test]
fn test_permit_rollout_when_aging_flag() {
    // permit=true => rollout allowed during Aging
    let mut gate = make_gate_with_signal(10);
    gate.config.permit_rollout_when_aging = true;
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Info,
        9,
    ));
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
    assert!(gate.evaluate_claim(&claim).rollout_permitted);

    // permit=false => rollout denied during Aging
    let mut config = GateConfig::default();
    config.permit_rollout_when_aging = false;
    let mut gate2 = FreshnessGate::with_config(config, epoch(10));
    gate2.silence_tracker.record_signal(epoch(10));
    gate2.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Info,
        9,
    ));
    assert!(!gate2.evaluate_claim(&claim).rollout_permitted);
}

// ---------------------------------------------------------------------------
// 18. Cumulative severity threshold
// ---------------------------------------------------------------------------

#[test]
fn test_cumulative_severity_threshold_triggers_stale() {
    let mut gate = make_gate_with_signal(10);
    // Each warning alarm with drift 500_000 => weighted_severity 200_000
    // DEFAULT_MAX_CUMULATIVE_SEVERITY = 1_500_000 => need >7.5 (8 alarms)
    for i in 0..8 {
        gate.record_alarm(make_alarm(
            &format!("a{}", i),
            ShiftDomain::General,
            ShiftSeverity::Warning,
            9,
        ));
    }
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
    assert_eq!(gate.evaluate_claim(&claim).freshness, FreshnessLevel::Stale);
}

// ---------------------------------------------------------------------------
// 19. Contributing alarms
// ---------------------------------------------------------------------------

#[test]
fn test_contributing_alarms_only_relevant_domains() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::ApiUsage,
        ShiftSeverity::Info,
        9,
    ));
    gate.record_alarm(make_alarm(
        "a2",
        ShiftDomain::General,
        ShiftSeverity::Info,
        9,
    ));
    gate.record_alarm(make_alarm(
        "a3",
        ShiftDomain::ControlFlow,
        ShiftSeverity::Info,
        9,
    ));

    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::ApiUsage]);
    let verdict = gate.evaluate_claim(&claim);
    assert_eq!(verdict.contributing_alarms.len(), 1);
    assert!(verdict.contributing_alarms.contains(&"a1".to_string()));
}

// ---------------------------------------------------------------------------
// 20. Total evaluations counter
// ---------------------------------------------------------------------------

#[test]
fn test_total_evaluations_across_single_and_batch() {
    let mut gate = make_gate_with_signal(1);
    let claim = make_claim("c1", ClaimSurface::Performance, &[]);
    gate.evaluate_claim(&claim);
    gate.evaluate_claim(&claim);
    assert_eq!(gate.total_evaluations, 2);

    gate.evaluate_batch(&[claim.clone(), claim]);
    assert_eq!(gate.total_evaluations, 4);
}

// ---------------------------------------------------------------------------
// 21. Custom config: smaller silence timeout
// ---------------------------------------------------------------------------

#[test]
fn test_custom_silence_timeout() {
    let mut config = GateConfig::default();
    config.silence_timeout_epochs = 5;
    let mut gate = FreshnessGate::with_config(config, epoch(10));
    gate.silence_tracker.record_signal(epoch(3));
    gate.silence_tracker
        .check_silence(epoch(10), gate.config.silence_timeout_epochs);

    let claim = make_claim("c1", ClaimSurface::Performance, &[]);
    // 10 - 3 = 7 > 5 => silence exceeded => Stale
    assert_eq!(gate.evaluate_claim(&claim).freshness, FreshnessLevel::Stale);
}

// ---------------------------------------------------------------------------
// 22. Serde roundtrips — core types
// ---------------------------------------------------------------------------

#[test]
fn test_serde_alarm_and_acquisition_roundtrip() {
    let alarm = make_alarm("a1", ShiftDomain::Concurrency, ShiftSeverity::Emergency, 42);
    let json = serde_json::to_string(&alarm).unwrap();
    let back: ShiftAlarm = serde_json::from_str(&json).unwrap();
    assert_eq!(alarm, back);

    let ev = make_acquisition(ShiftDomain::IoPattern, 75, 200, AcquisitionStatus::Active);
    let json = serde_json::to_string(&ev).unwrap();
    let back: AcquisitionEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);

    let mut config = GateConfig::default();
    config.required_active_domains.insert(ShiftDomain::ApiUsage);
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn test_serde_verdict_and_receipt_roundtrip() {
    let mut gate = make_gate_with_signal(10);
    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Info,
        9,
    ));
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
    let verdict = gate.evaluate_claim(&claim);
    let json = serde_json::to_string(&verdict).unwrap();
    let back: FreshnessVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(verdict, back);

    let receipt = DecisionReceipt::from_verdict(&verdict, &gate.config);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn test_serde_batch_and_summary_roundtrip() {
    let mut gate = make_gate_with_signal(10);
    let claims = vec![
        make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]),
        make_claim("c2", ClaimSurface::Memory, &[ShiftDomain::ApiUsage]),
    ];
    let batch = gate.evaluate_batch(&claims);
    let json = serde_json::to_string(&batch).unwrap();
    let back: BatchVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(batch.claims_total, back.claims_total);
    assert_eq!(batch.overall_freshness, back.overall_freshness);

    let summary = gate.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// 25. Claim builder, domain and surface coverage
// ---------------------------------------------------------------------------

#[test]
fn test_claim_builder_and_all_surfaces_evaluate() {
    let claim = BenchmarkClaim::new("c1", ClaimSurface::Memory, 800_000, epoch(5), "desc")
        .with_domain(ShiftDomain::MemoryAllocation)
        .with_domains([ShiftDomain::Concurrency, ShiftDomain::General]);
    assert_eq!(claim.dependent_domains.len(), 3);
    assert!(
        claim
            .dependent_domains
            .contains(&ShiftDomain::MemoryAllocation)
    );

    // All surfaces evaluate successfully
    let surfaces = [
        ClaimSurface::Performance,
        ClaimSurface::Correctness,
        ClaimSurface::Memory,
        ClaimSurface::ColdStart,
        ClaimSurface::CompilationSpeed,
        ClaimSurface::Compatibility,
        ClaimSurface::Supremacy,
    ];
    let mut gate = make_gate_with_signal(10);
    for (i, surface) in surfaces.iter().enumerate() {
        let c = make_claim(&format!("s{}", i), *surface, &[]);
        assert_eq!(gate.evaluate_claim(&c).freshness, FreshnessLevel::Fresh);
    }
}

#[test]
fn test_all_shift_domains_distinct_display() {
    let domains = [
        ShiftDomain::ProgramSize,
        ShiftDomain::ApiUsage,
        ShiftDomain::ControlFlow,
        ShiftDomain::ModuleTopology,
        ShiftDomain::Concurrency,
        ShiftDomain::MemoryAllocation,
        ShiftDomain::IoPattern,
        ShiftDomain::General,
    ];
    let mut seen = BTreeSet::new();
    for d in &domains {
        assert!(seen.insert(d.to_string()));
    }
}

// ---------------------------------------------------------------------------
// 26. Domain freshness method and gate state serde
// ---------------------------------------------------------------------------

#[test]
fn test_domain_freshness_and_gate_serde() {
    let mut gate = make_gate_with_signal(10);
    assert_eq!(
        gate.domain_freshness(ShiftDomain::General),
        FreshnessLevel::Fresh
    );

    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::ApiUsage,
        ShiftSeverity::Emergency,
        9,
    ));
    assert_eq!(
        gate.domain_freshness(ShiftDomain::ApiUsage),
        FreshnessLevel::Invalid
    );
    assert_eq!(
        gate.domain_freshness(ShiftDomain::General),
        FreshnessLevel::Fresh
    );

    gate.record_acquisition(make_acquisition(
        ShiftDomain::General,
        30,
        100,
        AcquisitionStatus::Active,
    ));
    let json = serde_json::to_string(&gate).unwrap();
    let back: FreshnessGate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.alarm_ledger.active_count(), 1);
    assert_eq!(back.acquisition_ledger.evidence.len(), 1);
    assert_eq!(back.current_epoch, epoch(10));
}

// ---------------------------------------------------------------------------
// 27. Verdict reasons and acquisition status
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_reasons_and_acquisition_status_health() {
    // Acquisition status
    assert!(AcquisitionStatus::Active.is_healthy());
    assert!(AcquisitionStatus::Complete.is_healthy());
    assert!(!AcquisitionStatus::Paused.is_healthy());
    assert!(!AcquisitionStatus::Stalled.is_healthy());
    assert!(!AcquisitionStatus::Absent.is_healthy());

    // Verdict reasons
    let mut gate = make_gate_with_signal(10);
    let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
    let fresh_verdict = gate.evaluate_claim(&claim);
    assert!(fresh_verdict.reasons.iter().any(|r| r.contains("fresh")));

    gate.record_alarm(make_alarm(
        "a1",
        ShiftDomain::General,
        ShiftSeverity::Warning,
        9,
    ));
    gate.record_acquisition(make_acquisition(
        ShiftDomain::General,
        10,
        100,
        AcquisitionStatus::Stalled,
    ));
    let stale_verdict = gate.evaluate_claim(&claim);
    assert!(stale_verdict.reasons.iter().any(|r| r.contains("stalled")));
}
