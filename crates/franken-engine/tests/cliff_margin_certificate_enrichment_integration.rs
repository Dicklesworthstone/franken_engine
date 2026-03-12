//! Enrichment integration tests for the cliff_margin_certificate module.
//!
//! Covers gaps not addressed in cliff_margin_certificate_integration.rs:
//! enum Display/serde coverage, MetricClaim edge cases, CliffProximity
//! predicates, EscapeAction stable_key formats, EscapePlan executability
//! boundaries, Certificate headroom, GateConfig effective margins, evaluation
//! edge cases, GateSummary arithmetic, and Manifest fields.
//!
//! Bead: bd-1lsy.7.19.3
//! Policy: RGC-619C

#![forbid(unsafe_code)]
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

use frankenengine_engine::catastrophe_witness_generator::{BoundaryKind, PhaseRegion};
use frankenengine_engine::cliff_margin_certificate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_proximity(
    distance: i64,
    kind: BoundaryKind,
    region: PhaseRegion,
    probes: u32,
    confidence: i64,
) -> CliffProximity {
    CliffProximity {
        distance_millionths: distance,
        boundary_kind: kind,
        current_region: region,
        probe_count: probes,
        confidence_millionths: confidence,
    }
}

fn make_claim(name: &str, claimed: i64, threshold: i64, higher_is_better: bool) -> MetricClaim {
    MetricClaim {
        metric_name: name.to_string(),
        claimed_value_millionths: claimed,
        threshold_millionths: threshold,
        higher_is_better,
    }
}

fn make_escape_plan(actions: Vec<EscapeAction>, validated: bool) -> EscapePlan {
    EscapePlan {
        plan_id: "test-plan".to_string(),
        actions,
        deadline_ticks: 100,
        validated,
        trigger_margin_millionths: 50_000,
    }
}

fn make_cert(
    domain: GateDomain,
    distance: i64,
    region: PhaseRegion,
    escape: Option<EscapePlan>,
) -> CliffMarginCertificate {
    CliffMarginCertificate::new(
        "test-cert",
        domain,
        make_claim("throughput", 800_000, 500_000, true),
        make_proximity(
            distance,
            BoundaryKind::GradualTransition,
            region,
            10,
            900_000,
        ),
        100_000,
        escape,
        SecurityEpoch::from_raw(1),
        1_000_000,
    )
}

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn single_alert_action() -> EscapeAction {
    EscapeAction::EmitAlert {
        alert_class: "test_alert".to_string(),
        context: "enrichment".to_string(),
    }
}

// ===========================================================================
// 1. GateDomain (5 tests)
// ===========================================================================

#[test]
fn enrichment_gate_domain_display_strings_unique() {
    let domains = [
        GateDomain::Autotuning,
        GateDomain::AotCompilation,
        GateDomain::Supremacy,
        GateDomain::ShippedPath,
        GateDomain::BenchmarkPublication,
    ];
    let set: BTreeSet<String> = domains.iter().map(|d| d.to_string()).collect();
    assert_eq!(set.len(), 5, "all 5 Display strings must be unique");
}

#[test]
fn enrichment_gate_domain_display_matches_expected_strings() {
    // Verify Display output matches the config key used in GateConfig::min_margin_by_domain.
    let config = GateConfig::default();
    let domains = [
        GateDomain::Autotuning,
        GateDomain::AotCompilation,
        GateDomain::Supremacy,
        GateDomain::ShippedPath,
        GateDomain::BenchmarkPublication,
    ];
    for domain in &domains {
        let key = domain.to_string();
        assert!(
            config.min_margin_by_domain.contains_key(&key),
            "Display string '{key}' must match a key in default min_margin_by_domain"
        );
    }
}

#[test]
fn enrichment_gate_domain_serde_roundtrip_all_variants() {
    let domains = [
        GateDomain::Autotuning,
        GateDomain::AotCompilation,
        GateDomain::Supremacy,
        GateDomain::ShippedPath,
        GateDomain::BenchmarkPublication,
    ];
    for domain in &domains {
        let json = serde_json::to_string(domain).unwrap();
        let back: GateDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*domain, back);
    }
}

#[test]
fn enrichment_gate_domain_ordering_stable() {
    let mut domains = vec![
        GateDomain::BenchmarkPublication,
        GateDomain::Supremacy,
        GateDomain::Autotuning,
        GateDomain::ShippedPath,
        GateDomain::AotCompilation,
    ];
    let clone1 = domains.clone();
    domains.sort();
    let mut clone2 = clone1;
    clone2.sort();
    assert_eq!(domains, clone2, "PartialOrd must be deterministic");
}

#[test]
fn enrichment_gate_domain_default_margin_lookup() {
    let config = GateConfig::default();
    assert_eq!(
        config.min_margin_by_domain.get("autotuning"),
        Some(&50_000)
    );
    assert_eq!(
        config.min_margin_by_domain.get("aot_compilation"),
        Some(&100_000)
    );
    assert_eq!(
        config.min_margin_by_domain.get("supremacy"),
        Some(&150_000)
    );
    assert_eq!(
        config.min_margin_by_domain.get("shipped_path"),
        Some(&100_000)
    );
    assert_eq!(
        config.min_margin_by_domain.get("benchmark_publication"),
        Some(&200_000)
    );
}

// ===========================================================================
// 2. CertificateVerdict (4 tests)
// ===========================================================================

#[test]
fn enrichment_certificate_verdict_display_unique() {
    let verdicts = [
        CertificateVerdict::Approved,
        CertificateVerdict::ApprovedWithCaveats,
        CertificateVerdict::Blocked,
        CertificateVerdict::InsufficientEvidence,
    ];
    let set: BTreeSet<String> = verdicts.iter().map(|v| v.to_string()).collect();
    assert_eq!(set.len(), 4, "all 4 verdict Display strings must be unique");
}

#[test]
fn enrichment_certificate_verdict_permits_action_semantics() {
    assert!(CertificateVerdict::Approved.permits_action());
    assert!(CertificateVerdict::ApprovedWithCaveats.permits_action());
    assert!(!CertificateVerdict::Blocked.permits_action());
    assert!(!CertificateVerdict::InsufficientEvidence.permits_action());
}

#[test]
fn enrichment_certificate_verdict_serde_roundtrip_all() {
    let verdicts = [
        CertificateVerdict::Approved,
        CertificateVerdict::ApprovedWithCaveats,
        CertificateVerdict::Blocked,
        CertificateVerdict::InsufficientEvidence,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: CertificateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_certificate_verdict_display_specific_strings() {
    assert_eq!(CertificateVerdict::Approved.to_string(), "approved");
    assert_eq!(
        CertificateVerdict::ApprovedWithCaveats.to_string(),
        "approved_with_caveats"
    );
    assert_eq!(CertificateVerdict::Blocked.to_string(), "blocked");
    assert_eq!(
        CertificateVerdict::InsufficientEvidence.to_string(),
        "insufficient_evidence"
    );
}

// ===========================================================================
// 3. BlockingReason (5 tests)
// ===========================================================================

#[test]
fn enrichment_blocking_reason_display_all_unique() {
    let reasons = vec![
        BlockingReason::InsufficientMargin {
            actual_millionths: 10_000,
            required_millionths: 50_000,
        },
        BlockingReason::MissingEscapePlan,
        BlockingReason::UnvalidatedEscapePlan,
        BlockingReason::EscapePlanTooComplex { action_count: 20 },
        BlockingReason::EscapePlanZeroDeadline,
        BlockingReason::ClaimNotWinning {
            margin_millionths: -30_000,
        },
        BlockingReason::LowConfidence {
            confidence_millionths: 400_000,
            min_required_millionths: 700_000,
        },
        BlockingReason::InsufficientProbes {
            probe_count: 2,
            min_required: 5,
        },
        BlockingReason::InRobustLossRegion,
        BlockingReason::BoundaryTooSevere {
            kind: BoundaryKind::CliffEdge,
            distance_millionths: 5_000,
        },
    ];
    let set: BTreeSet<String> = reasons.iter().map(|r| r.to_string()).collect();
    assert_eq!(set.len(), 10, "all 10 BlockingReason Display strings must be unique");
}

#[test]
fn enrichment_blocking_reason_display_contains_values() {
    let reason = BlockingReason::InsufficientMargin {
        actual_millionths: 10_000,
        required_millionths: 50_000,
    };
    let display = reason.to_string();
    assert!(display.contains("10000"), "must contain actual value");
    assert!(display.contains("50000"), "must contain required value");

    let reason2 = BlockingReason::ClaimNotWinning {
        margin_millionths: -30_000,
    };
    let display2 = reason2.to_string();
    assert!(display2.contains("-30000"), "must contain margin value");
}

#[test]
fn enrichment_blocking_reason_serde_roundtrip_all_10() {
    let reasons = vec![
        BlockingReason::InsufficientMargin {
            actual_millionths: 30_000,
            required_millionths: 100_000,
        },
        BlockingReason::MissingEscapePlan,
        BlockingReason::UnvalidatedEscapePlan,
        BlockingReason::EscapePlanTooComplex { action_count: 25 },
        BlockingReason::EscapePlanZeroDeadline,
        BlockingReason::ClaimNotWinning {
            margin_millionths: -50_000,
        },
        BlockingReason::LowConfidence {
            confidence_millionths: 300_000,
            min_required_millionths: 700_000,
        },
        BlockingReason::InsufficientProbes {
            probe_count: 1,
            min_required: 5,
        },
        BlockingReason::InRobustLossRegion,
        BlockingReason::BoundaryTooSevere {
            kind: BoundaryKind::Cusp,
            distance_millionths: 8_000,
        },
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: BlockingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, &back);
    }
}

#[test]
fn enrichment_blocking_reason_insufficient_probes_display() {
    let reason = BlockingReason::InsufficientProbes {
        probe_count: 2,
        min_required: 5,
    };
    let display = reason.to_string();
    assert!(display.contains("2"), "must contain probe_count");
    assert!(display.contains("5"), "must contain min_required");
}

#[test]
fn enrichment_blocking_reason_low_confidence_display() {
    let reason = BlockingReason::LowConfidence {
        confidence_millionths: 400_000,
        min_required_millionths: 700_000,
    };
    let display = reason.to_string();
    assert!(display.contains("400000"), "must contain confidence");
    assert!(display.contains("700000"), "must contain min_required");
}

// ===========================================================================
// 4. EscapePlanStatus (3 tests)
// ===========================================================================

#[test]
fn enrichment_escape_plan_status_debug_all_unique() {
    let statuses = [
        EscapePlanStatus::ValidAndExecutable,
        EscapePlanStatus::PresentNotValidated,
        EscapePlanStatus::PresentNotExecutable,
        EscapePlanStatus::Absent,
        EscapePlanStatus::NotRequired,
    ];
    let set: BTreeSet<String> = statuses.iter().map(|s| format!("{s:?}")).collect();
    assert_eq!(set.len(), 5, "all 5 EscapePlanStatus Debug strings must be unique");
}

#[test]
fn enrichment_escape_plan_status_serde_roundtrip_all() {
    let statuses = [
        EscapePlanStatus::ValidAndExecutable,
        EscapePlanStatus::PresentNotValidated,
        EscapePlanStatus::PresentNotExecutable,
        EscapePlanStatus::Absent,
        EscapePlanStatus::NotRequired,
    ];
    for status in &statuses {
        let json = serde_json::to_string(status).unwrap();
        let back: EscapePlanStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, back);
    }
}

#[test]
fn enrichment_escape_plan_status_ordering_stable() {
    let mut statuses = vec![
        EscapePlanStatus::NotRequired,
        EscapePlanStatus::ValidAndExecutable,
        EscapePlanStatus::Absent,
        EscapePlanStatus::PresentNotValidated,
        EscapePlanStatus::PresentNotExecutable,
    ];
    let mut clone = statuses.clone();
    statuses.sort();
    clone.sort();
    assert_eq!(statuses, clone);
}

// ===========================================================================
// 5. MetricClaim (5 tests)
// ===========================================================================

#[test]
fn enrichment_metric_claim_margin_positive_higher_is_better() {
    let claim = make_claim("throughput", 1_500_000, 1_000_000, true);
    assert_eq!(claim.margin_millionths(), 500_000);
    assert!(claim.is_winning());
}

#[test]
fn enrichment_metric_claim_margin_positive_lower_is_better() {
    // Latency: claimed 500k < threshold 1_000_000 -> winning
    let claim = make_claim("latency", 500_000, 1_000_000, false);
    assert_eq!(claim.margin_millionths(), 500_000);
    assert!(claim.is_winning());
}

#[test]
fn enrichment_metric_claim_margin_zero_not_winning() {
    let claim = make_claim("exact", 1_000_000, 1_000_000, true);
    assert_eq!(claim.margin_millionths(), 0);
    assert!(!claim.is_winning());
}

#[test]
fn enrichment_metric_claim_margin_one_is_winning() {
    let claim = make_claim("barely", 1_000_001, 1_000_000, true);
    assert_eq!(claim.margin_millionths(), 1);
    assert!(claim.is_winning());
}

#[test]
fn enrichment_metric_claim_serde_roundtrip() {
    let claim = make_claim("test_metric", 750_000, 600_000, true);
    let json = serde_json::to_string(&claim).unwrap();
    let back: MetricClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(claim, back);
}

// ===========================================================================
// 6. CliffProximity (4 tests)
// ===========================================================================

#[test]
fn enrichment_cliff_proximity_is_brittle_true_for_brittle_win() {
    let prox = make_proximity(100_000, BoundaryKind::Fold, PhaseRegion::BrittleWin, 10, 900_000);
    assert!(prox.is_brittle());
}

#[test]
fn enrichment_cliff_proximity_is_brittle_false_for_robust_win() {
    let prox = make_proximity(100_000, BoundaryKind::Fold, PhaseRegion::RobustWin, 10, 900_000);
    assert!(!prox.is_brittle());
}

#[test]
fn enrichment_cliff_proximity_well_probed_true_at_5() {
    let prox = make_proximity(100_000, BoundaryKind::Fold, PhaseRegion::RobustWin, 5, 900_000);
    assert!(prox.is_well_probed());
}

#[test]
fn enrichment_cliff_proximity_well_probed_false_below_5() {
    let prox = make_proximity(100_000, BoundaryKind::Fold, PhaseRegion::RobustWin, 4, 900_000);
    assert!(!prox.is_well_probed());
}

// ===========================================================================
// 7. EscapeAction stable_key (5 tests)
// ===========================================================================

#[test]
fn enrichment_escape_action_revert_parameter_key_format() {
    let action = EscapeAction::RevertParameter {
        parameter_key: "batch_size".to_string(),
        safe_value_millionths: 100_000,
    };
    assert_eq!(action.stable_key(), "revert_param:batch_size");
}

#[test]
fn enrichment_escape_action_disable_aot_key_format() {
    let action = EscapeAction::DisableAotArtifact {
        artifact_id: "aot-42".to_string(),
    };
    assert_eq!(action.stable_key(), "disable_aot:aot-42");
}

#[test]
fn enrichment_escape_action_revert_shipped_path_key_format() {
    let action = EscapeAction::RevertShippedPath {
        path_id: "main-exec".to_string(),
        rollback_version: 7,
    };
    assert_eq!(action.stable_key(), "revert_path:main-exec");
}

#[test]
fn enrichment_escape_action_emit_alert_key_format() {
    let action = EscapeAction::EmitAlert {
        alert_class: "cliff_erosion".to_string(),
        context: "enrichment test".to_string(),
    };
    assert_eq!(action.stable_key(), "alert:cliff_erosion");
}

#[test]
fn enrichment_escape_action_quarantine_key_format_and_all_unique() {
    let action = EscapeAction::QuarantineOptimization {
        optimization_id: "opt-tiering".to_string(),
        reason: "margin thin".to_string(),
    };
    assert_eq!(action.stable_key(), "quarantine:opt-tiering");

    // Verify all 5 key prefixes are unique.
    let keys: BTreeSet<String> = vec![
        EscapeAction::RevertParameter {
            parameter_key: "x".to_string(),
            safe_value_millionths: 0,
        },
        EscapeAction::DisableAotArtifact {
            artifact_id: "x".to_string(),
        },
        EscapeAction::RevertShippedPath {
            path_id: "x".to_string(),
            rollback_version: 0,
        },
        EscapeAction::EmitAlert {
            alert_class: "x".to_string(),
            context: "x".to_string(),
        },
        EscapeAction::QuarantineOptimization {
            optimization_id: "x".to_string(),
            reason: "x".to_string(),
        },
    ]
    .into_iter()
    .map(|a| a.stable_key())
    .collect();
    assert_eq!(keys.len(), 5);
}

// ===========================================================================
// 8. EscapePlan (5 tests)
// ===========================================================================

#[test]
fn enrichment_escape_plan_is_executable_valid() {
    let plan = make_escape_plan(vec![single_alert_action()], true);
    assert!(plan.is_executable());
}

#[test]
fn enrichment_escape_plan_not_executable_empty_actions() {
    let plan = make_escape_plan(vec![], true);
    assert!(!plan.is_executable());
}

#[test]
fn enrichment_escape_plan_not_executable_too_many_actions() {
    let actions: Vec<EscapeAction> = (0..17)
        .map(|i| EscapeAction::EmitAlert {
            alert_class: format!("alert_{i}"),
            context: "overflow".to_string(),
        })
        .collect();
    let plan = make_escape_plan(actions, true);
    assert!(
        !plan.is_executable(),
        "17 actions exceeds MAX_ESCAPE_ACTIONS (16)"
    );
}

#[test]
fn enrichment_escape_plan_not_executable_zero_deadline() {
    let plan = EscapePlan {
        plan_id: "zero-dl".to_string(),
        actions: vec![single_alert_action()],
        deadline_ticks: 0,
        validated: true,
        trigger_margin_millionths: 50_000,
    };
    assert!(!plan.is_executable());
}

#[test]
fn enrichment_escape_plan_exactly_max_actions_is_executable() {
    let actions: Vec<EscapeAction> = (0..MAX_ESCAPE_ACTIONS)
        .map(|i| EscapeAction::EmitAlert {
            alert_class: format!("alert_{i}"),
            context: "at-limit".to_string(),
        })
        .collect();
    let plan = make_escape_plan(actions, true);
    assert_eq!(plan.actions.len(), MAX_ESCAPE_ACTIONS);
    assert!(
        plan.is_executable(),
        "exactly MAX_ESCAPE_ACTIONS must be executable"
    );
}

// ===========================================================================
// 9. Certificate (4 tests)
// ===========================================================================

#[test]
fn enrichment_certificate_headroom_calculation() {
    // distance=300_000, required=100_000 -> headroom=200_000
    let cert = make_cert(GateDomain::Autotuning, 300_000, PhaseRegion::RobustWin, None);
    assert_eq!(cert.headroom_millionths(), 200_000);
}

#[test]
fn enrichment_certificate_has_sufficient_margin_true() {
    let cert = make_cert(GateDomain::Autotuning, 100_000, PhaseRegion::RobustWin, None);
    // headroom = 100_000 - 100_000 = 0 => sufficient (>= 0)
    assert_eq!(cert.headroom_millionths(), 0);
    assert!(cert.has_sufficient_margin());
}

#[test]
fn enrichment_certificate_has_sufficient_margin_false() {
    let cert = make_cert(GateDomain::Autotuning, 50_000, PhaseRegion::RobustWin, None);
    // headroom = 50_000 - 100_000 = -50_000 => insufficient
    assert!(cert.headroom_millionths() < 0);
    assert!(!cert.has_sufficient_margin());
}

#[test]
fn enrichment_certificate_has_executable_escape_plan() {
    let plan = make_escape_plan(vec![single_alert_action()], true);
    let cert = make_cert(
        GateDomain::Supremacy,
        300_000,
        PhaseRegion::RobustWin,
        Some(plan),
    );
    assert!(cert.has_executable_escape_plan());

    // Unvalidated plan should NOT count as executable.
    let bad_plan = make_escape_plan(vec![single_alert_action()], false);
    let cert2 = make_cert(
        GateDomain::Supremacy,
        300_000,
        PhaseRegion::RobustWin,
        Some(bad_plan),
    );
    assert!(!cert2.has_executable_escape_plan());

    // No plan at all.
    let cert3 = make_cert(GateDomain::Supremacy, 300_000, PhaseRegion::RobustWin, None);
    assert!(!cert3.has_executable_escape_plan());
}

// ===========================================================================
// 10. GateConfig (5 tests)
// ===========================================================================

#[test]
fn enrichment_gate_config_default_has_5_entries() {
    let config = GateConfig::default();
    assert_eq!(config.min_margin_by_domain.len(), 5);
}

#[test]
fn enrichment_gate_config_effective_min_margin_cliff_edge_doubles() {
    let config = GateConfig::default();
    // Autotuning base = 50_000; cliff-edge multiplier = 2.0 => 100_000
    let effective = config.effective_min_margin(&GateDomain::Autotuning, &BoundaryKind::CliffEdge);
    assert_eq!(effective, 100_000);
}

#[test]
fn enrichment_gate_config_effective_min_margin_non_cliff_edge_returns_base() {
    let config = GateConfig::default();
    let effective = config.effective_min_margin(&GateDomain::Autotuning, &BoundaryKind::Fold);
    assert_eq!(effective, 50_000);
    let effective2 =
        config.effective_min_margin(&GateDomain::Autotuning, &BoundaryKind::GradualTransition);
    assert_eq!(effective2, 50_000);
}

#[test]
fn enrichment_gate_config_requires_escape_plan_semantics() {
    let config = GateConfig::default();
    // Supremacy, ShippedPath, BenchmarkPublication require escape plans.
    assert!(config.requires_escape_plan(&GateDomain::Supremacy));
    assert!(config.requires_escape_plan(&GateDomain::ShippedPath));
    assert!(config.requires_escape_plan(&GateDomain::BenchmarkPublication));
    // Autotuning and AotCompilation do NOT require escape plans.
    assert!(!config.requires_escape_plan(&GateDomain::Autotuning));
    assert!(!config.requires_escape_plan(&GateDomain::AotCompilation));
}

#[test]
fn enrichment_gate_config_hash_deterministic() {
    let c1 = GateConfig::default();
    let c2 = GateConfig::default();
    assert_eq!(c1.config_hash(), c2.config_hash());
    // Different config -> different hash.
    let c3 = GateConfig {
        min_probe_count: 99,
        ..Default::default()
    };
    assert_ne!(c1.config_hash(), c3.config_hash());
}

// ===========================================================================
// 11. Evaluation edge cases (5 tests)
// ===========================================================================

#[test]
fn enrichment_eval_exact_boundary_approved() {
    // distance == effective margin -> headroom = 0, but should pass margin check
    // Autotuning with GradualTransition: effective margin = 50_000
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = CliffMarginCertificate::new(
        "exact-boundary",
        GateDomain::Autotuning,
        make_claim("throughput", 1_500_000, 1_000_000, true),
        make_proximity(
            50_000,
            BoundaryKind::GradualTransition,
            PhaseRegion::RobustWin,
            10,
            900_000,
        ),
        DEFAULT_MIN_MARGIN_MILLIONTHS,
        None,
        epoch(),
        1_000_000,
    );
    let v = gate.evaluate(&cert);
    // distance (50_000) >= effective_min (50_000) so margin check passes.
    assert!(
        v.permits_action(),
        "exact boundary should be approved, got: {v}"
    );
}

#[test]
fn enrichment_eval_claim_not_winning_plus_robust_loss_multiple_reasons() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = CliffMarginCertificate::new(
        "multi-block",
        GateDomain::Autotuning,
        make_claim("throughput", 800_000, 1_000_000, true), // losing: 800k < 1M
        make_proximity(
            300_000,
            BoundaryKind::Fold,
            PhaseRegion::RobustLoss,
            10,
            900_000,
        ),
        DEFAULT_MIN_MARGIN_MILLIONTHS,
        None,
        epoch(),
        1_000_000,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
    let receipt = gate.last_receipt().unwrap();
    // Should have both ClaimNotWinning and InRobustLossRegion reasons.
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::ClaimNotWinning { .. }))
    );
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::InRobustLossRegion))
    );
    assert!(receipt.blocking_reasons.len() >= 2);
}

#[test]
fn enrichment_eval_insufficient_evidence_low_probe_winning_claim() {
    // Single blocking reason InsufficientProbes with winning claim -> InsufficientEvidence
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = CliffMarginCertificate::new(
        "low-probe",
        GateDomain::Autotuning,
        make_claim("throughput", 2_000_000, 1_000_000, true), // winning
        make_proximity(
            300_000,
            BoundaryKind::GradualTransition,
            PhaseRegion::RobustWin,
            2,       // below min_probe_count (5)
            900_000, // above min_confidence
        ),
        DEFAULT_MIN_MARGIN_MILLIONTHS,
        None,
        epoch(),
        1_000_000,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::InsufficientEvidence);
}

#[test]
fn enrichment_eval_approved_with_caveats_severe_boundary() {
    // CliffEdge or Cusp within 2x effective margin triggers caveat but not block
    let mut gate = CliffMarginGate::with_defaults(epoch());
    // Autotuning cliff-edge: effective_min = 100_000. Caveat if distance < 200_000.
    // Use distance 150_000: passes margin check (150k >= 100k) but within caveat zone.
    let cert = CliffMarginCertificate::new(
        "caveat-cert",
        GateDomain::Autotuning,
        make_claim("throughput", 2_000_000, 1_000_000, true),
        make_proximity(
            150_000,
            BoundaryKind::CliffEdge,
            PhaseRegion::RobustWin,
            10,
            900_000,
        ),
        DEFAULT_MIN_MARGIN_MILLIONTHS,
        None,
        epoch(),
        1_000_000,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::ApprovedWithCaveats);
    let receipt = gate.last_receipt().unwrap();
    assert!(!receipt.caveats.is_empty());
}

#[test]
fn enrichment_eval_receipt_counter_increments_correctly() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    for i in 0..5 {
        let cert = CliffMarginCertificate::new(
            &format!("cnt-{i}"),
            GateDomain::Autotuning,
            make_claim("throughput", 2_000_000, 1_000_000, true),
            make_proximity(
                300_000,
                BoundaryKind::GradualTransition,
                PhaseRegion::RobustWin,
                10,
                900_000,
            ),
            DEFAULT_MIN_MARGIN_MILLIONTHS,
            None,
            epoch(),
            1_000_000,
        );
        gate.evaluate(&cert);
    }
    assert_eq!(gate.receipts().len(), 5);
    for (i, receipt) in gate.receipts().iter().enumerate() {
        assert_eq!(receipt.receipt_id, format!("cmg-rcpt-{}", i + 1));
    }
}

// ===========================================================================
// 12. GateSummary (3 tests)
// ===========================================================================

#[test]
fn enrichment_gate_summary_pass_rate_zero_evals() {
    let gate = CliffMarginGate::with_defaults(epoch());
    let summary = gate.summary();
    assert_eq!(summary.total_evaluations, 0);
    assert_eq!(summary.pass_rate_millionths(), 0);
}

#[test]
fn enrichment_gate_summary_pass_rate_half() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    // 5 approved, 5 blocked = 500_000 (50%)
    for i in 0..10 {
        let claim = if i % 2 == 0 {
            make_claim("throughput", 2_000_000, 1_000_000, true) // winning
        } else {
            make_claim("throughput", 800_000, 1_000_000, true) // losing
        };
        let cert = CliffMarginCertificate::new(
            &format!("half-{i}"),
            GateDomain::Autotuning,
            claim,
            make_proximity(
                300_000,
                BoundaryKind::GradualTransition,
                PhaseRegion::RobustWin,
                10,
                900_000,
            ),
            DEFAULT_MIN_MARGIN_MILLIONTHS,
            None,
            epoch(),
            1_000_000,
        );
        gate.evaluate(&cert);
    }
    let summary = gate.summary();
    assert_eq!(summary.total_evaluations, 10);
    assert_eq!(summary.approved_count, 5);
    assert_eq!(summary.blocked_count, 5);
    assert_eq!(summary.pass_rate_millionths(), 500_000);
}

#[test]
fn enrichment_gate_summary_serde_roundtrip() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = CliffMarginCertificate::new(
        "sum-serde",
        GateDomain::Autotuning,
        make_claim("throughput", 2_000_000, 1_000_000, true),
        make_proximity(
            300_000,
            BoundaryKind::GradualTransition,
            PhaseRegion::RobustWin,
            10,
            900_000,
        ),
        DEFAULT_MIN_MARGIN_MILLIONTHS,
        None,
        epoch(),
        1_000_000,
    );
    gate.evaluate(&cert);
    let summary = gate.summary();
    let json = serde_json::to_string_pretty(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary.total_evaluations, back.total_evaluations);
    assert_eq!(summary.approved_count, back.approved_count);
    assert_eq!(summary.blocked_count, back.blocked_count);
    assert_eq!(summary.summary_hash, back.summary_hash);
}

// ===========================================================================
// 13. Manifest (2 tests)
// ===========================================================================

#[test]
fn enrichment_manifest_schema_version_prefix() {
    let gate = CliffMarginGate::with_defaults(epoch());
    let manifest = CliffMarginManifest::from_gate(&gate);
    assert!(
        manifest.schema_version.starts_with("franken-engine."),
        "schema version must start with 'franken-engine.'"
    );
    assert_eq!(manifest.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_manifest_bead_and_component_non_empty() {
    let gate = CliffMarginGate::with_defaults(epoch());
    let manifest = CliffMarginManifest::from_gate(&gate);
    assert!(!manifest.bead_id.is_empty());
    assert!(!manifest.component.is_empty());
    assert_eq!(manifest.bead_id, BEAD_ID);
    assert_eq!(manifest.component, COMPONENT);
    assert_eq!(manifest.policy_id, POLICY_ID);
}

// ===========================================================================
// Bonus: EscapePlan compute_hash determinism
// ===========================================================================

#[test]
fn enrichment_escape_plan_compute_hash_deterministic() {
    let plan1 = make_escape_plan(vec![single_alert_action()], true);
    let plan2 = make_escape_plan(vec![single_alert_action()], true);
    assert_eq!(plan1.compute_hash(), plan2.compute_hash());

    // Different actions -> different hash.
    let plan3 = make_escape_plan(
        vec![EscapeAction::DisableAotArtifact {
            artifact_id: "other".to_string(),
        }],
        true,
    );
    assert_ne!(plan1.compute_hash(), plan3.compute_hash());
}
