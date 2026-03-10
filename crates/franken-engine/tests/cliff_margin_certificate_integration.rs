//! Integration tests for cliff_margin_certificate module.
//!
//! Bead: bd-1lsy.7.19.3
//! Policy: RGC-619C

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

use std::collections::BTreeMap;

use frankenengine_engine::catastrophe_witness_generator::{BoundaryKind, PhaseRegion};
use frankenengine_engine::cliff_margin_certificate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn winning_latency_claim() -> MetricClaim {
    MetricClaim {
        metric_name: "p99_latency_ns".to_string(),
        claimed_value_millionths: 500_000,
        threshold_millionths: 1_000_000,
        higher_is_better: false,
    }
}

fn winning_throughput_claim() -> MetricClaim {
    MetricClaim {
        metric_name: "ops_per_sec".to_string(),
        claimed_value_millionths: 2_000_000,
        threshold_millionths: 1_000_000,
        higher_is_better: true,
    }
}

fn losing_throughput_claim() -> MetricClaim {
    MetricClaim {
        metric_name: "ops_per_sec".to_string(),
        claimed_value_millionths: 800_000,
        threshold_millionths: 1_000_000,
        higher_is_better: true,
    }
}

fn robust_win_proximity(distance: i64) -> CliffProximity {
    CliffProximity {
        distance_millionths: distance,
        boundary_kind: BoundaryKind::Fold,
        current_region: PhaseRegion::RobustWin,
        probe_count: 15,
        confidence_millionths: 950_000,
    }
}

fn brittle_win_proximity(distance: i64) -> CliffProximity {
    CliffProximity {
        distance_millionths: distance,
        boundary_kind: BoundaryKind::Cusp,
        current_region: PhaseRegion::BrittleWin,
        probe_count: 10,
        confidence_millionths: 800_000,
    }
}

fn cliff_edge_proximity(distance: i64) -> CliffProximity {
    CliffProximity {
        distance_millionths: distance,
        boundary_kind: BoundaryKind::CliffEdge,
        current_region: PhaseRegion::BrittleWin,
        probe_count: 10,
        confidence_millionths: 800_000,
    }
}

fn validated_escape_plan() -> EscapePlan {
    EscapePlan {
        plan_id: "integ-escape-001".to_string(),
        actions: vec![
            EscapeAction::RevertParameter {
                parameter_key: "batch_size".to_string(),
                safe_value_millionths: 100_000,
            },
            EscapeAction::EmitAlert {
                alert_class: "cliff_erosion".to_string(),
                context: "integration test".to_string(),
            },
            EscapeAction::QuarantineOptimization {
                optimization_id: "opt-aggressive-tiering".to_string(),
                reason: "margin too thin".to_string(),
            },
        ],
        deadline_ticks: 50,
        validated: true,
        trigger_margin_millionths: 30_000,
    }
}

fn make_cert_with_plan(
    id: &str,
    domain: GateDomain,
    claim: MetricClaim,
    proximity: CliffProximity,
    plan: Option<EscapePlan>,
) -> CliffMarginCertificate {
    CliffMarginCertificate::new(
        id,
        domain,
        claim,
        proximity,
        DEFAULT_MIN_MARGIN_MILLIONTHS,
        plan,
        epoch(),
        1_000_000_000,
    )
}

// ===========================================================================
// Autotuning domain tests
// ===========================================================================

#[test]
fn test_autotuning_approved_robust_win() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = make_cert_with_plan(
        "at-001",
        GateDomain::Autotuning,
        winning_latency_claim(),
        robust_win_proximity(300_000),
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Approved);
}

#[test]
fn test_autotuning_approved_no_escape_required() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = make_cert_with_plan(
        "at-002",
        GateDomain::Autotuning,
        winning_throughput_claim(),
        robust_win_proximity(500_000),
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Approved);
    let receipt = gate.last_receipt().unwrap();
    assert_eq!(receipt.escape_plan_status, EscapePlanStatus::NotRequired);
}

#[test]
fn test_autotuning_blocked_insufficient_margin() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = make_cert_with_plan(
        "at-003",
        GateDomain::Autotuning,
        winning_latency_claim(),
        robust_win_proximity(20_000), // below 50k autotuning minimum
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
}

#[test]
fn test_autotuning_cliff_edge_doubles_margin_requirement() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    // Autotuning margin = 50k, cliff-edge doubles to 100k
    let cert = make_cert_with_plan(
        "at-004",
        GateDomain::Autotuning,
        winning_latency_claim(),
        cliff_edge_proximity(80_000), // above 50k but below 100k
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
}

#[test]
fn test_autotuning_cliff_edge_approved_with_caveats() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    // 150k distance, cliff-edge requires 100k. 150k < 100k*2 = 200k → caveat
    let cert = make_cert_with_plan(
        "at-005",
        GateDomain::Autotuning,
        winning_latency_claim(),
        cliff_edge_proximity(150_000),
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::ApprovedWithCaveats);
}

// ===========================================================================
// Supremacy domain tests
// ===========================================================================

#[test]
fn test_supremacy_requires_escape_plan() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = make_cert_with_plan(
        "sup-001",
        GateDomain::Supremacy,
        winning_throughput_claim(),
        robust_win_proximity(500_000),
        None, // No escape plan
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
    let receipt = gate.last_receipt().unwrap();
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::MissingEscapePlan))
    );
}

#[test]
fn test_supremacy_approved_with_escape_plan() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = make_cert_with_plan(
        "sup-002",
        GateDomain::Supremacy,
        winning_throughput_claim(),
        robust_win_proximity(500_000),
        Some(validated_escape_plan()),
    );
    let v = gate.evaluate(&cert);
    assert!(v.permits_action());
}

#[test]
fn test_supremacy_blocked_unvalidated_plan() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let mut plan = validated_escape_plan();
    plan.validated = false;
    let cert = make_cert_with_plan(
        "sup-003",
        GateDomain::Supremacy,
        winning_throughput_claim(),
        robust_win_proximity(500_000),
        Some(plan),
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
}

#[test]
fn test_supremacy_higher_margin_requirement() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    // Supremacy requires 150k margin
    let cert = make_cert_with_plan(
        "sup-004",
        GateDomain::Supremacy,
        winning_throughput_claim(),
        robust_win_proximity(120_000), // < 150k
        Some(validated_escape_plan()),
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
}

// ===========================================================================
// AOT compilation domain tests
// ===========================================================================

#[test]
fn test_aot_approved_no_escape_required() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = make_cert_with_plan(
        "aot-001",
        GateDomain::AotCompilation,
        winning_latency_claim(),
        robust_win_proximity(300_000),
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Approved);
}

#[test]
fn test_aot_blocked_thin_margin() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    // AOT requires 100k margin
    let cert = make_cert_with_plan(
        "aot-002",
        GateDomain::AotCompilation,
        winning_latency_claim(),
        robust_win_proximity(60_000),
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
}

// ===========================================================================
// Shipped path domain tests
// ===========================================================================

#[test]
fn test_shipped_path_requires_escape_plan() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = make_cert_with_plan(
        "sp-001",
        GateDomain::ShippedPath,
        winning_throughput_claim(),
        robust_win_proximity(300_000),
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
}

#[test]
fn test_shipped_path_approved_with_plan() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = make_cert_with_plan(
        "sp-002",
        GateDomain::ShippedPath,
        winning_throughput_claim(),
        robust_win_proximity(300_000),
        Some(validated_escape_plan()),
    );
    let v = gate.evaluate(&cert);
    assert!(v.permits_action());
}

// ===========================================================================
// Benchmark publication domain tests
// ===========================================================================

#[test]
fn test_benchmark_pub_highest_margin() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    // Benchmark publication requires 200k margin
    let cert = make_cert_with_plan(
        "bp-001",
        GateDomain::BenchmarkPublication,
        winning_throughput_claim(),
        robust_win_proximity(180_000), // < 200k
        Some(validated_escape_plan()),
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
}

#[test]
fn test_benchmark_pub_approved_with_sufficient_margin() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = make_cert_with_plan(
        "bp-002",
        GateDomain::BenchmarkPublication,
        winning_throughput_claim(),
        robust_win_proximity(300_000),
        Some(validated_escape_plan()),
    );
    let v = gate.evaluate(&cert);
    assert!(v.permits_action());
}

// ===========================================================================
// Evidence sufficiency tests
// ===========================================================================

#[test]
fn test_insufficient_probes_returns_insufficient_evidence() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let prox = CliffProximity {
        distance_millionths: 300_000,
        boundary_kind: BoundaryKind::Fold,
        current_region: PhaseRegion::RobustWin,
        probe_count: 2,
        confidence_millionths: 950_000,
    };
    let cert = make_cert_with_plan(
        "ev-001",
        GateDomain::Autotuning,
        winning_latency_claim(),
        prox,
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::InsufficientEvidence);
}

#[test]
fn test_low_confidence_returns_insufficient_evidence() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let prox = CliffProximity {
        distance_millionths: 300_000,
        boundary_kind: BoundaryKind::Fold,
        current_region: PhaseRegion::RobustWin,
        probe_count: 10,
        confidence_millionths: 500_000, // below 700k threshold
    };
    let cert = make_cert_with_plan(
        "ev-002",
        GateDomain::Autotuning,
        winning_latency_claim(),
        prox,
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::InsufficientEvidence);
}

#[test]
fn test_low_probes_plus_losing_claim_is_blocked_not_insufficient() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let prox = CliffProximity {
        distance_millionths: 300_000,
        boundary_kind: BoundaryKind::Fold,
        current_region: PhaseRegion::RobustWin,
        probe_count: 2,
        confidence_millionths: 950_000,
    };
    let cert = make_cert_with_plan(
        "ev-003",
        GateDomain::Autotuning,
        losing_throughput_claim(),
        prox,
        None,
    );
    let v = gate.evaluate(&cert);
    // Multiple blocking reasons → Blocked, not InsufficientEvidence
    assert_eq!(v, CertificateVerdict::Blocked);
}

// ===========================================================================
// Region tests
// ===========================================================================

#[test]
fn test_robust_loss_always_blocked() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let prox = CliffProximity {
        distance_millionths: 900_000,
        boundary_kind: BoundaryKind::Fold,
        current_region: PhaseRegion::RobustLoss,
        probe_count: 20,
        confidence_millionths: 990_000,
    };
    let cert = make_cert_with_plan(
        "reg-001",
        GateDomain::Autotuning,
        losing_throughput_claim(),
        prox,
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
    assert!(
        gate.last_receipt()
            .unwrap()
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::InRobustLossRegion))
    );
}

#[test]
fn test_brittle_win_can_still_approve() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = make_cert_with_plan(
        "reg-002",
        GateDomain::Autotuning,
        winning_throughput_claim(),
        brittle_win_proximity(200_000),
        None,
    );
    let v = gate.evaluate(&cert);
    // Brittle win with cusp boundary and 200k distance may get caveats
    assert!(v.permits_action());
}

#[test]
fn test_neutral_region_with_winning_claim() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let prox = CliffProximity {
        distance_millionths: 200_000,
        boundary_kind: BoundaryKind::Fold,
        current_region: PhaseRegion::Neutral,
        probe_count: 10,
        confidence_millionths: 850_000,
    };
    let cert = make_cert_with_plan(
        "reg-003",
        GateDomain::Autotuning,
        winning_throughput_claim(),
        prox,
        None,
    );
    let v = gate.evaluate(&cert);
    assert!(v.permits_action());
}

// ===========================================================================
// Escape plan detail tests
// ===========================================================================

#[test]
fn test_escape_plan_too_many_actions() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let actions: Vec<EscapeAction> = (0..20)
        .map(|i| EscapeAction::EmitAlert {
            alert_class: format!("alert_{i}"),
            context: "overloaded".to_string(),
        })
        .collect();
    let plan = EscapePlan {
        plan_id: "too-many".to_string(),
        actions,
        deadline_ticks: 50,
        validated: true,
        trigger_margin_millionths: 50_000,
    };
    let cert = make_cert_with_plan(
        "ep-001",
        GateDomain::Supremacy,
        winning_throughput_claim(),
        robust_win_proximity(500_000),
        Some(plan),
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
}

#[test]
fn test_escape_plan_zero_deadline() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let plan = EscapePlan {
        plan_id: "zero-dl".to_string(),
        actions: vec![EscapeAction::EmitAlert {
            alert_class: "test".to_string(),
            context: "test".to_string(),
        }],
        deadline_ticks: 0,
        validated: true,
        trigger_margin_millionths: 50_000,
    };
    let cert = make_cert_with_plan(
        "ep-002",
        GateDomain::Supremacy,
        winning_throughput_claim(),
        robust_win_proximity(500_000),
        Some(plan),
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
}

#[test]
fn test_escape_plan_revert_shipped_path() {
    let plan = EscapePlan {
        plan_id: "revert-path".to_string(),
        actions: vec![EscapeAction::RevertShippedPath {
            path_id: "main-executor".to_string(),
            rollback_version: 42,
        }],
        deadline_ticks: 100,
        validated: true,
        trigger_margin_millionths: 50_000,
    };
    assert!(plan.is_executable());
    let key = plan.actions[0].stable_key();
    assert!(key.starts_with("revert_path:"));
}

#[test]
fn test_escape_plan_disable_aot() {
    let plan = EscapePlan {
        plan_id: "disable-aot".to_string(),
        actions: vec![EscapeAction::DisableAotArtifact {
            artifact_id: "aot-123".to_string(),
        }],
        deadline_ticks: 30,
        validated: true,
        trigger_margin_millionths: 40_000,
    };
    assert!(plan.is_executable());
    let key = plan.actions[0].stable_key();
    assert!(key.starts_with("disable_aot:"));
}

// ===========================================================================
// Batch evaluation tests
// ===========================================================================

#[test]
fn test_batch_mixed_verdicts() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let certs = vec![
        make_cert_with_plan(
            "batch-001",
            GateDomain::Autotuning,
            winning_latency_claim(),
            robust_win_proximity(300_000),
            None,
        ),
        make_cert_with_plan(
            "batch-002",
            GateDomain::Autotuning,
            losing_throughput_claim(),
            robust_win_proximity(300_000),
            None,
        ),
        make_cert_with_plan(
            "batch-003",
            GateDomain::Autotuning,
            winning_throughput_claim(),
            robust_win_proximity(300_000),
            None,
        ),
    ];
    let result = evaluate_batch(&mut gate, &certs);
    assert!(!result.all_approved);
    assert_eq!(result.verdicts.len(), 3);
    assert_eq!(
        result.verdicts.get("batch-001"),
        Some(&CertificateVerdict::Approved)
    );
    assert_eq!(
        result.verdicts.get("batch-002"),
        Some(&CertificateVerdict::Blocked)
    );
}

#[test]
fn test_batch_all_approved() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let certs = vec![
        make_cert_with_plan(
            "ok-001",
            GateDomain::Autotuning,
            winning_latency_claim(),
            robust_win_proximity(300_000),
            None,
        ),
        make_cert_with_plan(
            "ok-002",
            GateDomain::Autotuning,
            winning_throughput_claim(),
            robust_win_proximity(200_000),
            None,
        ),
    ];
    let result = evaluate_batch(&mut gate, &certs);
    assert!(result.all_approved);
}

#[test]
fn test_batch_summary_accurate() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let certs: Vec<CliffMarginCertificate> = (0..10)
        .map(|i| {
            let claim = if (i as u64).is_multiple_of(2) {
                winning_throughput_claim()
            } else {
                losing_throughput_claim()
            };
            make_cert_with_plan(
                &format!("sum-{i:03}"),
                GateDomain::Autotuning,
                claim,
                robust_win_proximity(300_000),
                None,
            )
        })
        .collect();
    let result = evaluate_batch(&mut gate, &certs);
    assert_eq!(result.summary.total_evaluations, 10);
    assert_eq!(result.summary.approved_count, 5);
    assert_eq!(result.summary.blocked_count, 5);
    assert_eq!(result.summary.pass_rate_millionths(), 500_000);
}

// ===========================================================================
// Custom config tests
// ===========================================================================

#[test]
fn test_custom_config_strict_margin() {
    let mut config = GateConfig::default();
    config
        .min_margin_by_domain
        .insert("autotuning".to_string(), 400_000); // 40%
    let mut gate = CliffMarginGate::new(config, epoch());

    let cert = make_cert_with_plan(
        "strict-001",
        GateDomain::Autotuning,
        winning_latency_claim(),
        robust_win_proximity(300_000), // < 400k
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Blocked);
}

#[test]
fn test_custom_config_no_escape_required() {
    let config = GateConfig {
        min_margin_by_domain: BTreeMap::new(),
        escape_plan_required_domains: vec![], // No domains require escape
        min_confidence_millionths: 500_000,
        min_probe_count: 3,
        cliff_edge_margin_multiplier_millionths: 1_500_000,
        fail_closed: true,
    };
    let mut gate = CliffMarginGate::new(config, epoch());

    let cert = make_cert_with_plan(
        "custom-001",
        GateDomain::Supremacy,
        winning_throughput_claim(),
        robust_win_proximity(200_000),
        None, // No escape plan — but custom config doesn't require one
    );
    let v = gate.evaluate(&cert);
    assert!(v.permits_action());
}

#[test]
fn test_custom_config_lower_probe_threshold() {
    let config = GateConfig {
        min_probe_count: 3,
        ..Default::default()
    };
    let mut gate = CliffMarginGate::new(config, epoch());

    let prox = CliffProximity {
        distance_millionths: 300_000,
        boundary_kind: BoundaryKind::Fold,
        current_region: PhaseRegion::RobustWin,
        probe_count: 3,
        confidence_millionths: 900_000,
    };
    let cert = make_cert_with_plan(
        "custom-002",
        GateDomain::Autotuning,
        winning_latency_claim(),
        prox,
        None,
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Approved);
}

// ===========================================================================
// Convenience constructor tests
// ===========================================================================

#[test]
fn test_latency_certificate_constructor() {
    let cert = latency_certificate(
        "lat-integ-001",
        GateDomain::AotCompilation,
        "p95_latency_ns",
        700_000,
        1_000_000,
        250_000,
        BoundaryKind::Fold,
        PhaseRegion::RobustWin,
        12,
        880_000,
        None,
        epoch(),
    );
    assert!(!cert.claim.higher_is_better);
    assert!(cert.claim.is_winning());
    assert_eq!(cert.domain, GateDomain::AotCompilation);
}

#[test]
fn test_throughput_certificate_constructor() {
    let cert = throughput_certificate(
        "tp-integ-001",
        GateDomain::Supremacy,
        "requests_per_sec",
        3_000_000,
        1_500_000,
        400_000,
        BoundaryKind::GradualTransition,
        PhaseRegion::RobustWin,
        20,
        980_000,
        Some(validated_escape_plan()),
        epoch(),
    );
    assert!(cert.claim.higher_is_better);
    assert!(cert.claim.is_winning());
    assert_eq!(cert.domain, GateDomain::Supremacy);
}

#[test]
fn test_latency_cert_through_gate() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = latency_certificate(
        "lat-gate-001",
        GateDomain::AotCompilation,
        "p99_ns",
        600_000,
        1_000_000,
        300_000,
        BoundaryKind::Fold,
        PhaseRegion::RobustWin,
        15,
        950_000,
        None,
        epoch(),
    );
    let v = gate.evaluate(&cert);
    assert_eq!(v, CertificateVerdict::Approved);
}

// ===========================================================================
// Manifest tests
// ===========================================================================

#[test]
fn test_manifest_from_gate_captures_all_receipts() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    for i in 0..5 {
        let cert = make_cert_with_plan(
            &format!("man-{i:03}"),
            GateDomain::Autotuning,
            winning_latency_claim(),
            robust_win_proximity(300_000),
            None,
        );
        gate.evaluate(&cert);
    }
    let manifest = CliffMarginManifest::from_gate(&gate);
    assert_eq!(manifest.schema_version, SCHEMA_VERSION);
    assert_eq!(manifest.bead_id, BEAD_ID);
    assert_eq!(manifest.receipts.len(), 5);
    assert_eq!(manifest.summary.total_evaluations, 5);
    assert_eq!(manifest.summary.approved_count, 5);
}

#[test]
fn test_manifest_serde_roundtrip() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let cert = make_cert_with_plan(
        "serde-001",
        GateDomain::Supremacy,
        winning_throughput_claim(),
        robust_win_proximity(500_000),
        Some(validated_escape_plan()),
    );
    gate.evaluate(&cert);
    let manifest = CliffMarginManifest::from_gate(&gate);

    let json = serde_json::to_string_pretty(&manifest).unwrap();
    let back: CliffMarginManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest.schema_version, back.schema_version);
    assert_eq!(manifest.manifest_hash, back.manifest_hash);
    assert_eq!(manifest.receipts.len(), back.receipts.len());
}

#[test]
fn test_manifest_hash_deterministic() {
    let mut g1 = CliffMarginGate::with_defaults(epoch());
    let mut g2 = CliffMarginGate::with_defaults(epoch());
    let cert = make_cert_with_plan(
        "det-001",
        GateDomain::Autotuning,
        winning_latency_claim(),
        robust_win_proximity(300_000),
        None,
    );
    g1.evaluate(&cert.clone());
    g2.evaluate(&cert);

    let m1 = CliffMarginManifest::from_gate(&g1);
    let m2 = CliffMarginManifest::from_gate(&g2);
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}

// ===========================================================================
// Summary detail tests
// ===========================================================================

#[test]
fn test_summary_headroom_stats() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    // Large margin cert
    let c1 = make_cert_with_plan(
        "hd-001",
        GateDomain::Autotuning,
        winning_latency_claim(),
        robust_win_proximity(500_000),
        None,
    );
    // Tight margin cert
    let c2 = make_cert_with_plan(
        "hd-002",
        GateDomain::Autotuning,
        winning_latency_claim(),
        robust_win_proximity(110_000), // headroom = 110k - 100k = 10k
        None,
    );
    gate.evaluate(&c1);
    gate.evaluate(&c2);

    let summary = gate.summary();
    // min headroom should be 10k (cert 2's headroom = 110k - 100k = 10_000)
    assert_eq!(summary.min_headroom_millionths, 10_000);
    // avg should be (400_000 + 10_000) / 2 = 205_000
    assert_eq!(summary.avg_headroom_millionths, 205_000);
}

#[test]
fn test_summary_empty_gate() {
    let gate = CliffMarginGate::with_defaults(epoch());
    let summary = gate.summary();
    assert_eq!(summary.total_evaluations, 0);
    assert_eq!(summary.approved_count, 0);
    assert_eq!(summary.blocked_count, 0);
    assert_eq!(summary.pass_rate_millionths(), 0);
    assert!(summary.blocking_reason_counts.is_empty());
}

// ===========================================================================
// Serde roundtrip tests
// ===========================================================================

#[test]
fn test_gate_config_serde_roundtrip() {
    let config = GateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(
        config.min_confidence_millionths,
        back.min_confidence_millionths
    );
    assert_eq!(config.min_probe_count, back.min_probe_count);
}

#[test]
fn test_escape_action_serde_roundtrip() {
    let actions = vec![
        EscapeAction::RevertParameter {
            parameter_key: "k".to_string(),
            safe_value_millionths: 500_000,
        },
        EscapeAction::DisableAotArtifact {
            artifact_id: "aot-1".to_string(),
        },
        EscapeAction::RevertShippedPath {
            path_id: "sp-1".to_string(),
            rollback_version: 7,
        },
        EscapeAction::EmitAlert {
            alert_class: "test".to_string(),
            context: "ctx".to_string(),
        },
        EscapeAction::QuarantineOptimization {
            optimization_id: "opt-1".to_string(),
            reason: "r".to_string(),
        },
    ];
    for action in &actions {
        let json = serde_json::to_string(action).unwrap();
        let back: EscapeAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, &back);
    }
}

#[test]
fn test_blocking_reason_serde_roundtrip() {
    let reasons = vec![
        BlockingReason::InsufficientMargin {
            actual_millionths: 30_000,
            required_millionths: 100_000,
        },
        BlockingReason::MissingEscapePlan,
        BlockingReason::UnvalidatedEscapePlan,
        BlockingReason::EscapePlanTooComplex { action_count: 20 },
        BlockingReason::EscapePlanZeroDeadline,
        BlockingReason::ClaimNotWinning {
            margin_millionths: -50_000,
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
            distance_millionths: 10_000,
        },
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: BlockingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, &back);
    }
}

// ===========================================================================
// Edge case and boundary tests
// ===========================================================================

#[test]
fn test_zero_margin_claim_not_winning() {
    let claim = MetricClaim {
        metric_name: "exact".to_string(),
        claimed_value_millionths: 1_000_000,
        threshold_millionths: 1_000_000,
        higher_is_better: true,
    };
    assert_eq!(claim.margin_millionths(), 0);
    assert!(!claim.is_winning());
}

#[test]
fn test_i64_max_claim_no_overflow() {
    let claim = MetricClaim {
        metric_name: "big".to_string(),
        claimed_value_millionths: i64::MAX,
        threshold_millionths: 0,
        higher_is_better: true,
    };
    // Should saturate, not overflow
    let margin = claim.margin_millionths();
    assert_eq!(margin, i64::MAX);
}

#[test]
fn test_cert_hash_changes_with_domain() {
    let c1 = make_cert_with_plan(
        "hash-001",
        GateDomain::Autotuning,
        winning_latency_claim(),
        robust_win_proximity(300_000),
        None,
    );
    let c2 = make_cert_with_plan(
        "hash-001",
        GateDomain::Supremacy,
        winning_latency_claim(),
        robust_win_proximity(300_000),
        None,
    );
    assert_ne!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn test_receipt_counter_increments() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    for i in 0..3 {
        let cert = make_cert_with_plan(
            &format!("cnt-{i}"),
            GateDomain::Autotuning,
            winning_latency_claim(),
            robust_win_proximity(300_000),
            None,
        );
        gate.evaluate(&cert);
    }
    assert_eq!(gate.receipts().len(), 3);
    assert_eq!(gate.receipts()[0].receipt_id, "cmg-rcpt-1");
    assert_eq!(gate.receipts()[1].receipt_id, "cmg-rcpt-2");
    assert_eq!(gate.receipts()[2].receipt_id, "cmg-rcpt-3");
}

#[test]
fn test_gate_approved_and_blocked_counts() {
    let mut gate = CliffMarginGate::with_defaults(epoch());
    let good = make_cert_with_plan(
        "cnt-g",
        GateDomain::Autotuning,
        winning_latency_claim(),
        robust_win_proximity(300_000),
        None,
    );
    let bad = make_cert_with_plan(
        "cnt-b",
        GateDomain::Autotuning,
        losing_throughput_claim(),
        robust_win_proximity(300_000),
        None,
    );
    gate.evaluate(&good);
    gate.evaluate(&bad);
    gate.evaluate(&good);

    assert_eq!(gate.approved_count(), 2);
    assert_eq!(gate.blocked_count(), 1);
}

#[test]
fn test_config_hash_changes_with_params() {
    let c1 = GateConfig::default();
    let c2 = GateConfig {
        min_probe_count: 20,
        ..Default::default()
    };
    assert_ne!(c1.config_hash(), c2.config_hash());
}

#[test]
fn test_escape_plan_hash_changes_with_actions() {
    let p1 = validated_escape_plan();
    let mut p2 = validated_escape_plan();
    p2.actions.push(EscapeAction::EmitAlert {
        alert_class: "extra".to_string(),
        context: "added".to_string(),
    });
    assert_ne!(p1.compute_hash(), p2.compute_hash());
}
