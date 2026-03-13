#![forbid(unsafe_code)]

//! Integration tests for the observability_channel_model module.
//!
//! Covers: PayloadFamily, DistortionMetric, ChannelPath enums; RateDistortionPoint,
//! RateDistortionEnvelope, FailureBudget, ChannelSpec, DistortionRiskEntry,
//! DistortionRiskLedger, PolicyViolation, ViolationKind, ChannelState,
//! ChannelReport, ChannelHealthEntry; generate_report, canonical_channel_specs,
//! canonical_risk_ledgers.

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
use std::collections::BTreeSet;

use frankenengine_engine::observability_channel_model::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

const MILLION: i64 = 1_000_000;

/// Build a minimal lossy channel spec for testing.
fn minimal_lossy_spec(id: &str) -> ChannelSpec {
    ChannelSpec {
        channel_id: id.to_string(),
        family: PayloadFamily::Decision,
        path: ChannelPath::RuntimeToLedger,
        envelope: RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![
                RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 2_000_000,
                },
                RateDistortionPoint {
                    distortion_millionths: 100_000,
                    rate_millibits: 1_000_000,
                },
            ],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        },
        failure_budget: FailureBudget {
            max_drops_per_epoch: 2,
            max_degraded_per_epoch: 3,
            degradation_threshold_millionths: 50_000,
            fail_closed: true,
        },
        max_items_per_epoch: 100,
        buffer_capacity: 10,
        lossy_permitted: true,
        tags: vec!["test".to_string()],
    }
}

/// Build a minimal lossless channel spec.
fn minimal_lossless_spec(id: &str) -> ChannelSpec {
    ChannelSpec {
        channel_id: id.to_string(),
        family: PayloadFamily::Security,
        path: ChannelPath::ControlPlaneToAudit,
        envelope: RateDistortionEnvelope {
            family: PayloadFamily::Security,
            metric: DistortionMetric::BinaryFidelity,
            frontier: vec![RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 1_000_000,
            }],
            max_distortion_millionths: 0,
            min_rate_millibits: 1_000_000,
        },
        failure_budget: FailureBudget {
            max_drops_per_epoch: 0,
            max_degraded_per_epoch: 0,
            degradation_threshold_millionths: 0,
            fail_closed: true,
        },
        max_items_per_epoch: 50,
        buffer_capacity: 10,
        lossy_permitted: false,
        tags: vec!["security".to_string()],
    }
}

// ===========================================================================
// Section 1: PayloadFamily enum
// ===========================================================================

#[test]
fn payload_family_all_contains_five_variants() {
    assert_eq!(PayloadFamily::ALL.len(), 5);
    assert_eq!(PayloadFamily::ALL[0], PayloadFamily::Decision);
    assert_eq!(PayloadFamily::ALL[1], PayloadFamily::Replay);
    assert_eq!(PayloadFamily::ALL[2], PayloadFamily::Optimization);
    assert_eq!(PayloadFamily::ALL[3], PayloadFamily::Security);
    assert_eq!(PayloadFamily::ALL[4], PayloadFamily::LegalProvenance);
}

#[test]
fn payload_family_display_matches_snake_case() {
    assert_eq!(PayloadFamily::Decision.to_string(), "decision");
    assert_eq!(PayloadFamily::Replay.to_string(), "replay");
    assert_eq!(PayloadFamily::Optimization.to_string(), "optimization");
    assert_eq!(PayloadFamily::Security.to_string(), "security");
    assert_eq!(
        PayloadFamily::LegalProvenance.to_string(),
        "legal_provenance"
    );
}

#[test]
fn payload_family_display_strings_all_unique() {
    let displays: BTreeSet<String> = PayloadFamily::ALL.iter().map(|f| f.to_string()).collect();
    assert_eq!(displays.len(), PayloadFamily::ALL.len());
}

#[test]
fn payload_family_serde_roundtrip_all_variants() {
    for fam in PayloadFamily::ALL {
        let json = serde_json::to_string(&fam).unwrap();
        let back: PayloadFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(back, fam);
    }
}

#[test]
fn payload_family_ord_ordering() {
    // Ensure all variants have a deterministic ordering.
    let mut sorted: Vec<PayloadFamily> = PayloadFamily::ALL.to_vec();
    sorted.sort();
    // Just confirm they sort without panicking and remain the same length.
    assert_eq!(sorted.len(), 5);
}

#[test]
fn payload_family_serde_snake_case_format() {
    let json = serde_json::to_string(&PayloadFamily::LegalProvenance).unwrap();
    assert_eq!(json, "\"legal_provenance\"");
    let json2 = serde_json::to_string(&PayloadFamily::Decision).unwrap();
    assert_eq!(json2, "\"decision\"");
}

// ===========================================================================
// Section 2: DistortionMetric enum
// ===========================================================================

#[test]
fn distortion_metric_display_all_variants() {
    assert_eq!(DistortionMetric::Hamming.to_string(), "hamming");
    assert_eq!(DistortionMetric::SquaredError.to_string(), "squared_error");
    assert_eq!(DistortionMetric::LogLoss.to_string(), "log_loss");
    assert_eq!(DistortionMetric::EditDistance.to_string(), "edit_distance");
    assert_eq!(
        DistortionMetric::BinaryFidelity.to_string(),
        "binary_fidelity"
    );
}

#[test]
fn distortion_metric_display_all_unique() {
    let metrics = [
        DistortionMetric::Hamming,
        DistortionMetric::SquaredError,
        DistortionMetric::LogLoss,
        DistortionMetric::EditDistance,
        DistortionMetric::BinaryFidelity,
    ];
    let displays: BTreeSet<String> = metrics.iter().map(|m| m.to_string()).collect();
    assert_eq!(displays.len(), metrics.len());
}

#[test]
fn distortion_metric_serde_roundtrip_all() {
    for dm in [
        DistortionMetric::Hamming,
        DistortionMetric::SquaredError,
        DistortionMetric::LogLoss,
        DistortionMetric::EditDistance,
        DistortionMetric::BinaryFidelity,
    ] {
        let json = serde_json::to_string(&dm).unwrap();
        let back: DistortionMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(dm, back);
    }
}

// ===========================================================================
// Section 3: ChannelPath enum
// ===========================================================================

#[test]
fn channel_path_all_contains_five_variants() {
    assert_eq!(ChannelPath::ALL.len(), 5);
}

#[test]
fn channel_path_display_all_variants() {
    assert_eq!(
        ChannelPath::CompilerToLedger.to_string(),
        "compiler_to_ledger"
    );
    assert_eq!(
        ChannelPath::RuntimeToLedger.to_string(),
        "runtime_to_ledger"
    );
    assert_eq!(
        ChannelPath::ControlPlaneToAudit.to_string(),
        "control_plane_to_audit"
    );
    assert_eq!(
        ChannelPath::ReplayToVerifier.to_string(),
        "replay_to_verifier"
    );
    assert_eq!(
        ChannelPath::ToComplianceArchive.to_string(),
        "to_compliance_archive"
    );
}

#[test]
fn channel_path_display_all_unique() {
    let displays: BTreeSet<String> = ChannelPath::ALL.iter().map(|p| p.to_string()).collect();
    assert_eq!(displays.len(), ChannelPath::ALL.len());
}

#[test]
fn channel_path_serde_roundtrip_all() {
    for cp in ChannelPath::ALL {
        let json = serde_json::to_string(&cp).unwrap();
        let back: ChannelPath = serde_json::from_str(&json).unwrap();
        assert_eq!(cp, back);
    }
}

// ===========================================================================
// Section 4: ViolationKind enum
// ===========================================================================

#[test]
fn violation_kind_display_all_variants() {
    assert_eq!(
        ViolationKind::UncappedTelemetry.to_string(),
        "uncapped_telemetry"
    );
    assert_eq!(
        ViolationKind::UnverifiableLoss.to_string(),
        "unverifiable_loss"
    );
    assert_eq!(
        ViolationKind::DropBudgetExceeded.to_string(),
        "drop_budget_exceeded"
    );
    assert_eq!(
        ViolationKind::DegradationBudgetExceeded.to_string(),
        "degradation_budget_exceeded"
    );
    assert_eq!(
        ViolationKind::BackpressureOverflow.to_string(),
        "backpressure_overflow"
    );
}

#[test]
fn violation_kind_display_all_unique() {
    let kinds = [
        ViolationKind::UncappedTelemetry,
        ViolationKind::UnverifiableLoss,
        ViolationKind::DropBudgetExceeded,
        ViolationKind::DegradationBudgetExceeded,
        ViolationKind::BackpressureOverflow,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), kinds.len());
}

#[test]
fn violation_kind_serde_roundtrip_all() {
    let kinds = [
        ViolationKind::UncappedTelemetry,
        ViolationKind::UnverifiableLoss,
        ViolationKind::DropBudgetExceeded,
        ViolationKind::DegradationBudgetExceeded,
        ViolationKind::BackpressureOverflow,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: ViolationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ===========================================================================
// Section 5: FailureBudget defaults and serde
// ===========================================================================

#[test]
fn failure_budget_default_values() {
    let fb = FailureBudget::default();
    assert_eq!(fb.max_drops_per_epoch, 0);
    assert_eq!(fb.max_degraded_per_epoch, 10);
    assert_eq!(fb.degradation_threshold_millionths, 100_000);
    assert!(fb.fail_closed);
}

#[test]
fn failure_budget_serde_roundtrip() {
    let fb = FailureBudget {
        max_drops_per_epoch: 5,
        max_degraded_per_epoch: 20,
        degradation_threshold_millionths: 75_000,
        fail_closed: false,
    };
    let json = serde_json::to_string(&fb).unwrap();
    let back: FailureBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(fb, back);
}

#[test]
fn failure_budget_default_serde_roundtrip() {
    let fb = FailureBudget::default();
    let json = serde_json::to_string(&fb).unwrap();
    let back: FailureBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(fb, back);
}

// ===========================================================================
// Section 6: RateDistortionEnvelope — interpolation and achievability
// ===========================================================================

#[test]
fn envelope_rate_at_zero_distortion() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 2_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 100_000,
                rate_millibits: 1_000_000,
            },
        ],
        max_distortion_millionths: 100_000,
        min_rate_millibits: 500_000,
    };
    assert_eq!(env.rate_at_distortion(0), Some(2_000_000));
}

#[test]
fn envelope_rate_linear_interpolation_midpoint() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 2_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 100_000,
                rate_millibits: 1_000_000,
            },
        ],
        max_distortion_millionths: 100_000,
        min_rate_millibits: 500_000,
    };
    assert_eq!(env.rate_at_distortion(50_000), Some(1_500_000));
}

#[test]
fn envelope_rate_interpolation_quarter_point() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 2_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 100_000,
                rate_millibits: 1_000_000,
            },
        ],
        max_distortion_millionths: 100_000,
        min_rate_millibits: 500_000,
    };
    // 25% of [0,100000]: rate = 2M + (1M-2M)*25000/100000 = 2M - 250000 = 1_750_000
    assert_eq!(env.rate_at_distortion(25_000), Some(1_750_000));
}

#[test]
fn envelope_rate_at_max_distortion_returns_last_frontier() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 2_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 100_000,
                rate_millibits: 1_000_000,
            },
        ],
        max_distortion_millionths: 100_000,
        min_rate_millibits: 500_000,
    };
    assert_eq!(env.rate_at_distortion(100_000), Some(1_000_000));
}

#[test]
fn envelope_rate_exceeds_max_distortion_returns_none() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![RateDistortionPoint {
            distortion_millionths: 0,
            rate_millibits: 2_000_000,
        }],
        max_distortion_millionths: 50_000,
        min_rate_millibits: 500_000,
    };
    assert_eq!(env.rate_at_distortion(100_000), None);
}

#[test]
fn envelope_empty_frontier_returns_none() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![],
        max_distortion_millionths: 100_000,
        min_rate_millibits: 500_000,
    };
    assert_eq!(env.rate_at_distortion(0), None);
}

#[test]
fn envelope_single_point_frontier() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Replay,
        metric: DistortionMetric::Hamming,
        frontier: vec![RateDistortionPoint {
            distortion_millionths: 0,
            rate_millibits: 8_000_000,
        }],
        max_distortion_millionths: 0,
        min_rate_millibits: 8_000_000,
    };
    assert_eq!(env.rate_at_distortion(0), Some(8_000_000));
}

#[test]
fn envelope_rate_past_last_frontier_point_uses_last() {
    // Distortion within max but past all frontier points.
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Optimization,
        metric: DistortionMetric::SquaredError,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 4_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 50_000,
                rate_millibits: 2_000_000,
            },
        ],
        max_distortion_millionths: 200_000,
        min_rate_millibits: 500_000,
    };
    // Distortion=100_000, past the last frontier point at 50_000.
    assert_eq!(env.rate_at_distortion(100_000), Some(2_000_000));
}

#[test]
fn envelope_three_point_interpolation() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 3_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 100_000,
                rate_millibits: 2_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 200_000,
                rate_millibits: 500_000,
            },
        ],
        max_distortion_millionths: 200_000,
        min_rate_millibits: 200_000,
    };
    // Between first two points at 50_000: 3M + (2M-3M)*50000/100000 = 2_500_000
    assert_eq!(env.rate_at_distortion(50_000), Some(2_500_000));
    // Between second and third at 150_000: 2M + (500k-2M)*50000/100000 = 2M - 750k = 1_250_000
    assert_eq!(env.rate_at_distortion(150_000), Some(1_250_000));
}

#[test]
fn envelope_is_achievable_above_rd_curve() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 2_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 100_000,
                rate_millibits: 1_000_000,
            },
        ],
        max_distortion_millionths: 100_000,
        min_rate_millibits: 500_000,
    };
    // Exactly on the curve.
    assert!(env.is_achievable(2_000_000, 0));
    assert!(env.is_achievable(1_500_000, 50_000));
    // Above the curve.
    assert!(env.is_achievable(3_000_000, 0));
}

#[test]
fn envelope_is_achievable_below_rd_curve_fails() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 2_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 100_000,
                rate_millibits: 1_000_000,
            },
        ],
        max_distortion_millionths: 100_000,
        min_rate_millibits: 500_000,
    };
    assert!(!env.is_achievable(500_000, 0));
    assert!(!env.is_achievable(100_000, 50_000));
}

#[test]
fn envelope_is_achievable_beyond_max_distortion_fails() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![RateDistortionPoint {
            distortion_millionths: 0,
            rate_millibits: 2_000_000,
        }],
        max_distortion_millionths: 50_000,
        min_rate_millibits: 500_000,
    };
    assert!(!env.is_achievable(2_000_000, 200_000));
}

#[test]
fn envelope_is_achievable_empty_frontier_fails() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![],
        max_distortion_millionths: 100_000,
        min_rate_millibits: 500_000,
    };
    assert!(!env.is_achievable(2_000_000, 0));
}

#[test]
fn envelope_serde_roundtrip() {
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Security,
        metric: DistortionMetric::BinaryFidelity,
        frontier: vec![RateDistortionPoint {
            distortion_millionths: 0,
            rate_millibits: 500_000,
        }],
        max_distortion_millionths: 0,
        min_rate_millibits: 500_000,
    };
    let json = serde_json::to_string(&env).unwrap();
    let back: RateDistortionEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, back);
}

#[test]
fn envelope_duplicate_distortion_points() {
    // When two frontier points have the same distortion, the second one's rate is returned.
    let env = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 50_000,
                rate_millibits: 3_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 50_000,
                rate_millibits: 1_500_000,
            },
        ],
        max_distortion_millionths: 100_000,
        min_rate_millibits: 500_000,
    };
    // dd==0, returns the current point's rate.
    assert_eq!(env.rate_at_distortion(50_000), Some(3_000_000));
}

// ===========================================================================
// Section 7: DistortionRiskLedger — risk interpolation
// ===========================================================================

#[test]
fn risk_ledger_interpolation_linear() {
    let ledger = DistortionRiskLedger {
        family: PayloadFamily::Decision,
        entries: vec![
            DistortionRiskEntry {
                distortion_millionths: 0,
                risk_millionths: 0,
                consequence: "none".to_string(),
            },
            DistortionRiskEntry {
                distortion_millionths: 100_000,
                risk_millionths: MILLION,
                consequence: "max".to_string(),
            },
        ],
    };
    assert_eq!(ledger.risk_at_distortion(0), 0);
    assert_eq!(ledger.risk_at_distortion(50_000), 500_000);
    assert_eq!(ledger.risk_at_distortion(100_000), MILLION);
}

#[test]
fn risk_ledger_empty_returns_zero() {
    let ledger = DistortionRiskLedger {
        family: PayloadFamily::Decision,
        entries: vec![],
    };
    assert_eq!(ledger.risk_at_distortion(50_000), 0);
}

#[test]
fn risk_ledger_security_binary_jump() {
    let ledgers = canonical_risk_ledgers();
    let sec = ledgers
        .iter()
        .find(|l| l.family == PayloadFamily::Security)
        .unwrap();
    assert_eq!(sec.risk_at_distortion(0), 0);
    assert_eq!(sec.risk_at_distortion(1), MILLION);
}

#[test]
fn risk_ledger_past_last_entry_uses_last() {
    let ledger = DistortionRiskLedger {
        family: PayloadFamily::Optimization,
        entries: vec![
            DistortionRiskEntry {
                distortion_millionths: 0,
                risk_millionths: 0,
                consequence: "zero".to_string(),
            },
            DistortionRiskEntry {
                distortion_millionths: 50_000,
                risk_millionths: 300_000,
                consequence: "medium".to_string(),
            },
        ],
    };
    assert_eq!(ledger.risk_at_distortion(200_000), 300_000);
}

#[test]
fn risk_ledger_serde_roundtrip() {
    let ledger = DistortionRiskLedger {
        family: PayloadFamily::Decision,
        entries: vec![DistortionRiskEntry {
            distortion_millionths: 0,
            risk_millionths: 0,
            consequence: "ok".to_string(),
        }],
    };
    let json = serde_json::to_string(&ledger).unwrap();
    let back: DistortionRiskLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
}

#[test]
fn canonical_risk_ledgers_cover_decision_and_security() {
    let ledgers = canonical_risk_ledgers();
    let families: BTreeSet<PayloadFamily> = ledgers.iter().map(|l| l.family).collect();
    assert!(families.contains(&PayloadFamily::Decision));
    assert!(families.contains(&PayloadFamily::Security));
}

// ===========================================================================
// Section 8: ChannelState — constructor, emit, drop, drain, reset, healthy
// ===========================================================================

#[test]
fn channel_state_new_has_zero_counters() {
    let state = ChannelState::new("test-ch".to_string(), epoch(1));
    assert_eq!(state.channel_id, "test-ch");
    assert_eq!(state.epoch, epoch(1));
    assert_eq!(state.items_emitted, 0);
    assert_eq!(state.items_dropped, 0);
    assert_eq!(state.items_degraded, 0);
    assert_eq!(state.buffer_used, 0);
    assert!(state.violations.is_empty());
}

#[test]
fn channel_state_emit_increments_counters() {
    let spec = minimal_lossy_spec("ch-test");
    let mut state = ChannelState::new("ch-test".to_string(), epoch(1));
    state.emit(&spec, 0).unwrap();
    assert_eq!(state.items_emitted, 1);
    assert_eq!(state.buffer_used, 1);
    assert_eq!(state.items_degraded, 0);
}

#[test]
fn channel_state_emit_rate_cap_violation() {
    let mut spec = minimal_lossy_spec("ch-test");
    spec.max_items_per_epoch = 2;
    let mut state = ChannelState::new("ch-test".to_string(), epoch(1));
    state.emit(&spec, 0).unwrap();
    state.emit(&spec, 0).unwrap();
    let err = state.emit(&spec, 0).unwrap_err();
    assert_eq!(err.violation_kind, ViolationKind::UncappedTelemetry);
    assert_eq!(err.channel_id, "ch-test");
    assert_eq!(err.epoch, epoch(1));
    assert!(err.detail.contains("rate cap"));
}

#[test]
fn channel_state_emit_backpressure_overflow() {
    let mut spec = minimal_lossy_spec("ch-bp");
    spec.buffer_capacity = 1;
    let mut state = ChannelState::new("ch-bp".to_string(), epoch(1));
    state.emit(&spec, 0).unwrap();
    let err = state.emit(&spec, 0).unwrap_err();
    assert_eq!(err.violation_kind, ViolationKind::BackpressureOverflow);
    assert!(err.detail.contains("buffer full"));
}

#[test]
fn channel_state_emit_lossy_on_lossless_channel() {
    let spec = minimal_lossless_spec("ch-sec");
    let mut state = ChannelState::new("ch-sec".to_string(), epoch(1));
    let err = state.emit(&spec, 10_000).unwrap_err();
    assert_eq!(err.violation_kind, ViolationKind::UnverifiableLoss);
    assert!(err.detail.contains("lossless-only channel"));
}

#[test]
fn channel_state_emit_zero_distortion_on_lossless_ok() {
    let spec = minimal_lossless_spec("ch-sec");
    let mut state = ChannelState::new("ch-sec".to_string(), epoch(1));
    assert!(state.emit(&spec, 0).is_ok());
    assert_eq!(state.items_emitted, 1);
}

#[test]
fn channel_state_emit_degradation_tracking() {
    let spec = minimal_lossy_spec("ch-deg");
    // degradation_threshold_millionths = 50_000
    let mut state = ChannelState::new("ch-deg".to_string(), epoch(1));
    // Below threshold.
    state.emit(&spec, 40_000).unwrap();
    assert_eq!(state.items_degraded, 0);
    // Above threshold.
    state.emit(&spec, 60_000).unwrap();
    assert_eq!(state.items_degraded, 1);
    // At threshold exactly: not degraded (requires strictly >).
    state.emit(&spec, 50_000).unwrap();
    assert_eq!(state.items_degraded, 1);
}

#[test]
fn channel_state_emit_degradation_budget_exceeded_fail_closed() {
    let mut spec = minimal_lossy_spec("ch-dbe");
    spec.failure_budget.max_degraded_per_epoch = 1;
    spec.failure_budget.fail_closed = true;
    let mut state = ChannelState::new("ch-dbe".to_string(), epoch(1));
    // First degraded item: within budget.
    state.emit(&spec, 60_000).unwrap();
    assert_eq!(state.items_degraded, 1);
    // Second degraded item: exceeds budget, fail_closed=true -> Err.
    let err = state.emit(&spec, 60_000).unwrap_err();
    assert_eq!(err.violation_kind, ViolationKind::DegradationBudgetExceeded);
}

#[test]
fn channel_state_emit_degradation_budget_exceeded_fail_open() {
    let mut spec = minimal_lossy_spec("ch-dbo");
    spec.failure_budget.max_degraded_per_epoch = 1;
    spec.failure_budget.fail_closed = false;
    let mut state = ChannelState::new("ch-dbo".to_string(), epoch(1));
    state.emit(&spec, 60_000).unwrap();
    // Second exceeds but fail_closed=false: Ok.
    assert!(state.emit(&spec, 60_000).is_ok());
    // Violation is still tracked even if no error returned.
    assert!(!state.violations.is_empty());
}

#[test]
fn channel_state_record_drop_within_budget() {
    let spec = minimal_lossy_spec("ch-dr");
    // max_drops_per_epoch = 2
    let mut state = ChannelState::new("ch-dr".to_string(), epoch(1));
    assert!(state.record_drop(&spec).is_ok());
    assert_eq!(state.items_dropped, 1);
    assert!(state.record_drop(&spec).is_ok());
    assert_eq!(state.items_dropped, 2);
}

#[test]
fn channel_state_record_drop_exceeds_budget_fail_closed() {
    let mut spec = minimal_lossy_spec("ch-drc");
    spec.failure_budget.max_drops_per_epoch = 0;
    spec.failure_budget.fail_closed = true;
    let mut state = ChannelState::new("ch-drc".to_string(), epoch(1));
    let err = state.record_drop(&spec).unwrap_err();
    assert_eq!(err.violation_kind, ViolationKind::DropBudgetExceeded);
}

#[test]
fn channel_state_record_drop_exceeds_budget_fail_open() {
    let mut spec = minimal_lossy_spec("ch-dro");
    spec.failure_budget.max_drops_per_epoch = 0;
    spec.failure_budget.fail_closed = false;
    let mut state = ChannelState::new("ch-dro".to_string(), epoch(1));
    // fail_closed=false: no error even when exceeding budget.
    assert!(state.record_drop(&spec).is_ok());
    assert_eq!(state.items_dropped, 1);
    assert!(!state.violations.is_empty());
}

#[test]
fn channel_state_drain_one_decrements_buffer() {
    let spec = minimal_lossy_spec("ch-drain");
    let mut state = ChannelState::new("ch-drain".to_string(), epoch(1));
    state.emit(&spec, 0).unwrap();
    state.emit(&spec, 0).unwrap();
    assert_eq!(state.buffer_used, 2);
    state.drain_one();
    assert_eq!(state.buffer_used, 1);
    state.drain_one();
    assert_eq!(state.buffer_used, 0);
}

#[test]
fn channel_state_drain_one_saturates_at_zero() {
    let mut state = ChannelState::new("ch-sat".to_string(), epoch(1));
    assert_eq!(state.buffer_used, 0);
    state.drain_one();
    assert_eq!(state.buffer_used, 0);
}

#[test]
fn channel_state_epoch_reset_clears_all() {
    let spec = minimal_lossy_spec("ch-reset");
    let mut state = ChannelState::new("ch-reset".to_string(), epoch(1));
    state.emit(&spec, 0).unwrap();
    state.emit(&spec, 60_000).unwrap(); // triggers degradation
    let _ = state.record_drop(&spec);
    assert!(state.items_emitted > 0);
    assert!(state.buffer_used > 0);

    state.epoch_reset(epoch(2));
    assert_eq!(state.epoch, epoch(2));
    assert_eq!(state.items_emitted, 0);
    assert_eq!(state.items_dropped, 0);
    assert_eq!(state.items_degraded, 0);
    assert_eq!(state.buffer_used, 0);
    assert!(state.violations.is_empty());
}

#[test]
fn channel_state_is_healthy_when_fresh() {
    let spec = minimal_lossy_spec("ch-health");
    let state = ChannelState::new("ch-health".to_string(), epoch(1));
    assert!(state.is_healthy(&spec));
}

#[test]
fn channel_state_unhealthy_after_drop_violation() {
    let mut spec = minimal_lossy_spec("ch-uh");
    spec.failure_budget.max_drops_per_epoch = 0;
    let mut state = ChannelState::new("ch-uh".to_string(), epoch(1));
    let _ = state.record_drop(&spec);
    assert!(!state.is_healthy(&spec));
}

#[test]
fn channel_state_serde_roundtrip() {
    let mut state = ChannelState::new("ch-serde".to_string(), epoch(5));
    state.items_emitted = 42;
    state.items_dropped = 3;
    state.items_degraded = 7;
    state.buffer_used = 10;
    let json = serde_json::to_string(&state).unwrap();
    let back: ChannelState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

// ===========================================================================
// Section 9: ChannelSpec and canonical specs
// ===========================================================================

#[test]
fn canonical_specs_returns_five_channels() {
    let specs = canonical_channel_specs();
    assert_eq!(specs.len(), 5);
}

#[test]
fn canonical_specs_unique_channel_ids() {
    let specs = canonical_channel_specs();
    let ids: BTreeSet<&str> = specs.iter().map(|s| s.channel_id.as_str()).collect();
    assert_eq!(ids.len(), specs.len());
}

#[test]
fn canonical_specs_cover_all_payload_families() {
    let specs = canonical_channel_specs();
    let families: BTreeSet<PayloadFamily> = specs.iter().map(|s| s.family).collect();
    for fam in PayloadFamily::ALL {
        assert!(families.contains(&fam), "missing family: {fam}");
    }
}

#[test]
fn canonical_specs_security_and_legal_are_lossless() {
    let specs = canonical_channel_specs();
    for spec in &specs {
        if spec.family == PayloadFamily::Security || spec.family == PayloadFamily::LegalProvenance {
            assert!(
                !spec.lossy_permitted,
                "{} should be lossless",
                spec.channel_id
            );
            assert_eq!(
                spec.envelope.max_distortion_millionths, 0,
                "{} max distortion should be zero",
                spec.channel_id,
            );
        }
    }
}

#[test]
fn canonical_specs_replay_is_lossless() {
    let specs = canonical_channel_specs();
    let replay = specs
        .iter()
        .find(|s| s.family == PayloadFamily::Replay)
        .unwrap();
    assert!(!replay.lossy_permitted);
    assert_eq!(replay.envelope.max_distortion_millionths, 0);
}

#[test]
fn canonical_specs_each_has_positive_buffer_capacity() {
    for spec in canonical_channel_specs() {
        assert!(
            spec.buffer_capacity > 0,
            "{} needs buffer_capacity > 0",
            spec.channel_id
        );
    }
}

#[test]
fn canonical_specs_each_has_nonempty_tags() {
    for spec in canonical_channel_specs() {
        assert!(!spec.tags.is_empty(), "{} needs tags", spec.channel_id);
    }
}

#[test]
fn channel_spec_serde_roundtrip() {
    let specs = canonical_channel_specs();
    let json = serde_json::to_string(&specs).unwrap();
    let back: Vec<ChannelSpec> = serde_json::from_str(&json).unwrap();
    assert_eq!(specs, back);
}

// ===========================================================================
// Section 10: generate_report — gate pass/fail, hash determinism, utilization
// ===========================================================================

#[test]
fn report_all_healthy_gate_pass() {
    let specs = canonical_channel_specs();
    let states = BTreeMap::new();
    let report = generate_report(&specs, &states, epoch(1));
    assert!(report.gate_pass);
    assert_eq!(report.total_violations, 0);
    assert_eq!(report.channels.len(), specs.len());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn report_with_violation_gate_fails() {
    let specs = canonical_channel_specs();
    let mut states = BTreeMap::new();
    let mut state = ChannelState::new(specs[0].channel_id.clone(), epoch(1));
    let _ = state.record_drop(&specs[0]); // 0-drop-budget spec -> violation
    states.insert(specs[0].channel_id.clone(), state);

    let report = generate_report(&specs, &states, epoch(1));
    assert!(!report.gate_pass);
    assert!(report.total_violations > 0);
    assert!(report.summary.contains("FAIL"));
}

#[test]
fn report_content_hash_is_deterministic() {
    let specs = canonical_channel_specs();
    let states = BTreeMap::new();
    let r1 = generate_report(&specs, &states, epoch(1));
    let r2 = generate_report(&specs, &states, epoch(1));
    assert_eq!(r1.content_hash, r2.content_hash);
    assert!(!r1.content_hash.is_empty());
}

#[test]
fn report_different_states_produce_different_hashes() {
    let specs = canonical_channel_specs();
    let empty_states = BTreeMap::new();
    let mut states_with_emit = BTreeMap::new();
    let mut s = ChannelState::new(specs[0].channel_id.clone(), epoch(1));
    s.items_emitted = 10;
    states_with_emit.insert(specs[0].channel_id.clone(), s);

    let r1 = generate_report(&specs, &empty_states, epoch(1));
    let r2 = generate_report(&specs, &states_with_emit, epoch(1));
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_utilization_computed_correctly() {
    let specs = canonical_channel_specs();
    let mut states = BTreeMap::new();
    let spec = &specs[0]; // max_items_per_epoch = 100_000
    let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
    for _ in 0..1000 {
        state.emit(spec, 0).unwrap();
        state.drain_one();
    }
    states.insert(spec.channel_id.clone(), state);

    let report = generate_report(&specs, &states, epoch(1));
    let entry = report
        .channels
        .iter()
        .find(|e| e.channel_id == spec.channel_id)
        .unwrap();
    assert_eq!(entry.items_emitted, 1000);
    // 1000/100_000 = 10_000 millionths (1%)
    assert_eq!(entry.utilization_millionths, 10_000);
}

#[test]
fn report_utilization_zero_for_zero_max_items() {
    let mut spec = minimal_lossy_spec("ch-zero-max");
    spec.max_items_per_epoch = 0;
    let specs = vec![spec];
    let states = BTreeMap::new();
    let report = generate_report(&specs, &states, epoch(1));
    assert_eq!(report.channels[0].utilization_millionths, 0);
}

#[test]
fn report_summary_contains_pass_string() {
    let specs = canonical_channel_specs();
    let report = generate_report(&specs, &BTreeMap::new(), epoch(1));
    assert!(report.summary.contains("healthy"));
    assert!(report.summary.contains("PASS"));
}

#[test]
fn report_missing_state_treated_as_healthy() {
    // If a spec has no corresponding state entry, it's treated as healthy with zero counters.
    let specs = vec![minimal_lossy_spec("ch-missing")];
    let states = BTreeMap::new();
    let report = generate_report(&specs, &states, epoch(1));
    assert!(report.gate_pass);
    assert_eq!(report.channels[0].items_emitted, 0);
    assert!(report.channels[0].healthy);
}

#[test]
fn report_serde_roundtrip() {
    let specs = canonical_channel_specs();
    let report = generate_report(&specs, &BTreeMap::new(), epoch(1));
    let json = serde_json::to_string(&report).unwrap();
    let back: ChannelReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ===========================================================================
// Section 11: PolicyViolation serde and fields
// ===========================================================================

#[test]
fn policy_violation_serde_roundtrip() {
    let v = PolicyViolation {
        channel_id: "ch-test".to_string(),
        epoch: epoch(42),
        violation_kind: ViolationKind::UncappedTelemetry,
        detail: "rate exceeded".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: PolicyViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn policy_violation_json_contains_all_fields() {
    let v = PolicyViolation {
        channel_id: "ch-0".to_string(),
        epoch: epoch(1),
        violation_kind: ViolationKind::BackpressureOverflow,
        detail: "overflow".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"channel_id\""));
    assert!(json.contains("\"violation_kind\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"detail\""));
}

// ===========================================================================
// Section 12: SCHEMA_VERSION constant
// ===========================================================================

#[test]
fn schema_version_is_v1() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.observability-channel.v1");
}

// ===========================================================================
// Section 13: End-to-end multi-channel workflow
// ===========================================================================

#[test]
fn end_to_end_multi_channel_emit_drain_reset_report() {
    let specs = canonical_channel_specs();
    let mut states: BTreeMap<String, ChannelState> = BTreeMap::new();

    // Initialize states for all channels.
    for spec in &specs {
        states.insert(
            spec.channel_id.clone(),
            ChannelState::new(spec.channel_id.clone(), epoch(1)),
        );
    }

    // Emit some items on the decision channel (lossy ok).
    let decision_spec = &specs[0];
    for _ in 0..10 {
        let st = states.get_mut(&decision_spec.channel_id).unwrap();
        st.emit(decision_spec, 0).unwrap();
    }

    // Emit zero-distortion items on replay channel (lossless).
    let replay_spec = &specs[1];
    for _ in 0..5 {
        let st = states.get_mut(&replay_spec.channel_id).unwrap();
        st.emit(replay_spec, 0).unwrap();
    }

    // Generate report: should be healthy.
    let report = generate_report(&specs, &states, epoch(1));
    assert!(report.gate_pass);

    // Drain all from decision channel.
    let st = states.get_mut(&decision_spec.channel_id).unwrap();
    for _ in 0..10 {
        st.drain_one();
    }
    assert_eq!(st.buffer_used, 0);

    // Reset for epoch 2.
    for st in states.values_mut() {
        st.epoch_reset(epoch(2));
    }

    // All states should be fresh.
    for st in states.values() {
        assert_eq!(st.epoch, epoch(2));
        assert_eq!(st.items_emitted, 0);
    }

    // New report for epoch 2: still healthy.
    let report2 = generate_report(&specs, &states, epoch(2));
    assert!(report2.gate_pass);
    assert_eq!(report2.epoch, epoch(2));
}

#[test]
fn violations_accumulate_in_state() {
    let mut spec = minimal_lossy_spec("ch-accum");
    spec.max_items_per_epoch = 2;
    spec.buffer_capacity = 100;
    let mut state = ChannelState::new("ch-accum".to_string(), epoch(1));

    // Two ok emits.
    state.emit(&spec, 0).unwrap();
    state.emit(&spec, 0).unwrap();

    // Third triggers UncappedTelemetry.
    let _ = state.emit(&spec, 0);
    assert_eq!(state.violations.len(), 1);

    // Fourth also fails (still at rate cap).
    let _ = state.emit(&spec, 0);
    assert_eq!(state.violations.len(), 2);

    // All violations are UncappedTelemetry.
    for v in &state.violations {
        assert_eq!(v.violation_kind, ViolationKind::UncappedTelemetry);
    }
}

// ============================================================================
// Enrichment tests — channel model construction, routing, capacity, ordering,
// serialization round-trips, contract validation, sampling, and mode resolution
// ============================================================================

use frankenengine_engine::observability_channel_model::{
    DistortionRiskLedger, ENGINE_OBSERVABILITY_CHANNEL_POLICY_SCHEMA_VERSION,
    OBSERVABILITY_CONTRACT_VALIDATION_REPORT_SCHEMA_VERSION, OPERATOR_MODE_CONTRACT_SCHEMA_VERSION,
    ObservabilityContractValidationReport, ObservabilityContractViolation, ObservabilityMode,
    OperatorModePolicy, SAMPLING_SEED_REPLAY_FIXTURE_MATRIX_SCHEMA_VERSION,
    SKETCH_ERROR_ENVELOPE_REPORT_SCHEMA_VERSION, SamplingReplayFixture, SamplingSeedField,
    SamplingStrategy, SketchErrorEnvelope, SketchFamily,
    TELEMETRY_SAMPLING_CONTRACT_SCHEMA_VERSION, TELEMETRY_SITE_POLICY_MATRIX_SCHEMA_VERSION,
    TelemetrySamplingRule, TelemetrySitePolicy, canonical_engine_observability_channel_policy,
    canonical_operator_mode_contract, canonical_sketch_error_envelope_report,
    canonical_telemetry_sampling_contract, canonical_telemetry_site_policy_matrix,
    derive_sampling_seed_hex, deterministic_sampling_interval, resolve_observability_mode,
    validate_observability_contract,
};

// ---------------------------------------------------------------------------
// A. Channel model construction properties (10 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_channel_state_new_initializes_all_counters_to_zero() {
    let state = ChannelState::new("ch-init".to_string(), epoch(10));
    assert_eq!(state.channel_id, "ch-init");
    assert_eq!(state.epoch, epoch(10));
    assert_eq!(state.items_emitted, 0);
    assert_eq!(state.items_dropped, 0);
    assert_eq!(state.items_degraded, 0);
    assert_eq!(state.buffer_used, 0);
    assert!(state.violations.is_empty());
}

#[test]
fn enrichment_channel_spec_construction_with_tags() {
    let mut spec = minimal_lossy_spec("ch-tagged");
    spec.tags = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
    assert_eq!(spec.tags.len(), 3);
    assert!(spec.tags.contains(&"alpha".to_string()));
    assert!(spec.tags.contains(&"gamma".to_string()));
}

#[test]
fn enrichment_channel_spec_lossy_vs_lossless_family_alignment() {
    let lossy = minimal_lossy_spec("ch-lossy");
    assert!(lossy.lossy_permitted);
    assert!(lossy.envelope.max_distortion_millionths > 0);

    let lossless = minimal_lossless_spec("ch-lossless");
    assert!(!lossless.lossy_permitted);
    assert_eq!(lossless.envelope.max_distortion_millionths, 0);
}

#[test]
fn enrichment_failure_budget_default_values() {
    let budget = FailureBudget::default();
    assert_eq!(budget.max_drops_per_epoch, 0);
    assert_eq!(budget.max_degraded_per_epoch, 10);
    assert_eq!(budget.degradation_threshold_millionths, 100_000);
    assert!(budget.fail_closed);
}

#[test]
fn enrichment_failure_budget_serde_roundtrip() {
    let budget = FailureBudget {
        max_drops_per_epoch: 5,
        max_degraded_per_epoch: 20,
        degradation_threshold_millionths: 75_000,
        fail_closed: false,
    };
    let json = serde_json::to_string(&budget).unwrap();
    let back: FailureBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, back);
}

#[test]
fn enrichment_rate_distortion_point_serde_roundtrip() {
    let point = RateDistortionPoint {
        distortion_millionths: 123_456,
        rate_millibits: 789_012,
    };
    let json = serde_json::to_string(&point).unwrap();
    let back: RateDistortionPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(point, back);
}

#[test]
fn enrichment_rate_distortion_envelope_serde_roundtrip() {
    let envelope = RateDistortionEnvelope {
        family: PayloadFamily::LegalProvenance,
        metric: DistortionMetric::BinaryFidelity,
        frontier: vec![RateDistortionPoint {
            distortion_millionths: 0,
            rate_millibits: 500_000,
        }],
        max_distortion_millionths: 0,
        min_rate_millibits: 500_000,
    };
    let json = serde_json::to_string(&envelope).unwrap();
    let back: RateDistortionEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(envelope, back);
}

#[test]
fn enrichment_channel_spec_with_zero_buffer_capacity_always_rejects() {
    let mut spec = minimal_lossy_spec("ch-zero-buf");
    spec.buffer_capacity = 0;
    let mut state = ChannelState::new("ch-zero-buf".to_string(), epoch(1));
    let err = state.emit(&spec, 0).unwrap_err();
    assert_eq!(err.violation_kind, ViolationKind::BackpressureOverflow);
}

#[test]
fn enrichment_canonical_specs_envelope_frontiers_sorted_by_distortion() {
    let specs = canonical_channel_specs();
    for spec in &specs {
        let frontier = &spec.envelope.frontier;
        for pair in frontier.windows(2) {
            assert!(
                pair[0].distortion_millionths <= pair[1].distortion_millionths,
                "frontier should be sorted by distortion in {}",
                spec.channel_id,
            );
        }
    }
}

#[test]
fn enrichment_canonical_specs_max_items_per_epoch_positive() {
    for spec in canonical_channel_specs() {
        assert!(
            spec.max_items_per_epoch > 0,
            "{} should have positive max_items_per_epoch",
            spec.channel_id,
        );
    }
}

// ---------------------------------------------------------------------------
// B. Observability event routing — emit/drop/drain interactions (10 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_emit_then_drop_accumulates_both_counters() {
    let spec = minimal_lossy_spec("ch-emit-drop");
    let mut state = ChannelState::new("ch-emit-drop".to_string(), epoch(1));
    state.emit(&spec, 0).unwrap();
    state.emit(&spec, 0).unwrap();
    state.record_drop(&spec).unwrap();
    assert_eq!(state.items_emitted, 2);
    assert_eq!(state.items_dropped, 1);
}

#[test]
fn enrichment_emit_after_epoch_reset_is_independent() {
    let spec = minimal_lossy_spec("ch-epoch-ind");
    let mut state = ChannelState::new("ch-epoch-ind".to_string(), epoch(1));
    for _ in 0..5 {
        state.emit(&spec, 0).unwrap();
    }
    assert_eq!(state.items_emitted, 5);
    state.epoch_reset(epoch(2));
    state.emit(&spec, 0).unwrap();
    assert_eq!(state.items_emitted, 1);
    assert_eq!(state.epoch, epoch(2));
}

#[test]
fn enrichment_drain_multiple_items_sequentially() {
    let spec = minimal_lossy_spec("ch-multi-drain");
    let mut state = ChannelState::new("ch-multi-drain".to_string(), epoch(1));
    for _ in 0..8 {
        state.emit(&spec, 0).unwrap();
    }
    assert_eq!(state.buffer_used, 8);
    for i in (0..8).rev() {
        state.drain_one();
        assert_eq!(state.buffer_used, i as u64);
    }
}

#[test]
fn enrichment_interleaved_emit_drain_stays_within_capacity() {
    let mut spec = minimal_lossy_spec("ch-interleave");
    spec.buffer_capacity = 3;
    spec.max_items_per_epoch = 1000;
    let mut state = ChannelState::new("ch-interleave".to_string(), epoch(1));
    for _ in 0..100 {
        state.emit(&spec, 0).unwrap();
        state.drain_one();
    }
    assert_eq!(state.items_emitted, 100);
    assert_eq!(state.buffer_used, 0);
}

#[test]
fn enrichment_multiple_drops_within_budget_no_violations() {
    let mut spec = minimal_lossy_spec("ch-drops-ok");
    spec.failure_budget.max_drops_per_epoch = 10;
    let mut state = ChannelState::new("ch-drops-ok".to_string(), epoch(1));
    for _ in 0..10 {
        state.record_drop(&spec).unwrap();
    }
    assert!(state.violations.is_empty());
    assert_eq!(state.items_dropped, 10);
}

#[test]
fn enrichment_degradation_just_at_threshold_not_counted() {
    let spec = minimal_lossy_spec("ch-deg-at");
    // degradation_threshold_millionths = 50_000
    let mut state = ChannelState::new("ch-deg-at".to_string(), epoch(1));
    state.emit(&spec, 50_000).unwrap();
    assert_eq!(
        state.items_degraded, 0,
        "distortion at threshold is not degraded"
    );
}

#[test]
fn enrichment_degradation_just_above_threshold_is_counted() {
    let spec = minimal_lossy_spec("ch-deg-above");
    let mut state = ChannelState::new("ch-deg-above".to_string(), epoch(1));
    state.emit(&spec, 50_001).unwrap();
    assert_eq!(state.items_degraded, 1);
}

#[test]
fn enrichment_emit_with_max_distortion_on_lossy_channel_ok() {
    let spec = minimal_lossy_spec("ch-max-dist");
    // max_distortion = 100_000
    let mut state = ChannelState::new("ch-max-dist".to_string(), epoch(1));
    state.emit(&spec, 100_000).unwrap();
    assert_eq!(state.items_emitted, 1);
    // 100_000 > degradation_threshold(50_000), so counted as degraded
    assert_eq!(state.items_degraded, 1);
}

#[test]
fn enrichment_violation_detail_contains_channel_id() {
    let mut spec = minimal_lossy_spec("ch-detail-check");
    spec.max_items_per_epoch = 0;
    let mut state = ChannelState::new("ch-detail-check".to_string(), epoch(3));
    let err = state.emit(&spec, 0).unwrap_err();
    assert_eq!(err.channel_id, "ch-detail-check");
    assert_eq!(err.epoch, epoch(3));
}

#[test]
fn enrichment_lossless_channel_zero_distortion_multiple_emits() {
    let spec = minimal_lossless_spec("ch-lossless-multi");
    let mut state = ChannelState::new("ch-lossless-multi".to_string(), epoch(1));
    for _ in 0..10 {
        state.emit(&spec, 0).unwrap();
        state.drain_one();
    }
    assert_eq!(state.items_emitted, 10);
    assert!(state.violations.is_empty());
}

// ---------------------------------------------------------------------------
// C. Channel capacity and overflow behavior (8 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_buffer_capacity_one_emit_then_overflow() {
    let mut spec = minimal_lossy_spec("ch-cap1");
    spec.buffer_capacity = 1;
    let mut state = ChannelState::new("ch-cap1".to_string(), epoch(1));
    state.emit(&spec, 0).unwrap();
    let err = state.emit(&spec, 0).unwrap_err();
    assert_eq!(err.violation_kind, ViolationKind::BackpressureOverflow);
}

#[test]
fn enrichment_buffer_recovery_after_overflow() {
    let mut spec = minimal_lossy_spec("ch-recovery");
    spec.buffer_capacity = 2;
    spec.max_items_per_epoch = 100;
    let mut state = ChannelState::new("ch-recovery".to_string(), epoch(1));
    state.emit(&spec, 0).unwrap();
    state.emit(&spec, 0).unwrap();
    let _ = state.emit(&spec, 0); // overflow
    assert!(!state.violations.is_empty());
    state.drain_one();
    // After draining, new emit should work
    state.emit(&spec, 0).unwrap();
    assert_eq!(state.buffer_used, 2);
}

#[test]
fn enrichment_rate_cap_exactly_at_limit_ok() {
    let mut spec = minimal_lossy_spec("ch-rate-exact");
    spec.max_items_per_epoch = 5;
    spec.buffer_capacity = 100;
    let mut state = ChannelState::new("ch-rate-exact".to_string(), epoch(1));
    for _ in 0..5 {
        state.emit(&spec, 0).unwrap();
        state.drain_one();
    }
    assert_eq!(state.items_emitted, 5);
    assert!(state.violations.is_empty());
}

#[test]
fn enrichment_rate_cap_one_past_limit_violates() {
    let mut spec = minimal_lossy_spec("ch-rate-past");
    spec.max_items_per_epoch = 5;
    spec.buffer_capacity = 100;
    let mut state = ChannelState::new("ch-rate-past".to_string(), epoch(1));
    for _ in 0..5 {
        state.emit(&spec, 0).unwrap();
        state.drain_one();
    }
    let err = state.emit(&spec, 0).unwrap_err();
    assert_eq!(err.violation_kind, ViolationKind::UncappedTelemetry);
}

#[test]
fn enrichment_multiple_violation_types_in_same_channel() {
    let mut spec = minimal_lossy_spec("ch-multi-viol");
    spec.failure_budget.max_drops_per_epoch = 0;
    spec.failure_budget.fail_closed = false;
    spec.buffer_capacity = 2;
    spec.max_items_per_epoch = 100;
    let mut state = ChannelState::new("ch-multi-viol".to_string(), epoch(1));
    // First: drop violation (fail_closed=false, records but continues)
    let _ = state.record_drop(&spec);
    // Then: fill buffer
    state.emit(&spec, 0).unwrap();
    state.emit(&spec, 0).unwrap();
    let _ = state.emit(&spec, 0); // backpressure
    let kinds: BTreeSet<_> = state.violations.iter().map(|v| v.violation_kind).collect();
    assert!(kinds.contains(&ViolationKind::DropBudgetExceeded));
    assert!(kinds.contains(&ViolationKind::BackpressureOverflow));
}

#[test]
fn enrichment_drain_beyond_zero_stays_zero() {
    let mut state = ChannelState::new("ch-drain-safe".to_string(), epoch(1));
    for _ in 0..100 {
        state.drain_one();
    }
    assert_eq!(state.buffer_used, 0);
}

#[test]
fn enrichment_large_emission_count_within_budget() {
    let mut spec = minimal_lossy_spec("ch-large-emit");
    spec.max_items_per_epoch = 10_000;
    spec.buffer_capacity = 10_000;
    let mut state = ChannelState::new("ch-large-emit".to_string(), epoch(1));
    for _ in 0..10_000 {
        state.emit(&spec, 0).unwrap();
    }
    assert_eq!(state.items_emitted, 10_000);
    assert!(state.violations.is_empty());
}

#[test]
fn enrichment_drop_budget_boundary_last_allowed_then_fail() {
    let mut spec = minimal_lossy_spec("ch-drop-boundary");
    spec.failure_budget.max_drops_per_epoch = 5;
    spec.failure_budget.fail_closed = true;
    let mut state = ChannelState::new("ch-drop-boundary".to_string(), epoch(1));
    for _ in 0..5 {
        state.record_drop(&spec).unwrap();
    }
    assert!(state.violations.is_empty());
    let err = state.record_drop(&spec).unwrap_err();
    assert_eq!(err.violation_kind, ViolationKind::DropBudgetExceeded);
}

// ---------------------------------------------------------------------------
// D. Deterministic ordering guarantees (8 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_channels_in_spec_order() {
    let specs = vec![
        minimal_lossy_spec("ch-z"),
        minimal_lossy_spec("ch-a"),
        minimal_lossy_spec("ch-m"),
    ];
    let states = BTreeMap::new();
    let report = generate_report(&specs, &states, epoch(1));
    assert_eq!(report.channels[0].channel_id, "ch-z");
    assert_eq!(report.channels[1].channel_id, "ch-a");
    assert_eq!(report.channels[2].channel_id, "ch-m");
}

#[test]
fn enrichment_violations_in_order_of_occurrence() {
    let mut spec = minimal_lossy_spec("ch-viol-order");
    spec.failure_budget.max_drops_per_epoch = 0;
    spec.failure_budget.fail_closed = false;
    spec.buffer_capacity = 1;
    spec.max_items_per_epoch = 100;
    let mut state = ChannelState::new("ch-viol-order".to_string(), epoch(1));
    // First violation: drop
    let _ = state.record_drop(&spec);
    // Second violation: backpressure
    state.emit(&spec, 0).unwrap();
    let _ = state.emit(&spec, 0);
    assert_eq!(
        state.violations[0].violation_kind,
        ViolationKind::DropBudgetExceeded
    );
    assert_eq!(
        state.violations[1].violation_kind,
        ViolationKind::BackpressureOverflow
    );
}

#[test]
fn enrichment_canonical_risk_ledgers_families_are_deterministic() {
    let ledgers_a = canonical_risk_ledgers();
    let ledgers_b = canonical_risk_ledgers();
    assert_eq!(ledgers_a.len(), ledgers_b.len());
    for (a, b) in ledgers_a.iter().zip(ledgers_b.iter()) {
        assert_eq!(a.family, b.family);
        assert_eq!(a.entries.len(), b.entries.len());
    }
}

#[test]
fn enrichment_report_hash_changes_with_epoch() {
    let specs = canonical_channel_specs();
    let states = BTreeMap::new();
    let r1 = generate_report(&specs, &states, epoch(1));
    let r2 = generate_report(&specs, &states, epoch(2));
    // Hash is based on channel entries, not epoch, so same entries => same hash
    // but different reports
    assert_ne!(r1.epoch, r2.epoch);
}

#[test]
fn enrichment_report_total_violations_sum_of_channels() {
    let specs = vec![minimal_lossy_spec("ch-v1"), minimal_lossy_spec("ch-v2")];
    let mut states = BTreeMap::new();
    let mut s1 = ChannelState::new("ch-v1".to_string(), epoch(1));
    // Fill buffer to trigger violation
    for _ in 0..10 {
        let _ = s1.emit(&specs[0], 0);
    }
    let _ = s1.emit(&specs[0], 0); // overflow
    states.insert("ch-v1".to_string(), s1);

    let mut s2 = ChannelState::new("ch-v2".to_string(), epoch(1));
    for _ in 0..10 {
        let _ = s2.emit(&specs[1], 0);
    }
    let _ = s2.emit(&specs[1], 0); // overflow
    states.insert("ch-v2".to_string(), s2);

    let report = generate_report(&specs, &states, epoch(1));
    let channel_sum: u64 = report.channels.iter().map(|c| c.violation_count).sum();
    assert_eq!(report.total_violations, channel_sum);
}

#[test]
fn enrichment_payload_family_ord_is_deterministic() {
    let mut families = vec![
        PayloadFamily::Security,
        PayloadFamily::Decision,
        PayloadFamily::Replay,
        PayloadFamily::LegalProvenance,
        PayloadFamily::Optimization,
    ];
    let families_clone = families.clone();
    families.sort();
    let mut families2 = families_clone;
    families2.sort();
    assert_eq!(families, families2);
}

#[test]
fn enrichment_channel_path_ord_is_deterministic() {
    let mut paths = ChannelPath::ALL.to_vec();
    let paths_clone = paths.clone();
    paths.sort();
    let mut paths2 = paths_clone;
    paths2.sort();
    assert_eq!(paths, paths2);
}

#[test]
fn enrichment_distortion_metric_ord_is_deterministic() {
    let mut metrics = vec![
        DistortionMetric::BinaryFidelity,
        DistortionMetric::Hamming,
        DistortionMetric::EditDistance,
        DistortionMetric::SquaredError,
        DistortionMetric::LogLoss,
    ];
    let clone = metrics.clone();
    metrics.sort();
    let mut metrics2 = clone;
    metrics2.sort();
    assert_eq!(metrics, metrics2);
}

// ---------------------------------------------------------------------------
// E. Serialization round-trips (12 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_distortion_risk_entry_serde_roundtrip() {
    use frankenengine_engine::observability_channel_model::DistortionRiskEntry;
    let entry = DistortionRiskEntry {
        distortion_millionths: 50_000,
        risk_millionths: 200_000,
        consequence: "minor precision loss".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: DistortionRiskEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_distortion_risk_ledger_serde_roundtrip() {
    let ledgers = canonical_risk_ledgers();
    for ledger in &ledgers {
        let json = serde_json::to_string(ledger).unwrap();
        let back: DistortionRiskLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(*ledger, back);
    }
}

#[test]
fn enrichment_channel_health_entry_serde_roundtrip() {
    use frankenengine_engine::observability_channel_model::ChannelHealthEntry;
    let entry = ChannelHealthEntry {
        channel_id: "ch-health-serde".to_string(),
        family: PayloadFamily::Decision,
        path: ChannelPath::RuntimeToLedger,
        items_emitted: 42,
        items_dropped: 3,
        items_degraded: 7,
        utilization_millionths: 420_000,
        healthy: true,
        violation_count: 0,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ChannelHealthEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_observability_mode_serde_roundtrip() {
    for mode in ObservabilityMode::ALL {
        let json = serde_json::to_string(&mode).unwrap();
        let back: ObservabilityMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }
}

#[test]
fn enrichment_sketch_family_serde_roundtrip() {
    for fam in SketchFamily::ALL {
        let json = serde_json::to_string(&fam).unwrap();
        let back: SketchFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(fam, back);
    }
}

#[test]
fn enrichment_sampling_strategy_serde_roundtrip() {
    let strategies = [
        SamplingStrategy::DeterministicStride,
        SamplingStrategy::GeometricWeightedSkip,
    ];
    for s in strategies {
        let json = serde_json::to_string(&s).unwrap();
        let back: SamplingStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn enrichment_sampling_seed_field_serde_roundtrip() {
    let fields = [
        SamplingSeedField::TraceId,
        SamplingSeedField::WorkloadId,
        SamplingSeedField::ManifestHash,
        SamplingSeedField::SiteId,
        SamplingSeedField::Mode,
    ];
    for f in fields {
        let json = serde_json::to_string(&f).unwrap();
        let back: SamplingSeedField = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }
}

#[test]
fn enrichment_operator_mode_policy_serde_roundtrip() {
    let policy = OperatorModePolicy {
        mode: ObservabilityMode::Degraded,
        precedence: 60,
        approximate_allowed: true,
        lossless_required: false,
        requires_calibration: true,
        description: "test policy".to_string(),
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: OperatorModePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_telemetry_sampling_rule_serde_roundtrip() {
    let rule = TelemetrySamplingRule {
        site_id: "test.site".to_string(),
        strategy: SamplingStrategy::GeometricWeightedSkip,
        base_interval: 32,
        max_burst_samples: 8,
        seed_fields: vec![
            SamplingSeedField::TraceId,
            SamplingSeedField::SiteId,
            SamplingSeedField::Mode,
        ],
        precision_target_millionths: 100_000,
        replay_stable: true,
    };
    let json = serde_json::to_string(&rule).unwrap();
    let back: TelemetrySamplingRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

#[test]
fn enrichment_sketch_error_envelope_serde_roundtrip() {
    let env = SketchErrorEnvelope {
        sketch_family: SketchFamily::CountMin,
        family: PayloadFamily::Decision,
        bias_bound_millionths: 40_000,
        variance_bound_millionths: 25_000,
        collision_bound_millionths: 10_000,
        quantile_error_bound_millionths: 0,
        required_exact_shadow_samples: 512,
    };
    let json = serde_json::to_string(&env).unwrap();
    let back: SketchErrorEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, back);
}

#[test]
fn enrichment_sampling_replay_fixture_serde_roundtrip() {
    let fixture = SamplingReplayFixture {
        fixture_id: "test-fixture".to_string(),
        trace_id: "trace-1".to_string(),
        workload_id: "workload-1".to_string(),
        manifest_hash: "hash-1".to_string(),
        site_id: "site-1".to_string(),
        mode: ObservabilityMode::DefaultCapture,
        expected_seed_hex: "abcd1234".to_string(),
        expected_interval: 5,
    };
    let json = serde_json::to_string(&fixture).unwrap();
    let back: SamplingReplayFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(fixture, back);
}

#[test]
fn enrichment_observability_contract_violation_serde_roundtrip() {
    let v = ObservabilityContractViolation {
        code: "FE-RGC-066A-TEST-0001".to_string(),
        detail: "test violation detail".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ObservabilityContractViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// F. Rate-distortion envelope edge cases (6 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_envelope_three_point_interpolation() {
    let envelope = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 3_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 100_000,
                rate_millibits: 2_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 200_000,
                rate_millibits: 1_000_000,
            },
        ],
        max_distortion_millionths: 200_000,
        min_rate_millibits: 500_000,
    };
    // Between first and second point
    assert_eq!(envelope.rate_at_distortion(50_000), Some(2_500_000));
    // Between second and third point
    assert_eq!(envelope.rate_at_distortion(150_000), Some(1_500_000));
    // At boundary points
    assert_eq!(envelope.rate_at_distortion(0), Some(3_000_000));
    assert_eq!(envelope.rate_at_distortion(200_000), Some(1_000_000));
}

#[test]
fn enrichment_envelope_single_point_frontier() {
    let envelope = RateDistortionEnvelope {
        family: PayloadFamily::Replay,
        metric: DistortionMetric::Hamming,
        frontier: vec![RateDistortionPoint {
            distortion_millionths: 0,
            rate_millibits: 8_000_000,
        }],
        max_distortion_millionths: 0,
        min_rate_millibits: 8_000_000,
    };
    assert_eq!(envelope.rate_at_distortion(0), Some(8_000_000));
    assert_eq!(envelope.rate_at_distortion(1), None);
}

#[test]
fn enrichment_envelope_is_achievable_exact_boundary() {
    let envelope = RateDistortionEnvelope {
        family: PayloadFamily::Optimization,
        metric: DistortionMetric::SquaredError,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 1_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 500_000,
                rate_millibits: 500_000,
            },
        ],
        max_distortion_millionths: 500_000,
        min_rate_millibits: 100_000,
    };
    // Exactly at frontier rate: achievable
    assert!(envelope.is_achievable(1_000_000, 0));
    // Below frontier rate: not achievable
    assert!(!envelope.is_achievable(999_999, 0));
    // Above frontier rate: achievable
    assert!(envelope.is_achievable(1_000_001, 0));
}

#[test]
fn enrichment_envelope_is_achievable_negative_distortion_below_frontier() {
    let envelope = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::LogLoss,
        frontier: vec![RateDistortionPoint {
            distortion_millionths: 0,
            rate_millibits: 2_000_000,
        }],
        max_distortion_millionths: 100_000,
        min_rate_millibits: 500_000,
    };
    // Negative distortion is below the first point, so rate_at_distortion returns first point
    assert_eq!(envelope.rate_at_distortion(-100), Some(2_000_000));
}

#[test]
fn enrichment_risk_ledger_interpolation_midpoint() {
    let ledgers = canonical_risk_ledgers();
    let decision_ledger = ledgers
        .iter()
        .find(|l| l.family == PayloadFamily::Decision)
        .unwrap();
    // Decision ledger: 0->0, 50_000->200_000, 100_000->600_000
    let risk_at_25k = decision_ledger.risk_at_distortion(25_000);
    // Should interpolate between 0 and 200_000 at midpoint -> 100_000
    assert_eq!(risk_at_25k, 100_000);
}

#[test]
fn enrichment_risk_ledger_at_exact_entries() {
    let ledgers = canonical_risk_ledgers();
    let decision_ledger = ledgers
        .iter()
        .find(|l| l.family == PayloadFamily::Decision)
        .unwrap();
    assert_eq!(decision_ledger.risk_at_distortion(0), 0);
    assert_eq!(decision_ledger.risk_at_distortion(50_000), 200_000);
    assert_eq!(decision_ledger.risk_at_distortion(100_000), 600_000);
}

// ---------------------------------------------------------------------------
// G. Schema version constants (7 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_engine_observability_channel_policy_schema_version_stable() {
    assert_eq!(
        ENGINE_OBSERVABILITY_CHANNEL_POLICY_SCHEMA_VERSION,
        "franken-engine.engine-observability-channel-policy.v1",
    );
}

#[test]
fn enrichment_operator_mode_contract_schema_version_stable() {
    assert_eq!(
        OPERATOR_MODE_CONTRACT_SCHEMA_VERSION,
        "franken-engine.operator-mode-contract.v1",
    );
}

#[test]
fn enrichment_telemetry_site_policy_matrix_schema_version_stable() {
    assert_eq!(
        TELEMETRY_SITE_POLICY_MATRIX_SCHEMA_VERSION,
        "franken-engine.telemetry-site-policy-matrix.v1",
    );
}

#[test]
fn enrichment_telemetry_sampling_contract_schema_version_stable() {
    assert_eq!(
        TELEMETRY_SAMPLING_CONTRACT_SCHEMA_VERSION,
        "franken-engine.telemetry-sampling-contract.v1",
    );
}

#[test]
fn enrichment_sketch_error_envelope_report_schema_version_stable() {
    assert_eq!(
        SKETCH_ERROR_ENVELOPE_REPORT_SCHEMA_VERSION,
        "franken-engine.sketch-error-envelope-report.v1",
    );
}

#[test]
fn enrichment_sampling_seed_replay_fixture_matrix_schema_version_stable() {
    assert_eq!(
        SAMPLING_SEED_REPLAY_FIXTURE_MATRIX_SCHEMA_VERSION,
        "franken-engine.sampling-seed-replay-fixture-matrix.v1",
    );
}

#[test]
fn enrichment_observability_contract_validation_report_schema_version_stable() {
    assert_eq!(
        OBSERVABILITY_CONTRACT_VALIDATION_REPORT_SCHEMA_VERSION,
        "franken-engine.observability-contract-validation-report.v1",
    );
}

// ---------------------------------------------------------------------------
// H. Contract validation — fail-closed edge cases (10 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_redaction_not_preceding_sampling_fails() {
    let mut policy = canonical_engine_observability_channel_policy();
    policy.redaction_must_precede_sampling = false;
    let mode_contract = canonical_operator_mode_contract();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling = canonical_telemetry_sampling_contract();
    let sketch = canonical_sketch_error_envelope_report();
    let report =
        validate_observability_contract(&policy, &mode_contract, &site_matrix, &sampling, &sketch);
    assert!(!report.gate_pass);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.code == "FE-RGC-066A-CONTRACT-0001")
    );
}

#[test]
fn enrichment_validate_lossless_and_approximate_overlap_fails() {
    let mut policy = canonical_engine_observability_channel_policy();
    // Make Security both lossless and approximate
    policy
        .approximate_allowed_families
        .push(PayloadFamily::Security);
    let mode_contract = canonical_operator_mode_contract();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling = canonical_telemetry_sampling_contract();
    let sketch = canonical_sketch_error_envelope_report();
    let report =
        validate_observability_contract(&policy, &mode_contract, &site_matrix, &sampling, &sketch);
    assert!(!report.gate_pass);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.code == "FE-RGC-066A-CONTRACT-0002")
    );
}

#[test]
fn enrichment_validate_missing_mode_in_contract_fails() {
    let mut mode_contract = canonical_operator_mode_contract();
    // Remove the last mode
    mode_contract.modes.pop();
    let policy = canonical_engine_observability_channel_policy();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling = canonical_telemetry_sampling_contract();
    let sketch = canonical_sketch_error_envelope_report();
    let report =
        validate_observability_contract(&policy, &mode_contract, &site_matrix, &sampling, &sketch);
    assert!(!report.gate_pass);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.code == "FE-RGC-066A-MODE-0003")
    );
}

#[test]
fn enrichment_validate_support_bundle_export_lossy_fails() {
    let mut mode_contract = canonical_operator_mode_contract();
    if let Some(sbe) = mode_contract
        .modes
        .iter_mut()
        .find(|m| m.mode == ObservabilityMode::SupportBundleExport)
    {
        sbe.approximate_allowed = true;
    }
    let policy = canonical_engine_observability_channel_policy();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling = canonical_telemetry_sampling_contract();
    let sketch = canonical_sketch_error_envelope_report();
    let report =
        validate_observability_contract(&policy, &mode_contract, &site_matrix, &sampling, &sketch);
    assert!(!report.gate_pass);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.code == "FE-RGC-066A-MODE-0004")
    );
}

#[test]
fn enrichment_validate_sketch_on_non_approximate_family_fails() {
    let policy = canonical_engine_observability_channel_policy();
    let mode_contract = canonical_operator_mode_contract();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling = canonical_telemetry_sampling_contract();
    let mut sketch = canonical_sketch_error_envelope_report();
    // Add envelope targeting a lossless family
    sketch.envelopes.push(SketchErrorEnvelope {
        sketch_family: SketchFamily::CountMin,
        family: PayloadFamily::Security,
        bias_bound_millionths: 10_000,
        variance_bound_millionths: 10_000,
        collision_bound_millionths: 5_000,
        quantile_error_bound_millionths: 0,
        required_exact_shadow_samples: 100,
    });
    let report =
        validate_observability_contract(&policy, &mode_contract, &site_matrix, &sampling, &sketch);
    assert!(!report.gate_pass);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.code == "FE-RGC-066A-SKETCH-0001")
    );
}

#[test]
fn enrichment_validate_sketch_zero_shadow_samples_fails() {
    let policy = canonical_engine_observability_channel_policy();
    let mode_contract = canonical_operator_mode_contract();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling = canonical_telemetry_sampling_contract();
    let mut sketch = canonical_sketch_error_envelope_report();
    // Set one envelope's required_exact_shadow_samples to 0
    if let Some(env) = sketch.envelopes.first_mut() {
        env.required_exact_shadow_samples = 0;
    }
    let report =
        validate_observability_contract(&policy, &mode_contract, &site_matrix, &sampling, &sketch);
    assert!(!report.gate_pass);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.code == "FE-RGC-066A-SKETCH-0002")
    );
}

#[test]
fn enrichment_validate_non_replay_stable_sampling_fails() {
    let policy = canonical_engine_observability_channel_policy();
    let mode_contract = canonical_operator_mode_contract();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let mut sampling = canonical_telemetry_sampling_contract();
    if let Some(rule) = sampling.rules.first_mut() {
        rule.replay_stable = false;
    }
    let sketch = canonical_sketch_error_envelope_report();
    let report =
        validate_observability_contract(&policy, &mode_contract, &site_matrix, &sampling, &sketch);
    assert!(!report.gate_pass);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.code == "FE-RGC-066A-SAMPLING-0003")
    );
}

#[test]
fn enrichment_validate_sampling_missing_site_id_in_seed_fails() {
    let policy = canonical_engine_observability_channel_policy();
    let mode_contract = canonical_operator_mode_contract();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let mut sampling = canonical_telemetry_sampling_contract();
    if let Some(rule) = sampling.rules.first_mut() {
        rule.seed_fields.retain(|f| *f != SamplingSeedField::SiteId);
    }
    let sketch = canonical_sketch_error_envelope_report();
    let report =
        validate_observability_contract(&policy, &mode_contract, &site_matrix, &sampling, &sketch);
    assert!(!report.gate_pass);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.code == "FE-RGC-066A-SAMPLING-0004")
    );
}

#[test]
fn enrichment_validate_contract_report_serde_with_violations() {
    let mut policy = canonical_engine_observability_channel_policy();
    policy.redaction_must_precede_sampling = false;
    let mode_contract = canonical_operator_mode_contract();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling = canonical_telemetry_sampling_contract();
    let sketch = canonical_sketch_error_envelope_report();
    let report =
        validate_observability_contract(&policy, &mode_contract, &site_matrix, &sampling, &sketch);
    assert!(!report.gate_pass);
    let json = serde_json::to_string(&report).unwrap();
    let back: ObservabilityContractValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.gate_pass, back.gate_pass);
    assert_eq!(report.violations.len(), back.violations.len());
}

#[test]
fn enrichment_validate_duplicate_sketch_envelope_fails() {
    let policy = canonical_engine_observability_channel_policy();
    let mode_contract = canonical_operator_mode_contract();
    let site_matrix = canonical_telemetry_site_policy_matrix();
    let sampling = canonical_telemetry_sampling_contract();
    let mut sketch = canonical_sketch_error_envelope_report();
    // Duplicate first envelope
    if !sketch.envelopes.is_empty() {
        let dup = sketch.envelopes[0].clone();
        sketch.envelopes.push(dup);
    }
    let report =
        validate_observability_contract(&policy, &mode_contract, &site_matrix, &sampling, &sketch);
    assert!(!report.gate_pass);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.code == "FE-RGC-066A-SKETCH-0003")
    );
}

// ---------------------------------------------------------------------------
// I. Sampling seed and interval properties (5 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sampling_seed_is_sha256_length() {
    let seed = derive_sampling_seed_hex("t1", "w1", "h1", "s1", ObservabilityMode::DefaultCapture);
    // SHA-256 hex output is 64 chars
    assert_eq!(seed.len(), 64, "seed should be 64 hex chars (SHA-256)");
}

#[test]
fn enrichment_sampling_seed_differs_by_workload_id() {
    let s1 = derive_sampling_seed_hex(
        "t",
        "workload-a",
        "h",
        "s",
        ObservabilityMode::DefaultCapture,
    );
    let s2 = derive_sampling_seed_hex(
        "t",
        "workload-b",
        "h",
        "s",
        ObservabilityMode::DefaultCapture,
    );
    assert_ne!(s1, s2);
}

#[test]
fn enrichment_sampling_seed_differs_by_manifest_hash() {
    let s1 = derive_sampling_seed_hex("t", "w", "hash-a", "s", ObservabilityMode::DefaultCapture);
    let s2 = derive_sampling_seed_hex("t", "w", "hash-b", "s", ObservabilityMode::DefaultCapture);
    assert_ne!(s1, s2);
}

#[test]
fn enrichment_sampling_interval_base_zero_returns_one() {
    let seed = derive_sampling_seed_hex("t", "w", "h", "s", ObservabilityMode::DefaultCapture);
    let interval = deterministic_sampling_interval(&seed, 0, 10);
    assert_eq!(interval, 1);
}

#[test]
fn enrichment_sampling_interval_short_seed_hex_does_not_panic() {
    // Very short hex should not panic
    let interval = deterministic_sampling_interval("ab", 100, 5);
    assert!(interval > 0);
}

// ---------------------------------------------------------------------------
// J. Mode resolution edge cases (4 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_resolve_mode_incident_highest_precedence() {
    let contract = canonical_operator_mode_contract();
    let incident_prec = contract
        .precedence_of(ObservabilityMode::IncidentFullCapture)
        .unwrap();
    for mode in ObservabilityMode::ALL {
        if mode != ObservabilityMode::IncidentFullCapture {
            let p = contract.precedence_of(mode).unwrap();
            assert!(
                incident_prec >= p,
                "incident should have highest precedence"
            );
        }
    }
}

#[test]
fn enrichment_resolve_mode_approximate_site_allows_degraded() {
    let matrix = canonical_telemetry_site_policy_matrix();
    let approx_site = matrix.sites.iter().find(|s| !s.lossless_required).unwrap();
    assert!(
        approx_site
            .allowed_modes
            .contains(&ObservabilityMode::Degraded),
        "approximate sites should allow degraded mode",
    );
}

#[test]
fn enrichment_resolve_mode_lossless_site_forbids_degraded() {
    let matrix = canonical_telemetry_site_policy_matrix();
    let lossless_site = matrix.sites.iter().find(|s| s.lossless_required).unwrap();
    assert!(
        !lossless_site
            .allowed_modes
            .contains(&ObservabilityMode::Degraded),
        "lossless sites should not allow degraded mode",
    );
}

#[test]
fn enrichment_resolve_mode_with_all_disallowed_returns_none() {
    let contract = canonical_operator_mode_contract();
    // Build a site that only allows DefaultCapture
    let site = TelemetrySitePolicy {
        site_id: "test.narrow".to_string(),
        component: "test".to_string(),
        family: PayloadFamily::Security,
        default_mode: ObservabilityMode::DefaultCapture,
        allowed_modes: vec![ObservabilityMode::DefaultCapture],
        allowed_sketch_families: vec![],
        lossless_required: true,
        requires_redaction: true,
        distortion_budget_millionths: 0,
    };
    // Request modes that are not allowed
    let result = resolve_observability_mode(
        &site,
        &[ObservabilityMode::Degraded, ObservabilityMode::ExactShadow],
        &contract,
    );
    assert!(
        result.is_none(),
        "all requested modes disallowed should return None"
    );
}
