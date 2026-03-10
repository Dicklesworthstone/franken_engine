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
