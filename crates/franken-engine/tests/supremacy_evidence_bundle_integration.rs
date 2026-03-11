//! Integration tests for `supremacy_evidence_bundle` module.
//!
//! Validates public API, serde contracts, determinism, gate evaluation logic,
//! coverage stats, staleness checks, integrity validation, decision receipts,
//! and fail-closed semantics.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::supremacy_evidence_bundle::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn green_cell(id: &str) -> CellEvidence {
    CellEvidence {
        cell_id: id.to_string(),
        status: CellStatus::Green,
        verdict_hash: ContentHash::compute(id.as_bytes()),
        observation_count: 100,
        effect_size_millionths: 300_000,
        observability_mode: ObservabilityMode::BudgetedCapture,
        evidence_epoch: SecurityEpoch::from_raw(100),
    }
}

fn red_cell(id: &str) -> CellEvidence {
    CellEvidence {
        cell_id: id.to_string(),
        status: CellStatus::Red,
        verdict_hash: ContentHash::compute(id.as_bytes()),
        observation_count: 50,
        effect_size_millionths: 100_000,
        observability_mode: ObservabilityMode::BudgetedCapture,
        evidence_epoch: SecurityEpoch::from_raw(100),
    }
}

fn yellow_cell(id: &str) -> CellEvidence {
    CellEvidence {
        cell_id: id.to_string(),
        status: CellStatus::Yellow,
        verdict_hash: ContentHash::compute(id.as_bytes()),
        observation_count: 10,
        effect_size_millionths: 50_000,
        observability_mode: ObservabilityMode::ExactShadow,
        evidence_epoch: SecurityEpoch::from_raw(100),
    }
}

fn missing_cell(id: &str) -> CellEvidence {
    CellEvidence {
        cell_id: id.to_string(),
        status: CellStatus::Missing,
        verdict_hash: ContentHash::compute(b"empty"),
        observation_count: 0,
        effect_size_millionths: 0,
        observability_mode: ObservabilityMode::BudgetedCapture,
        evidence_epoch: SecurityEpoch::from_raw(100),
    }
}

fn unsupported_cell(id: &str) -> CellEvidence {
    CellEvidence {
        cell_id: id.to_string(),
        status: CellStatus::Unsupported,
        verdict_hash: ContentHash::compute(b"na"),
        observation_count: 0,
        effect_size_millionths: 0,
        observability_mode: ObservabilityMode::DegradedCapture,
        evidence_epoch: SecurityEpoch::from_raw(100),
    }
}

fn ambiguous_cell(id: &str) -> CellEvidence {
    CellEvidence {
        cell_id: id.to_string(),
        status: CellStatus::ModeAmbiguous,
        verdict_hash: ContentHash::compute(b"ambig"),
        observation_count: 30,
        effect_size_millionths: 200_000,
        observability_mode: ObservabilityMode::IncidentCapture,
        evidence_epoch: SecurityEpoch::from_raw(100),
    }
}

fn stale_cell(id: &str) -> CellEvidence {
    CellEvidence {
        cell_id: id.to_string(),
        status: CellStatus::Green,
        verdict_hash: ContentHash::compute(id.as_bytes()),
        observation_count: 100,
        effect_size_millionths: 300_000,
        observability_mode: ObservabilityMode::BudgetedCapture,
        evidence_epoch: SecurityEpoch::from_raw(50),
    }
}

fn cell_at_epoch(id: &str, status: CellStatus, ep: u64) -> CellEvidence {
    CellEvidence {
        cell_id: id.to_string(),
        status,
        verdict_hash: ContentHash::compute(id.as_bytes()),
        observation_count: 100,
        effect_size_millionths: 250_000,
        observability_mode: ObservabilityMode::BudgetedCapture,
        evidence_epoch: SecurityEpoch::from_raw(ep),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("supremacy-evidence-bundle"));
}

#[test]
fn component_name() {
    assert_eq!(COMPONENT, "supremacy_evidence_bundle");
}

#[test]
fn bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn default_coverage_fraction_is_full() {
    assert_eq!(DEFAULT_MIN_COVERAGE_FRACTION, 1_000_000);
}

#[test]
fn default_max_staleness_positive() {
    assert!(DEFAULT_MAX_STALENESS_EPOCHS > 0);
}

#[test]
fn max_cells_positive() {
    assert!(MAX_CELLS_PER_BUNDLE > 0);
}

#[test]
fn max_block_reasons_positive() {
    assert!(MAX_BLOCK_REASONS > 0);
}

// ---------------------------------------------------------------------------
// CellStatus
// ---------------------------------------------------------------------------

#[test]
fn cell_status_all_count() {
    assert_eq!(CellStatus::ALL.len(), 6);
}

#[test]
fn cell_status_names_unique() {
    let names: BTreeSet<&str> = CellStatus::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(names.len(), CellStatus::ALL.len());
}

#[test]
fn cell_status_display_matches_as_str() {
    for s in CellStatus::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn cell_status_serde_all() {
    for s in CellStatus::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: CellStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn cell_status_green_publication_safe() {
    assert!(CellStatus::Green.is_publication_safe());
}

#[test]
fn cell_status_yellow_publication_safe() {
    assert!(CellStatus::Yellow.is_publication_safe());
}

#[test]
fn cell_status_red_not_publication_safe() {
    assert!(!CellStatus::Red.is_publication_safe());
}

#[test]
fn cell_status_missing_not_publication_safe() {
    assert!(!CellStatus::Missing.is_publication_safe());
}

#[test]
fn cell_status_unsupported_not_publication_safe() {
    assert!(!CellStatus::Unsupported.is_publication_safe());
}

#[test]
fn cell_status_mode_ambiguous_not_publication_safe() {
    assert!(!CellStatus::ModeAmbiguous.is_publication_safe());
}

#[test]
fn cell_status_blocks_strict_all() {
    assert!(!CellStatus::Green.blocks_strict());
    assert!(!CellStatus::Yellow.blocks_strict());
    assert!(CellStatus::Red.blocks_strict());
    assert!(CellStatus::Missing.blocks_strict());
    assert!(CellStatus::Unsupported.blocks_strict());
    assert!(CellStatus::ModeAmbiguous.blocks_strict());
}

// ---------------------------------------------------------------------------
// ObservabilityMode
// ---------------------------------------------------------------------------

#[test]
fn obs_mode_all_count() {
    assert_eq!(ObservabilityMode::ALL.len(), 4);
}

#[test]
fn obs_mode_names_unique() {
    let names: BTreeSet<&str> = ObservabilityMode::ALL.iter().map(|m| m.as_str()).collect();
    assert_eq!(names.len(), ObservabilityMode::ALL.len());
}

#[test]
fn obs_mode_display_all() {
    for m in ObservabilityMode::ALL {
        assert_eq!(m.to_string(), m.as_str());
    }
}

#[test]
fn obs_mode_serde_all() {
    for m in ObservabilityMode::ALL {
        let json = serde_json::to_string(m).unwrap();
        let back: ObservabilityMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*m, back);
    }
}

#[test]
fn obs_mode_rigorous_budgeted() {
    assert!(ObservabilityMode::BudgetedCapture.is_rigorous());
}

#[test]
fn obs_mode_rigorous_exact_shadow() {
    assert!(ObservabilityMode::ExactShadow.is_rigorous());
}

#[test]
fn obs_mode_not_rigorous_degraded() {
    assert!(!ObservabilityMode::DegradedCapture.is_rigorous());
}

#[test]
fn obs_mode_not_rigorous_incident() {
    assert!(!ObservabilityMode::IncidentCapture.is_rigorous());
}

// ---------------------------------------------------------------------------
// BlockReason
// ---------------------------------------------------------------------------

#[test]
fn block_reason_tags_unique() {
    let reasons = [
        BlockReason::MissingCell {
            cell_id: "a".into(),
        },
        BlockReason::RedCell {
            cell_id: "b".into(),
        },
        BlockReason::UnsupportedCell {
            cell_id: "c".into(),
        },
        BlockReason::ModeAmbiguousCell {
            cell_id: "d".into(),
        },
        BlockReason::InsufficientCoverage {
            coverage_fraction_millionths: 0,
            required_millionths: 0,
        },
        BlockReason::StaleEvidence {
            cell_id: "e".into(),
            evidence_epoch: 0,
            current_epoch: 100,
            max_staleness: 10,
        },
        BlockReason::IntegrityFailure {
            details: "bad".into(),
        },
    ];
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 7);
}

#[test]
fn block_reason_display_missing_cell() {
    let r = BlockReason::MissingCell {
        cell_id: "cell-x".into(),
    };
    assert!(r.to_string().contains("cell-x"));
    assert!(r.to_string().contains("missing"));
}

#[test]
fn block_reason_display_red_cell() {
    let r = BlockReason::RedCell {
        cell_id: "cell-y".into(),
    };
    assert!(r.to_string().contains("red"));
    assert!(r.to_string().contains("cell-y"));
}

#[test]
fn block_reason_display_unsupported_cell() {
    let r = BlockReason::UnsupportedCell {
        cell_id: "cell-u".into(),
    };
    assert!(r.to_string().contains("unsupported"));
}

#[test]
fn block_reason_display_mode_ambiguous() {
    let r = BlockReason::ModeAmbiguousCell {
        cell_id: "cell-m".into(),
    };
    assert!(r.to_string().contains("ambiguous"));
}

#[test]
fn block_reason_display_insufficient_coverage() {
    let r = BlockReason::InsufficientCoverage {
        coverage_fraction_millionths: 500_000,
        required_millionths: 1_000_000,
    };
    let s = r.to_string();
    assert!(s.contains("500000"));
    assert!(s.contains("1000000"));
}

#[test]
fn block_reason_display_stale_evidence() {
    let r = BlockReason::StaleEvidence {
        cell_id: "cell-s".into(),
        evidence_epoch: 10,
        current_epoch: 100,
        max_staleness: 5,
    };
    let s = r.to_string();
    assert!(s.contains("stale"));
    assert!(s.contains("cell-s"));
}

#[test]
fn block_reason_display_integrity_failure() {
    let r = BlockReason::IntegrityFailure {
        details: "hash mismatch".into(),
    };
    assert!(r.to_string().contains("integrity"));
}

#[test]
fn block_reason_serde_roundtrip() {
    let r = BlockReason::StaleEvidence {
        cell_id: "c1".into(),
        evidence_epoch: 10,
        current_epoch: 100,
        max_staleness: 5,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: BlockReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// PublicationGateVerdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_approved_properties() {
    let v = PublicationGateVerdict::Approved;
    assert!(v.is_approved());
    assert!(!v.is_blocked());
    assert_eq!(v.block_count(), 0);
    assert_eq!(v.tag(), "approved");
    assert_eq!(v.to_string(), "APPROVED");
}

#[test]
fn verdict_blocked_properties() {
    let v = PublicationGateVerdict::Blocked {
        reasons: vec![
            BlockReason::RedCell {
                cell_id: "a".into(),
            },
            BlockReason::MissingCell {
                cell_id: "b".into(),
            },
        ],
    };
    assert!(!v.is_approved());
    assert!(v.is_blocked());
    assert_eq!(v.block_count(), 2);
    assert_eq!(v.tag(), "blocked");
    assert!(v.to_string().contains("2 reason(s)"));
}

#[test]
fn verdict_serde_approved() {
    let v = PublicationGateVerdict::Approved;
    let json = serde_json::to_string(&v).unwrap();
    let back: PublicationGateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn verdict_serde_blocked() {
    let v = PublicationGateVerdict::Blocked {
        reasons: vec![BlockReason::IntegrityFailure {
            details: "bad hash".into(),
        }],
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: PublicationGateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// CellEvidence
// ---------------------------------------------------------------------------

#[test]
fn cell_evidence_hash_deterministic() {
    let c1 = green_cell("cell-det");
    let c2 = green_cell("cell-det");
    assert_eq!(c1.compute_hash(), c2.compute_hash());
}

#[test]
fn cell_evidence_different_id_different_hash() {
    let c1 = green_cell("cell-a");
    let c2 = green_cell("cell-b");
    assert_ne!(c1.compute_hash(), c2.compute_hash());
}

#[test]
fn cell_evidence_different_status_different_hash() {
    let c1 = green_cell("same-id");
    let mut c2 = green_cell("same-id");
    c2.status = CellStatus::Red;
    assert_ne!(c1.compute_hash(), c2.compute_hash());
}

#[test]
fn cell_evidence_serde_roundtrip() {
    let c = green_cell("serde-cell");
    let json = serde_json::to_string(&c).unwrap();
    let back: CellEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn cell_evidence_all_statuses_serde() {
    let cells = vec![
        green_cell("g"),
        red_cell("r"),
        yellow_cell("y"),
        missing_cell("m"),
        unsupported_cell("u"),
        ambiguous_cell("a"),
    ];
    for c in &cells {
        let json = serde_json::to_string(c).unwrap();
        let back: CellEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ---------------------------------------------------------------------------
// CoverageStats
// ---------------------------------------------------------------------------

#[test]
fn coverage_all_green() {
    let cells = vec![green_cell("a"), green_cell("b"), green_cell("c")];
    let stats = compute_coverage_stats(&cells);
    assert_eq!(stats.total_cells, 3);
    assert_eq!(stats.green_count, 3);
    assert_eq!(stats.red_count, 0);
    assert_eq!(stats.yellow_count, 0);
    assert_eq!(stats.missing_count, 0);
    assert!(stats.all_green());
    assert!(!stats.has_blocking_cells());
    assert_eq!(stats.coverage_fraction_millionths, 1_000_000);
}

#[test]
fn coverage_mixed_statuses() {
    let cells = vec![
        green_cell("g1"),
        red_cell("r1"),
        yellow_cell("y1"),
        missing_cell("m1"),
        unsupported_cell("u1"),
        ambiguous_cell("a1"),
    ];
    let stats = compute_coverage_stats(&cells);
    assert_eq!(stats.total_cells, 6);
    assert_eq!(stats.green_count, 1);
    assert_eq!(stats.red_count, 1);
    assert_eq!(stats.yellow_count, 1);
    assert_eq!(stats.missing_count, 1);
    assert_eq!(stats.unsupported_count, 1);
    assert_eq!(stats.mode_ambiguous_count, 1);
    assert!(!stats.all_green());
    assert!(stats.has_blocking_cells());
    // 1/6 * 1_000_000 = 166_666
    assert_eq!(stats.coverage_fraction_millionths, 166_666);
}

#[test]
fn coverage_empty_cells() {
    let stats = compute_coverage_stats(&[]);
    assert_eq!(stats.total_cells, 0);
    assert_eq!(stats.coverage_fraction_millionths, 0);
    assert!(!stats.all_green());
    assert!(!stats.has_blocking_cells());
}

#[test]
fn coverage_half_green() {
    let cells = vec![green_cell("a"), yellow_cell("b")];
    let stats = compute_coverage_stats(&cells);
    assert_eq!(stats.coverage_fraction_millionths, 500_000);
}

#[test]
fn coverage_all_red() {
    let cells = vec![red_cell("a"), red_cell("b")];
    let stats = compute_coverage_stats(&cells);
    assert_eq!(stats.green_count, 0);
    assert_eq!(stats.red_count, 2);
    assert_eq!(stats.coverage_fraction_millionths, 0);
    assert!(stats.has_blocking_cells());
}

#[test]
fn coverage_stats_display() {
    let cells = vec![green_cell("a"), red_cell("b")];
    let stats = compute_coverage_stats(&cells);
    let s = stats.to_string();
    assert!(s.contains("coverage"));
    assert!(s.contains("1/2"));
}

// ---------------------------------------------------------------------------
// BundleConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let c = BundleConfig::default();
    assert!(c.required_cell_ids.is_empty());
    assert_eq!(c.max_staleness_epochs, DEFAULT_MAX_STALENESS_EPOCHS);
    assert_eq!(
        c.min_coverage_fraction_millionths,
        DEFAULT_MIN_COVERAGE_FRACTION
    );
    assert!(c.require_all_green);
}

#[test]
fn config_permissive_values() {
    let c = BundleConfig::permissive();
    assert!(!c.require_all_green);
    assert_eq!(c.min_coverage_fraction_millionths, 0);
    assert_eq!(c.max_staleness_epochs, u64::MAX);
}

#[test]
fn config_serde_roundtrip() {
    let mut c = BundleConfig::default();
    c.required_cell_ids.insert("cell-a".to_string());
    c.required_cell_ids.insert("cell-b".to_string());
    let json = serde_json::to_string(&c).unwrap();
    let back: BundleConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn config_default_trait() {
    let c1 = BundleConfig::default();
    let c2 = BundleConfig::default_config();
    assert_eq!(c1, c2);
}

// ---------------------------------------------------------------------------
// BundleError
// ---------------------------------------------------------------------------

#[test]
fn error_empty_cells() {
    let e = BundleError::EmptyCells;
    assert_eq!(e.tag(), "empty_cells");
    assert!(e.to_string().contains("no cells"));
}

#[test]
fn error_too_many_cells() {
    let e = BundleError::TooManyCells {
        count: 600,
        max: 512,
    };
    assert_eq!(e.tag(), "too_many_cells");
    assert!(e.to_string().contains("600"));
}

#[test]
fn error_duplicate_cell_ids() {
    let e = BundleError::DuplicateCellIds {
        duplicates: vec!["dup".into()],
    };
    assert_eq!(e.tag(), "duplicate_cell_ids");
    assert!(e.to_string().contains("dup"));
}

#[test]
fn error_missing_required() {
    let e = BundleError::MissingRequiredCells {
        missing: vec!["req-1".into()],
    };
    assert_eq!(e.tag(), "missing_required_cells");
    assert!(e.to_string().contains("req-1"));
}

#[test]
fn error_integrity_mismatch() {
    let e = BundleError::IntegrityMismatch {
        expected: ContentHash::compute(b"a"),
        actual: ContentHash::compute(b"b"),
    };
    assert_eq!(e.tag(), "integrity_mismatch");
    assert!(e.to_string().contains("integrity mismatch"));
}

#[test]
fn error_serde_roundtrip() {
    let e = BundleError::DuplicateCellIds {
        duplicates: vec!["x".into(), "y".into()],
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: BundleError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// assemble_bundle — happy paths
// ---------------------------------------------------------------------------

#[test]
fn assemble_all_green_approved() {
    let cells = vec![green_cell("a"), green_cell("b"), green_cell("c")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("bundle-1", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_approved());
    assert_eq!(bundle.cells.len(), 3);
    assert_eq!(bundle.coverage_stats.green_count, 3);
    assert_eq!(bundle.schema_version, SCHEMA_VERSION);
}

#[test]
fn assemble_single_green() {
    let cells = vec![green_cell("solo")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("single", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_approved());
    assert_eq!(bundle.coverage_stats.total_cells, 1);
}

#[test]
fn assemble_preserves_bundle_id() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("my-bundle-id", &cells, &config, epoch()).unwrap();
    assert_eq!(bundle.bundle_id, "my-bundle-id");
}

#[test]
fn assemble_preserves_epoch() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let ep = SecurityEpoch::from_raw(42);
    let bundle = assemble_bundle("ep-test", &cells, &config, ep).unwrap();
    assert_eq!(bundle.creation_epoch, ep);
}

// ---------------------------------------------------------------------------
// assemble_bundle — error paths
// ---------------------------------------------------------------------------

#[test]
fn assemble_empty_cells_error() {
    let config = BundleConfig::default();
    let err = assemble_bundle("empty", &[], &config, epoch()).unwrap_err();
    assert_eq!(err.tag(), "empty_cells");
}

#[test]
fn assemble_duplicate_cell_ids_error() {
    let cells = vec![green_cell("dup"), green_cell("dup")];
    let config = BundleConfig::permissive();
    let err = assemble_bundle("dup-bundle", &cells, &config, epoch()).unwrap_err();
    assert_eq!(err.tag(), "duplicate_cell_ids");
}

#[test]
fn assemble_missing_required_cells_error() {
    let cells = vec![green_cell("a")];
    let mut config = BundleConfig::permissive();
    config.required_cell_ids.insert("b".to_string());
    let err = assemble_bundle("miss", &cells, &config, epoch()).unwrap_err();
    assert_eq!(err.tag(), "missing_required_cells");
}

#[test]
fn assemble_multiple_missing_required() {
    let cells = vec![green_cell("a")];
    let mut config = BundleConfig::permissive();
    config.required_cell_ids.insert("b".to_string());
    config.required_cell_ids.insert("c".to_string());
    let err = assemble_bundle("miss2", &cells, &config, epoch()).unwrap_err();
    if let BundleError::MissingRequiredCells { missing } = &err {
        assert_eq!(missing.len(), 2);
    } else {
        panic!("expected MissingRequiredCells");
    }
}

// ---------------------------------------------------------------------------
// assemble_bundle — blocking verdicts
// ---------------------------------------------------------------------------

#[test]
fn assemble_red_cell_blocked() {
    let cells = vec![green_cell("a"), red_cell("b")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("red-test", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
    if let PublicationGateVerdict::Blocked { reasons } = &bundle.verdict {
        assert!(reasons.iter().any(|r| r.tag() == "red_cell"));
    }
}

#[test]
fn assemble_missing_status_blocked() {
    let cells = vec![green_cell("a"), missing_cell("b")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("missing-test", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
}

#[test]
fn assemble_unsupported_blocked() {
    let cells = vec![green_cell("a"), unsupported_cell("b")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("unsup-test", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
    if let PublicationGateVerdict::Blocked { reasons } = &bundle.verdict {
        assert!(reasons.iter().any(|r| r.tag() == "unsupported_cell"));
    }
}

#[test]
fn assemble_mode_ambiguous_blocked() {
    let cells = vec![green_cell("a"), ambiguous_cell("b")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("ambig-test", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
    if let PublicationGateVerdict::Blocked { reasons } = &bundle.verdict {
        assert!(reasons.iter().any(|r| r.tag() == "mode_ambiguous_cell"));
    }
}

#[test]
fn assemble_stale_evidence_blocked() {
    let cells = vec![stale_cell("stale-a")];
    let mut config = BundleConfig::permissive();
    config.max_staleness_epochs = 5;
    let bundle = assemble_bundle("stale-bundle", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
    if let PublicationGateVerdict::Blocked { reasons } = &bundle.verdict {
        assert!(reasons.iter().any(|r| r.tag() == "stale_evidence"));
    }
}

#[test]
fn assemble_stale_within_threshold_approved() {
    let cells = vec![stale_cell("stale-ok")];
    let mut config = BundleConfig::permissive();
    config.max_staleness_epochs = 100; // gap is 50, within threshold
    let bundle = assemble_bundle("stale-ok-bundle", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_approved());
}

#[test]
fn assemble_yellow_permissive_approved() {
    let cells = vec![green_cell("a"), yellow_cell("b")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("yellow-ok", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_approved());
}

#[test]
fn assemble_yellow_strict_insufficient_coverage() {
    let cells = vec![green_cell("a"), yellow_cell("b")];
    let mut config = BundleConfig::permissive();
    config.require_all_green = true;
    config.min_coverage_fraction_millionths = 1_000_000;
    let bundle = assemble_bundle("yellow-strict", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
}

#[test]
fn assemble_coverage_below_threshold_blocked() {
    // 1 green, 2 yellow => 33% green. With min 50%, should block.
    let cells = vec![green_cell("a"), yellow_cell("b"), yellow_cell("c")];
    let mut config = BundleConfig::permissive();
    config.min_coverage_fraction_millionths = 500_000;
    let bundle = assemble_bundle("cov-low", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
    if let PublicationGateVerdict::Blocked { reasons } = &bundle.verdict {
        assert!(reasons.iter().any(|r| r.tag() == "insufficient_coverage"));
    }
}

#[test]
fn assemble_required_cells_present_approved() {
    let cells = vec![green_cell("req-a"), green_cell("req-b")];
    let mut config = BundleConfig::permissive();
    config.required_cell_ids.insert("req-a".to_string());
    config.required_cell_ids.insert("req-b".to_string());
    let bundle = assemble_bundle("req-ok", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_approved());
}

#[test]
fn assemble_required_cells_missing_in_gate() {
    // All cells present but one required is not in the cell list via config.
    // This is caught as a BundleError, not a gate block.
    let cells = vec![green_cell("a")];
    let mut config = BundleConfig::permissive();
    config.required_cell_ids.insert("missing-req".to_string());
    let result = assemble_bundle("req-miss", &cells, &config, epoch());
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// assemble_bundle — multiple block reasons
// ---------------------------------------------------------------------------

#[test]
fn assemble_multiple_blocking_reasons() {
    let cells = vec![red_cell("r1"), missing_cell("m1"), ambiguous_cell("a1")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("multi-block", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
    if let PublicationGateVerdict::Blocked { reasons } = &bundle.verdict {
        assert!(reasons.len() >= 3);
        let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
        assert!(tags.contains("red_cell"));
        assert!(tags.contains("missing_cell"));
        assert!(tags.contains("mode_ambiguous_cell"));
    }
}

// ---------------------------------------------------------------------------
// validate_bundle_integrity
// ---------------------------------------------------------------------------

#[test]
fn integrity_valid_bundle() {
    let cells = vec![green_cell("a"), green_cell("b")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("valid", &cells, &config, epoch()).unwrap();
    assert!(validate_bundle_integrity(&bundle).is_ok());
}

#[test]
fn integrity_tampered_bundle_id() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let mut bundle = assemble_bundle("tamper-id", &cells, &config, epoch()).unwrap();
    bundle.bundle_id = "tampered".to_string();
    assert!(validate_bundle_integrity(&bundle).is_err());
}

#[test]
fn integrity_tampered_cells() {
    let cells = vec![green_cell("a"), green_cell("b")];
    let config = BundleConfig::permissive();
    let mut bundle = assemble_bundle("tamper-cells", &cells, &config, epoch()).unwrap();
    bundle.cells.push(green_cell("c"));
    assert!(validate_bundle_integrity(&bundle).is_err());
}

#[test]
fn integrity_tampered_verdict() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let mut bundle = assemble_bundle("tamper-verdict", &cells, &config, epoch()).unwrap();
    bundle.verdict = PublicationGateVerdict::Blocked {
        reasons: vec![BlockReason::IntegrityFailure {
            details: "fake".into(),
        }],
    };
    assert!(validate_bundle_integrity(&bundle).is_err());
}

#[test]
fn integrity_tampered_epoch() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let mut bundle = assemble_bundle("tamper-epoch", &cells, &config, epoch()).unwrap();
    bundle.creation_epoch = SecurityEpoch::from_raw(999);
    assert!(validate_bundle_integrity(&bundle).is_err());
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn receipt_creation_and_verify() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("rcpt-bundle", &cells, &config, epoch()).unwrap();
    let genesis = ContentHash::compute(b"genesis");
    let receipt = DecisionReceipt::new("rcpt-001", &bundle, genesis);
    assert_eq!(receipt.bundle_id, "rcpt-bundle");
    assert_eq!(receipt.verdict_tag, "approved");
    assert!(receipt.verify());
}

#[test]
fn receipt_chain_two() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let b1 = assemble_bundle("b1", &cells, &config, epoch()).unwrap();
    let b2 = assemble_bundle("b2", &cells, &config, epoch()).unwrap();

    let genesis = ContentHash::compute(b"genesis");
    let r1 = DecisionReceipt::new("r1", &b1, genesis);
    assert!(r1.verify());

    let r2 = DecisionReceipt::new("r2", &b2, r1.receipt_hash.clone());
    assert!(r2.verify());
    assert_eq!(r2.previous_receipt_hash, r1.receipt_hash);
}

#[test]
fn receipt_chain_three() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let b1 = assemble_bundle("b1", &cells, &config, epoch()).unwrap();
    let b2 = assemble_bundle("b2", &cells, &config, epoch()).unwrap();
    let b3 = assemble_bundle("b3", &cells, &config, epoch()).unwrap();

    let genesis = ContentHash::compute(b"genesis");
    let r1 = DecisionReceipt::new("r1", &b1, genesis);
    let r2 = DecisionReceipt::new("r2", &b2, r1.receipt_hash.clone());
    let r3 = DecisionReceipt::new("r3", &b3, r2.receipt_hash.clone());
    assert!(r1.verify());
    assert!(r2.verify());
    assert!(r3.verify());
    assert_eq!(r3.previous_receipt_hash, r2.receipt_hash);
}

#[test]
fn receipt_tampered_fails_verify() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("rtamp", &cells, &config, epoch()).unwrap();
    let genesis = ContentHash::compute(b"genesis");
    let mut receipt = DecisionReceipt::new("rtamp-001", &bundle, genesis);
    receipt.verdict_tag = "tampered".to_string();
    assert!(!receipt.verify());
}

#[test]
fn receipt_tampered_bundle_id_fails() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("rtamp2", &cells, &config, epoch()).unwrap();
    let genesis = ContentHash::compute(b"genesis");
    let mut receipt = DecisionReceipt::new("rtamp2-001", &bundle, genesis);
    receipt.bundle_id = "wrong-bundle".to_string();
    assert!(!receipt.verify());
}

#[test]
fn receipt_serde_roundtrip() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("rserde", &cells, &config, epoch()).unwrap();
    let genesis = ContentHash::compute(b"genesis");
    let receipt = DecisionReceipt::new("rs-001", &bundle, genesis);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn receipt_hash_deterministic() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("rdet", &cells, &config, epoch()).unwrap();
    let genesis = ContentHash::compute(b"genesis");
    let r1 = DecisionReceipt::new("rdet-001", &bundle, genesis.clone());
    let r2 = DecisionReceipt::new("rdet-001", &bundle, genesis);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

// ---------------------------------------------------------------------------
// EvidenceBundle serde
// ---------------------------------------------------------------------------

#[test]
fn bundle_serde_roundtrip_approved() {
    let cells = vec![green_cell("a"), green_cell("b")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("serde-ok", &cells, &config, epoch()).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: EvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

#[test]
fn bundle_serde_roundtrip_blocked() {
    let cells = vec![green_cell("a"), red_cell("b")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("serde-blocked", &cells, &config, epoch()).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: EvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

// ---------------------------------------------------------------------------
// Bundle hash determinism
// ---------------------------------------------------------------------------

#[test]
fn bundle_hash_deterministic() {
    let cells = vec![green_cell("a"), green_cell("b")];
    let config = BundleConfig::permissive();
    let b1 = assemble_bundle("det", &cells, &config, epoch()).unwrap();
    let b2 = assemble_bundle("det", &cells, &config, epoch()).unwrap();
    assert_eq!(b1.bundle_hash, b2.bundle_hash);
}

#[test]
fn bundle_hash_differs_by_id() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let b1 = assemble_bundle("id-1", &cells, &config, epoch()).unwrap();
    let b2 = assemble_bundle("id-2", &cells, &config, epoch()).unwrap();
    assert_ne!(b1.bundle_hash, b2.bundle_hash);
}

#[test]
fn bundle_hash_differs_by_epoch() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let b1 = assemble_bundle("ep", &cells, &config, SecurityEpoch::from_raw(1)).unwrap();
    let b2 = assemble_bundle("ep", &cells, &config, SecurityEpoch::from_raw(2)).unwrap();
    assert_ne!(b1.bundle_hash, b2.bundle_hash);
}

// ---------------------------------------------------------------------------
// Staleness edge cases
// ---------------------------------------------------------------------------

#[test]
fn staleness_exact_boundary_approved() {
    // Gap of exactly max_staleness should NOT be stale (only > is stale).
    let cells = vec![cell_at_epoch("exact", CellStatus::Green, 90)];
    let mut config = BundleConfig::permissive();
    config.max_staleness_epochs = 10; // gap is 100-90 = 10, exactly at boundary
    let bundle = assemble_bundle("exact-stale", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_approved());
}

#[test]
fn staleness_one_over_boundary_blocked() {
    let cells = vec![cell_at_epoch("over", CellStatus::Green, 89)];
    let mut config = BundleConfig::permissive();
    config.max_staleness_epochs = 10; // gap is 100-89 = 11, over boundary
    let bundle = assemble_bundle("over-stale", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
}

#[test]
fn staleness_future_epoch_not_stale() {
    // Evidence epoch in the future (should not happen but shouldn't flag stale).
    let cells = vec![cell_at_epoch("future", CellStatus::Green, 200)];
    let mut config = BundleConfig::permissive();
    config.max_staleness_epochs = 5;
    let bundle = assemble_bundle("future-ep", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_approved());
}

// ---------------------------------------------------------------------------
// Fail-closed semantics
// ---------------------------------------------------------------------------

#[test]
fn fail_closed_every_blocking_status() {
    for status in CellStatus::ALL {
        if status.blocks_strict() {
            let cell = CellEvidence {
                cell_id: format!("cell-{}", status.as_str()),
                status: *status,
                verdict_hash: ContentHash::compute(status.as_str().as_bytes()),
                observation_count: 10,
                effect_size_millionths: 0,
                observability_mode: ObservabilityMode::BudgetedCapture,
                evidence_epoch: SecurityEpoch::from_raw(100),
            };
            let cells = vec![cell];
            let config = BundleConfig::permissive();
            let bundle = assemble_bundle(
                format!("fail-closed-{}", status.as_str()),
                &cells,
                &config,
                epoch(),
            )
            .unwrap();
            assert!(
                bundle.verdict.is_blocked(),
                "expected blocked for status {}",
                status
            );
        }
    }
}
