//! Enrichment integration tests for `supremacy_evidence_bundle` module.
//!
//! Tests advanced edge cases, multi-cell interactions, integrity chains,
//! config combinations, boundary conditions, and fail-closed semantics.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
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
// 1. CellEvidence hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrich_cell_evidence_hash_varies_with_observation_count() {
    let mut c1 = green_cell("x");
    let mut c2 = green_cell("x");
    c1.observation_count = 100;
    c2.observation_count = 200;
    assert_ne!(c1.compute_hash(), c2.compute_hash());
}

#[test]
fn enrich_cell_evidence_hash_varies_with_effect_size() {
    let mut c1 = green_cell("x");
    let mut c2 = green_cell("x");
    c1.effect_size_millionths = 100_000;
    c2.effect_size_millionths = 200_000;
    assert_ne!(c1.compute_hash(), c2.compute_hash());
}

#[test]
fn enrich_cell_evidence_hash_varies_with_observability_mode() {
    let mut c1 = green_cell("x");
    let mut c2 = green_cell("x");
    c1.observability_mode = ObservabilityMode::BudgetedCapture;
    c2.observability_mode = ObservabilityMode::ExactShadow;
    assert_ne!(c1.compute_hash(), c2.compute_hash());
}

#[test]
fn enrich_cell_evidence_hash_varies_with_epoch() {
    let mut c1 = green_cell("x");
    let mut c2 = green_cell("x");
    c1.evidence_epoch = SecurityEpoch::from_raw(10);
    c2.evidence_epoch = SecurityEpoch::from_raw(20);
    assert_ne!(c1.compute_hash(), c2.compute_hash());
}

// ---------------------------------------------------------------------------
// 2. Coverage edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_coverage_all_yellow_zero_green_fraction() {
    let cells = vec![yellow_cell("a"), yellow_cell("b"), yellow_cell("c")];
    let stats = compute_coverage_stats(&cells);
    assert_eq!(stats.green_count, 0);
    assert_eq!(stats.yellow_count, 3);
    assert_eq!(stats.coverage_fraction_millionths, 0);
    assert!(!stats.all_green());
    assert!(!stats.has_blocking_cells());
}

#[test]
fn enrich_coverage_all_unsupported_has_blocking() {
    let cells = vec![unsupported_cell("a"), unsupported_cell("b")];
    let stats = compute_coverage_stats(&cells);
    assert_eq!(stats.unsupported_count, 2);
    assert!(stats.has_blocking_cells());
}

#[test]
fn enrich_coverage_all_mode_ambiguous_has_blocking() {
    let cells = vec![ambiguous_cell("a"), ambiguous_cell("b")];
    let stats = compute_coverage_stats(&cells);
    assert_eq!(stats.mode_ambiguous_count, 2);
    assert!(stats.has_blocking_cells());
}

#[test]
fn enrich_coverage_single_green_is_100_percent() {
    let cells = vec![green_cell("sole")];
    let stats = compute_coverage_stats(&cells);
    assert_eq!(stats.coverage_fraction_millionths, 1_000_000);
    assert!(stats.all_green());
}

// ---------------------------------------------------------------------------
// 3. Config with required cells
// ---------------------------------------------------------------------------

#[test]
fn enrich_config_required_cells_all_present_subset() {
    let cells = vec![green_cell("a"), green_cell("b"), green_cell("c")];
    let mut config = BundleConfig::permissive();
    config.required_cell_ids.insert("a".to_string());
    config.required_cell_ids.insert("b".to_string());
    let bundle = assemble_bundle("req-subset", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_approved());
}

#[test]
fn enrich_config_required_cells_one_missing_error() {
    let cells = vec![green_cell("a"), green_cell("b")];
    let mut config = BundleConfig::permissive();
    config.required_cell_ids.insert("a".to_string());
    config.required_cell_ids.insert("c".to_string());
    let err = assemble_bundle("req-miss-one", &cells, &config, epoch()).unwrap_err();
    if let BundleError::MissingRequiredCells { missing } = &err {
        assert_eq!(missing.len(), 1);
        assert!(missing.contains(&"c".to_string()));
    } else {
        panic!("expected MissingRequiredCells, got {:?}", err);
    }
}

// ---------------------------------------------------------------------------
// 4. Multi-blocking-reason accumulation
// ---------------------------------------------------------------------------

#[test]
fn enrich_assemble_accumulates_all_blocking_reason_types() {
    let cells = vec![
        red_cell("r1"),
        missing_cell("m1"),
        unsupported_cell("u1"),
        ambiguous_cell("a1"),
    ];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("multi-all", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
    if let PublicationGateVerdict::Blocked { reasons } = &bundle.verdict {
        let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
        assert!(tags.contains("red_cell"));
        assert!(tags.contains("missing_cell"));
        assert!(tags.contains("unsupported_cell"));
        assert!(tags.contains("mode_ambiguous_cell"));
    }
}

#[test]
fn enrich_assemble_stale_plus_red_yields_multiple_reasons() {
    let cells = vec![
        red_cell("r"),
        cell_at_epoch("stale-g", CellStatus::Green, 50),
    ];
    let mut config = BundleConfig::permissive();
    config.max_staleness_epochs = 5;
    let bundle = assemble_bundle("stale-red", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
    if let PublicationGateVerdict::Blocked { reasons } = &bundle.verdict {
        let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
        assert!(tags.contains("red_cell"));
        assert!(tags.contains("stale_evidence"));
    }
}

// ---------------------------------------------------------------------------
// 5. Strict mode
// ---------------------------------------------------------------------------

#[test]
fn enrich_strict_mode_only_green_approved() {
    let cells = vec![green_cell("a"), green_cell("b")];
    let config = BundleConfig::default();
    let bundle = assemble_bundle("strict-ok", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_approved());
}

#[test]
fn enrich_strict_mode_yellow_blocks_with_full_coverage_requirement() {
    let cells = vec![green_cell("a"), yellow_cell("b")];
    let config = BundleConfig::default();
    let bundle = assemble_bundle("strict-yellow", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
}

// ---------------------------------------------------------------------------
// 6. Integrity validation after field mutation
// ---------------------------------------------------------------------------

#[test]
fn enrich_integrity_swapped_cell_order_fails() {
    let cells = vec![green_cell("a"), green_cell("b")];
    let config = BundleConfig::permissive();
    let mut bundle = assemble_bundle("swap-order", &cells, &config, epoch()).unwrap();
    if bundle.cells.len() == 2 {
        bundle.cells.swap(0, 1);
    }
    assert!(validate_bundle_integrity(&bundle).is_err());
}

#[test]
fn enrich_integrity_modified_coverage_fraction_fails() {
    let cells = vec![green_cell("a"), green_cell("b")];
    let config = BundleConfig::permissive();
    let mut bundle = assemble_bundle("tamper-cov", &cells, &config, epoch()).unwrap();
    // coverage_fraction_millionths is part of the bundle hash
    bundle.coverage_stats.coverage_fraction_millionths = 999_999;
    assert!(validate_bundle_integrity(&bundle).is_err());
}

// ---------------------------------------------------------------------------
// 7. Receipt chain integrity
// ---------------------------------------------------------------------------

#[test]
fn enrich_receipt_chain_five_deep_all_verify() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let genesis = ContentHash::compute(b"genesis");
    let mut prev_hash = genesis;
    for i in 0..5 {
        let bid = format!("b{i}");
        let bundle = assemble_bundle(&bid, &cells, &config, epoch()).unwrap();
        let rid = format!("r{i}");
        let receipt = DecisionReceipt::new(&rid, &bundle, prev_hash);
        assert!(receipt.verify(), "receipt {rid} should verify");
        prev_hash = receipt.receipt_hash;
    }
}

#[test]
fn enrich_receipt_tampered_previous_hash_fails() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("rcpt-test", &cells, &config, epoch()).unwrap();
    let genesis = ContentHash::compute(b"genesis");
    let mut receipt = DecisionReceipt::new("r1", &bundle, genesis);
    receipt.previous_receipt_hash = ContentHash::compute(b"wrong");
    assert!(!receipt.verify());
}

#[test]
fn enrich_receipt_tampered_receipt_id_fails() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("rid-test", &cells, &config, epoch()).unwrap();
    let genesis = ContentHash::compute(b"genesis");
    let mut receipt = DecisionReceipt::new("original", &bundle, genesis);
    receipt.receipt_id = "tampered-id".to_string();
    assert!(!receipt.verify());
}

// ---------------------------------------------------------------------------
// 8. Bundle serde with complex blocked verdict
// ---------------------------------------------------------------------------

#[test]
fn enrich_bundle_serde_complex_blocked() {
    let cells = vec![
        green_cell("g1"),
        red_cell("r1"),
        yellow_cell("y1"),
        missing_cell("m1"),
    ];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("serde-complex", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
    let json = serde_json::to_string(&bundle).unwrap();
    let back: EvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

// ---------------------------------------------------------------------------
// 9. Block reasons serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_block_reason_all_variants_serde_roundtrip() {
    let reasons = vec![
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
            coverage_fraction_millionths: 500_000,
            required_millionths: 1_000_000,
        },
        BlockReason::StaleEvidence {
            cell_id: "e".into(),
            evidence_epoch: 10,
            current_epoch: 100,
            max_staleness: 5,
        },
        BlockReason::IntegrityFailure {
            details: "bad hash".into(),
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: BlockReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// 10. Epoch zero edge case
// ---------------------------------------------------------------------------

#[test]
fn enrich_assemble_at_epoch_zero() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("ep0", &cells, &config, SecurityEpoch::from_raw(0)).unwrap();
    assert!(bundle.verdict.is_approved());
    assert_eq!(bundle.creation_epoch, SecurityEpoch::from_raw(0));
}

// ---------------------------------------------------------------------------
// 11. Verdict blocked empty reasons
// ---------------------------------------------------------------------------

#[test]
fn enrich_verdict_blocked_empty_reasons() {
    let v = PublicationGateVerdict::Blocked { reasons: vec![] };
    assert!(v.is_blocked());
    assert_eq!(v.block_count(), 0);
}

// ---------------------------------------------------------------------------
// 12. Large observation count
// ---------------------------------------------------------------------------

#[test]
fn enrich_cell_evidence_large_observation_count() {
    let mut c = green_cell("big-obs");
    c.observation_count = u64::MAX;
    c.effect_size_millionths = u64::MAX;
    let hash = c.compute_hash();
    assert_ne!(hash.as_bytes(), &[0u8; 32]);
}

// ---------------------------------------------------------------------------
// 13. Bundle error tags unique
// ---------------------------------------------------------------------------

#[test]
fn enrich_bundle_error_all_tags_unique() {
    let errors: Vec<BundleError> = vec![
        BundleError::EmptyCells,
        BundleError::TooManyCells {
            count: 600,
            max: 512,
        },
        BundleError::DuplicateCellIds {
            duplicates: vec!["x".into()],
        },
        BundleError::MissingRequiredCells {
            missing: vec!["y".into()],
        },
        BundleError::IntegrityMismatch {
            expected: ContentHash::compute(b"a"),
            actual: ContentHash::compute(b"b"),
        },
    ];
    let tags: BTreeSet<&str> = errors.iter().map(|e| e.tag()).collect();
    assert_eq!(tags.len(), 5);
}

// ---------------------------------------------------------------------------
// 14. Staleness with same epoch
// ---------------------------------------------------------------------------

#[test]
fn enrich_staleness_zero_gap_approved() {
    let cells = vec![cell_at_epoch("same", CellStatus::Green, 100)];
    let mut config = BundleConfig::permissive();
    config.max_staleness_epochs = 0;
    let bundle = assemble_bundle("zero-gap", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_approved());
}

// ---------------------------------------------------------------------------
// 15. Bundle hash differs by cell count
// ---------------------------------------------------------------------------

#[test]
fn enrich_bundle_hash_differs_by_cell_count() {
    let config = BundleConfig::permissive();
    let b1 = assemble_bundle("same-id", &[green_cell("a")], &config, epoch()).unwrap();
    let b2 = assemble_bundle(
        "same-id",
        &[green_cell("a"), green_cell("b")],
        &config,
        epoch(),
    )
    .unwrap();
    assert_ne!(b1.bundle_hash, b2.bundle_hash);
}

// ---------------------------------------------------------------------------
// 16. Status classification matrix
// ---------------------------------------------------------------------------

#[test]
fn enrich_cell_status_safe_vs_strict_disjoint() {
    for s in CellStatus::ALL {
        if s.is_publication_safe() {
            assert!(
                !s.blocks_strict(),
                "status {s} should not be both safe and blocking"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 17. ObservabilityMode rigorous count
// ---------------------------------------------------------------------------

#[test]
fn enrich_obs_mode_rigorous_count() {
    let rigorous = ObservabilityMode::ALL
        .iter()
        .filter(|m| m.is_rigorous())
        .count();
    let non_rigorous = ObservabilityMode::ALL
        .iter()
        .filter(|m| !m.is_rigorous())
        .count();
    assert_eq!(rigorous, 2);
    assert_eq!(non_rigorous, 2);
}

// ---------------------------------------------------------------------------
// 18. All six statuses bundle
// ---------------------------------------------------------------------------

#[test]
fn enrich_assemble_all_six_statuses_blocked() {
    let cells = vec![
        green_cell("g"),
        red_cell("r"),
        yellow_cell("y"),
        missing_cell("m"),
        unsupported_cell("u"),
        ambiguous_cell("a"),
    ];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("all-six", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_blocked());
    assert_eq!(bundle.cells.len(), 6);
}

// ---------------------------------------------------------------------------
// 19. Receipt on blocked bundle
// ---------------------------------------------------------------------------

#[test]
fn enrich_receipt_on_blocked_bundle_has_blocked_tag() {
    let cells = vec![red_cell("r")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("blocked-rcpt", &cells, &config, epoch()).unwrap();
    let genesis = ContentHash::compute(b"genesis");
    let receipt = DecisionReceipt::new("r-blocked", &bundle, genesis);
    assert_eq!(receipt.verdict_tag, "blocked");
    assert!(receipt.verify());
}

// ---------------------------------------------------------------------------
// 20. Coverage stats serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_coverage_stats_serde_roundtrip() {
    let cells = vec![green_cell("a"), red_cell("b"), yellow_cell("c")];
    let stats = compute_coverage_stats(&cells);
    let json = serde_json::to_string(&stats).unwrap();
    let back: CoverageStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, back);
}

// ---------------------------------------------------------------------------
// 21. BundleConfig serde with required cells
// ---------------------------------------------------------------------------

#[test]
fn enrich_config_serde_with_multiple_required() {
    let mut config = BundleConfig::default();
    for i in 0..10 {
        config.required_cell_ids.insert(format!("cell-{i}"));
    }
    let json = serde_json::to_string(&config).unwrap();
    let back: BundleConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
    assert_eq!(back.required_cell_ids.len(), 10);
}

// ---------------------------------------------------------------------------
// 22. BundleError display non-empty
// ---------------------------------------------------------------------------

#[test]
fn enrich_bundle_error_display_all_non_empty() {
    let errors: Vec<BundleError> = vec![
        BundleError::EmptyCells,
        BundleError::TooManyCells {
            count: 1000,
            max: 512,
        },
        BundleError::DuplicateCellIds {
            duplicates: vec!["x".into()],
        },
        BundleError::MissingRequiredCells {
            missing: vec!["y".into()],
        },
        BundleError::IntegrityMismatch {
            expected: ContentHash::compute(b"a"),
            actual: ContentHash::compute(b"b"),
        },
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// 23. Determinism across three calls
// ---------------------------------------------------------------------------

#[test]
fn enrich_assemble_bundle_deterministic_across_three_calls() {
    let cells = vec![green_cell("a"), green_cell("b"), green_cell("c")];
    let config = BundleConfig::permissive();
    let h1 = assemble_bundle("det3", &cells, &config, epoch())
        .unwrap()
        .bundle_hash;
    let h2 = assemble_bundle("det3", &cells, &config, epoch())
        .unwrap()
        .bundle_hash;
    let h3 = assemble_bundle("det3", &cells, &config, epoch())
        .unwrap()
        .bundle_hash;
    assert_eq!(h1, h2);
    assert_eq!(h2, h3);
}

// ---------------------------------------------------------------------------
// 24. Strict config coverage threshold met
// ---------------------------------------------------------------------------

#[test]
fn enrich_strict_config_coverage_threshold_met_approved() {
    let cells = vec![green_cell("a"), green_cell("b"), yellow_cell("c")];
    let mut config = BundleConfig::permissive();
    config.require_all_green = true;
    config.min_coverage_fraction_millionths = 500_000;
    let bundle = assemble_bundle("thresh-met", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_approved());
}

// ---------------------------------------------------------------------------
// 25. Receipt epoch matches bundle epoch
// ---------------------------------------------------------------------------

#[test]
fn enrich_receipt_epoch_matches_bundle_creation_epoch() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let ep = SecurityEpoch::from_raw(42);
    let bundle = assemble_bundle("ep-match", &cells, &config, ep).unwrap();
    let genesis = ContentHash::compute(b"genesis");
    let receipt = DecisionReceipt::new("rm", &bundle, genesis);
    assert_eq!(receipt.epoch, ep);
}

// ---------------------------------------------------------------------------
// 26. Many cells
// ---------------------------------------------------------------------------

#[test]
fn enrich_assemble_many_green_cells_approved() {
    let cells: Vec<CellEvidence> = (0..100).map(|i| green_cell(&format!("cell-{i}"))).collect();
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("many-cells", &cells, &config, epoch()).unwrap();
    assert!(bundle.verdict.is_approved());
    assert_eq!(bundle.cells.len(), 100);
}

// ---------------------------------------------------------------------------
// 27. Triple duplicate
// ---------------------------------------------------------------------------

#[test]
fn enrich_assemble_triple_duplicate_error() {
    let cells = vec![green_cell("dup"), green_cell("dup"), green_cell("dup")];
    let config = BundleConfig::permissive();
    let err = assemble_bundle("triple-dup", &cells, &config, epoch()).unwrap_err();
    assert_eq!(err.tag(), "duplicate_cell_ids");
}

// ---------------------------------------------------------------------------
// 28. Verdict Display with multiple reasons
// ---------------------------------------------------------------------------

#[test]
fn enrich_verdict_display_blocked_reasons_count() {
    let v = PublicationGateVerdict::Blocked {
        reasons: vec![
            BlockReason::RedCell {
                cell_id: "a".into(),
            },
            BlockReason::RedCell {
                cell_id: "b".into(),
            },
            BlockReason::RedCell {
                cell_id: "c".into(),
            },
        ],
    };
    let s = v.to_string();
    assert!(s.contains("3 reason(s)"));
}

// ---------------------------------------------------------------------------
// 29. Receipt hash differs for different bundles
// ---------------------------------------------------------------------------

#[test]
fn enrich_receipt_hash_differs_for_different_bundles() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let b1 = assemble_bundle("b-1", &cells, &config, epoch()).unwrap();
    let b2 = assemble_bundle("b-2", &cells, &config, epoch()).unwrap();
    let genesis = ContentHash::compute(b"genesis");
    let r1 = DecisionReceipt::new("r1", &b1, genesis);
    let r2 = DecisionReceipt::new("r2", &b2, genesis);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

// ---------------------------------------------------------------------------
// 30. EvidenceBundle Debug
// ---------------------------------------------------------------------------

#[test]
fn enrich_evidence_bundle_debug_not_empty() {
    let cells = vec![green_cell("a")];
    let config = BundleConfig::permissive();
    let bundle = assemble_bundle("dbg", &cells, &config, epoch()).unwrap();
    let dbg = format!("{:?}", bundle);
    assert!(dbg.contains("EvidenceBundle"));
}
