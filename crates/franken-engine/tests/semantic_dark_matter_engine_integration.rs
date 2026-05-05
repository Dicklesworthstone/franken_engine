//! Integration tests for semantic_dark_matter_engine (RGC-707).

use frankenengine_engine::dark_matter_saturation_gate::{
    BoardState, DARK_MATTER_GATE_SCHEMA_VERSION, DarkMatterRegion, DarkMatterRegionKind,
    RatchetWideningReason, SaturationReason,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::novelty_scoring_contract::{
    CandidateKind, DimensionWeight, NoveltyCandidate, NoveltyDimension, ScoringConfig, score_batch,
};
use frankenengine_engine::novelty_synthesis_engine::franken_engine_synthesis_manifest;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::semantic_dark_matter_engine::{
    DarkMatterEngineConfig, DarkMatterEngineError, DarkMatterEngineOrchestrator,
    DarkMatterSpecimenFamily, DarkMatterVerdict, RegionUpdateAction,
    SynthesizedCandidateDenialReason, dark_matter_corpus, run_dark_matter_corpus,
};

const MILLION: u64 = 1_000_000;

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn candidate(id: &str, kind: CandidateKind, desc_len: u64) -> NoveltyCandidate {
    NoveltyCandidate {
        candidate_id: id.to_string(),
        kind,
        description_length_bits: desc_len,
        feature_vector: vec![desc_len; 4],
        source_hash: ContentHash::compute(id.as_bytes()),
    }
}

fn candidate_with_features(
    id: &str,
    kind: CandidateKind,
    desc_len: u64,
    feature_vector: Vec<u64>,
) -> NoveltyCandidate {
    NoveltyCandidate {
        candidate_id: id.to_string(),
        kind,
        description_length_bits: desc_len,
        feature_vector,
        source_hash: ContentHash::compute(id.as_bytes()),
    }
}

fn expected_cycle_metrics(
    config: &DarkMatterEngineConfig,
    candidates: &[NoveltyCandidate],
) -> (usize, usize, u64, u64) {
    let batch = score_batch(candidates, &config.scoring_config);
    let mut promoted = 0usize;
    let mut rejected = 0usize;
    let mut max_novelty = 0u64;
    let mut sum_novelty = 0u64;

    for certificate in &batch.certificates {
        let score = certificate.score.total_score_millionths;
        sum_novelty = sum_novelty.saturating_add(score);
        max_novelty = max_novelty.max(score);
        if score >= config.promotion_threshold_millionths
            && promoted < config.max_promotions_per_cycle
        {
            promoted += 1;
        } else {
            rejected += 1;
        }
    }

    let avg_novelty = if candidates.is_empty() {
        0
    } else {
        sum_novelty / candidates.len() as u64
    };

    (promoted, rejected, max_novelty, avg_novelty)
}

// --- Construction ---

#[test]
fn test_construction_defaults() {
    let engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let summary = engine.summary();
    assert_eq!(summary.total_cycles, 0);
    assert_eq!(summary.total_candidates, 0);
}

#[test]
fn test_custom_config() {
    let config = DarkMatterEngineConfig {
        promotion_threshold_millionths: 300_000,
        max_promotions_per_cycle: 5,
        ..DarkMatterEngineConfig::default()
    };
    let engine = DarkMatterEngineOrchestrator::new(test_epoch(), config);
    assert_eq!(engine.summary().total_cycles, 0);
}

// --- Discovery ---

#[test]
fn test_discover_single_candidate() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let result = engine
        .discover(&[candidate("c1", CandidateKind::Program, 800_000)])
        .unwrap();
    assert_eq!(result.seq, 1);
    assert_eq!(result.candidates_evaluated, 1);
}

#[test]
fn test_discover_empty_error() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    assert!(matches!(
        engine.discover(&[]),
        Err(DarkMatterEngineError::NoCandidates)
    ));
}

#[test]
fn test_discover_mixed_candidates() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let candidates = vec![
        candidate("high", CandidateKind::Program, 900_000),
        candidate("low", CandidateKind::Package, 100_000),
        candidate("mid", CandidateKind::ReactComponent, 500_000),
    ];
    let result = engine.discover(&candidates).unwrap();
    let (promoted, rejected, _, _) = expected_cycle_metrics(&engine.config, &candidates);
    assert_eq!(result.candidates_evaluated, 3);
    assert_eq!(result.candidates_promoted, promoted);
    assert_eq!(result.candidates_rejected, rejected);
}

#[test]
fn test_discover_all_promoted() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let candidates = vec![
        candidate("h1", CandidateKind::Program, 900_000),
        candidate("h2", CandidateKind::Package, 800_000),
    ];
    let result = engine.discover(&candidates).unwrap();
    let (promoted, rejected, _, _) = expected_cycle_metrics(&engine.config, &candidates);
    assert_eq!(result.candidates_promoted, promoted);
    assert_eq!(result.candidates_rejected, rejected);
}

#[test]
fn test_discover_all_rejected() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let candidates = vec![
        candidate("l1", CandidateKind::Program, 100_000),
        candidate("l2", CandidateKind::Program, 200_000),
    ];
    let result = engine.discover(&candidates).unwrap();
    let (promoted, rejected, _, _) = expected_cycle_metrics(&engine.config, &candidates);
    assert_eq!(result.candidates_promoted, promoted);
    assert_eq!(result.candidates_rejected, rejected);
}

#[test]
fn test_max_novelty() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let candidates = vec![
        candidate("a", CandidateKind::Program, 300_000),
        candidate("b", CandidateKind::Program, 700_000),
        candidate("c", CandidateKind::Program, 500_000),
    ];
    let result = engine.discover(&candidates).unwrap();
    let (_, _, max_novelty, _) = expected_cycle_metrics(&engine.config, &candidates);
    assert_eq!(result.max_novelty_millionths, max_novelty);
}

#[test]
fn test_avg_novelty() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let candidates = vec![
        candidate("a", CandidateKind::Program, 300_000),
        candidate("b", CandidateKind::Program, 600_000),
        candidate("c", CandidateKind::Program, 900_000),
    ];
    let result = engine.discover(&candidates).unwrap();
    let (_, _, _, avg_novelty) = expected_cycle_metrics(&engine.config, &candidates);
    assert_eq!(result.avg_novelty_millionths, avg_novelty);
}

// --- Multiple cycles ---

#[test]
fn test_multiple_cycles() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let _ = engine.discover(&[candidate("c1", CandidateKind::Program, 800_000)]);
    let _ = engine.discover(&[candidate("c2", CandidateKind::Package, 200_000)]);
    let _ = engine.discover(&[candidate("c3", CandidateKind::Program, 600_000)]);
    let summary = engine.summary();
    assert_eq!(summary.total_cycles, 3);
    assert_eq!(summary.total_candidates, 3);
}

#[test]
fn test_seq_increments() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let r1 = engine
        .discover(&[candidate("c1", CandidateKind::Program, 800_000)])
        .unwrap();
    let r2 = engine
        .discover(&[candidate("c2", CandidateKind::Program, 800_000)])
        .unwrap();
    assert_eq!(r1.seq, 1);
    assert_eq!(r2.seq, 2);
}

#[test]
fn test_discover_emits_mixed_synthesized_candidate_receipts_and_region_updates() {
    let mut engine = DarkMatterEngineOrchestrator::new(
        test_epoch(),
        DarkMatterEngineConfig {
            promotion_threshold_millionths: 850_000,
            max_promotions_per_cycle: 2,
            ..DarkMatterEngineConfig::default()
        },
    );
    let result = engine
        .discover(&[candidate("explicit-high", CandidateKind::Program, 900_000)])
        .expect("discovery should succeed");

    let synthesis_receipt = result
        .synthesis_receipt
        .as_ref()
        .expect("synthesis receipt should be present");
    assert_eq!(
        synthesis_receipt.candidates_proposed as usize,
        result.synthesized_candidate_receipts.len()
    );
    assert!(synthesis_receipt.candidates_accepted > 0);
    assert!(synthesis_receipt.candidates_denied > 0);

    let accepted = result
        .synthesized_candidate_receipts
        .iter()
        .filter(|receipt| receipt.accepted)
        .count();
    let denied = result
        .synthesized_candidate_receipts
        .iter()
        .filter(|receipt| !receipt.accepted)
        .count();
    assert!(accepted > 0);
    assert!(denied > 0);
    assert!(
        result
            .synthesized_candidate_receipts
            .iter()
            .any(|receipt| matches!(
                receipt.denial_reason,
                Some(SynthesizedCandidateDenialReason::PromotionCapReached)
            )),
        "expected at least one synthesized candidate denied by promotion cap"
    );
    assert!(
        result
            .synthesized_candidate_receipts
            .iter()
            .any(|receipt| matches!(
                receipt.denial_reason,
                Some(SynthesizedCandidateDenialReason::Filter(_))
            )),
        "expected at least one synthesized candidate denied by synthesis filtering"
    );
    assert!(
        result
            .region_update_receipts
            .iter()
            .any(|receipt| receipt.action == RegionUpdateAction::Retired)
    );
    assert!(
        result
            .region_update_receipts
            .iter()
            .any(|receipt| receipt.action == RegionUpdateAction::Activated)
    );
    assert!(engine.regions().iter().any(|region| {
        region
            .region_id
            .starts_with("semantic_dark_matter_synthesis::")
            && region.retired
    }));
    assert!(engine.regions().iter().any(|region| {
        region
            .region_id
            .starts_with("semantic_dark_matter_synthesis::")
            && !region.retired
    }));
}

#[test]
fn test_discover_emits_composed_saturation_gate_receipt() {
    let mut engine = DarkMatterEngineOrchestrator::new(
        test_epoch(),
        DarkMatterEngineConfig {
            promotion_threshold_millionths: 850_000,
            max_promotions_per_cycle: 2,
            ..DarkMatterEngineConfig::default()
        },
    );
    let result = engine
        .discover(&[candidate("explicit-high", CandidateKind::Program, 900_000)])
        .expect("discovery should succeed");

    let receipt = result
        .board_state_receipt
        .as_ref()
        .expect("board-state receipt should be present");
    assert_eq!(receipt.schema_version, DARK_MATTER_GATE_SCHEMA_VERSION);
    assert_eq!(receipt.composite_state, BoardState::ScopeLimited);
    assert_eq!(engine.board_state(), &BoardState::ScopeLimited);
    assert_eq!(receipt.saturation_verdict.observation_count, 1);
    assert!(
        receipt.saturation_verdict.dark_matter_fraction_millionths > 0,
        "synthesized region updates should feed a non-zero dark-matter estimate"
    );
    assert!(
        receipt
            .saturation_verdict
            .reasons
            .iter()
            .any(|reason| matches!(
                reason,
                SaturationReason::InsufficientObservations { count: 1, .. }
            )),
        "composed receipt should carry the saturation-gate insufficient-observations reason"
    );
    assert!(
        receipt.freshness_verdict.is_fresh,
        "the same-cycle receipt should stay fresh"
    );
    assert!(!receipt.ratchet_widening_verdict.permitted);
    assert_eq!(
        receipt.ratchet_widening_verdict.reason,
        RatchetWideningReason::InsufficientData
    );
}

#[test]
fn test_discover_synthesis_artifacts_are_deterministic() {
    let config = DarkMatterEngineConfig {
        promotion_threshold_millionths: 850_000,
        max_promotions_per_cycle: 2,
        ..DarkMatterEngineConfig::default()
    };
    let candidates = [candidate("explicit-high", CandidateKind::Program, 900_000)];
    let mut first = DarkMatterEngineOrchestrator::new(test_epoch(), config.clone());
    let mut second = DarkMatterEngineOrchestrator::new(test_epoch(), config);

    let first_result = first
        .discover(&candidates)
        .expect("first discovery should succeed");
    let second_result = second
        .discover(&candidates)
        .expect("second discovery should succeed");

    let manifest_hash = franken_engine_synthesis_manifest().content_hash();
    assert_eq!(
        first_result
            .synthesis_receipt
            .as_ref()
            .expect("synthesis receipt should be present")
            .manifest_hash,
        manifest_hash
    );
    assert_eq!(
        first_result.synthesis_receipt,
        second_result.synthesis_receipt
    );
    assert_eq!(
        first_result.synthesized_candidate_receipts,
        second_result.synthesized_candidate_receipts
    );
    assert_eq!(
        first_result.region_update_receipts,
        second_result.region_update_receipts
    );
    assert_eq!(first_result.content_hash, second_result.content_hash);
}

// --- Summary ---

#[test]
fn test_summary_initial() {
    let engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let s = engine.summary();
    assert_eq!(s.total_cycles, 0);
    assert_eq!(s.total_promoted, 0);
    assert_eq!(s.total_rejected, 0);
}

#[test]
fn test_summary_after_discover() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let candidates = [candidate("x", CandidateKind::Program, 800_000)];
    let _ = engine.discover(&candidates);
    let s = engine.summary();
    let (promoted, rejected, _, _) = expected_cycle_metrics(&engine.config, &candidates);
    assert_eq!(s.total_cycles, 1);
    assert_eq!(s.total_candidates, 1);
    assert_eq!(s.total_promoted, promoted as u64);
    assert_eq!(s.total_rejected, rejected as u64);
}

#[test]
fn test_summary_hash_deterministic() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let _ = engine.discover(&[candidate("x", CandidateKind::Program, 800_000)]);
    let s1 = engine.summary();
    let s2 = engine.summary();
    assert_eq!(s1.content_hash, s2.content_hash);
}

// --- Regions ---

#[test]
fn test_add_region() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    engine.add_region(DarkMatterRegion {
        region_id: "r1".to_string(),
        kind: DarkMatterRegionKind::UntestedCodePath,
        mass_millionths: 200_000,
        retired: false,
        discovered_at_epoch_secs: 0,
        retired_at_epoch_secs: None,
        priority_weight_millionths: MILLION,
    });
    assert_eq!(engine.regions().len(), 1);
}

#[test]
fn test_multiple_regions() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    for i in 0..3 {
        engine.add_region(DarkMatterRegion {
            region_id: format!("r{i}"),
            kind: DarkMatterRegionKind::UnobservedInteraction,
            mass_millionths: 100_000,
            retired: false,
            discovered_at_epoch_secs: 0,
            retired_at_epoch_secs: None,
            priority_weight_millionths: MILLION,
        });
    }
    assert_eq!(engine.regions().len(), 3);
}

// --- History ---

#[test]
fn test_history_recorded() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let _ = engine.discover(&[candidate("x", CandidateKind::Program, 800_000)]);
    assert_eq!(engine.history().len(), 1);
}

#[test]
fn test_history_bounded() {
    let config = DarkMatterEngineConfig {
        max_history: 2,
        ..DarkMatterEngineConfig::default()
    };
    let mut engine = DarkMatterEngineOrchestrator::new(test_epoch(), config);
    for i in 0..5 {
        let _ = engine.discover(&[candidate(&format!("c{i}"), CandidateKind::Program, 800_000)]);
    }
    assert!(engine.history().len() <= 2);
}

// --- Reset ---

#[test]
fn test_reset_clears() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let _ = engine.discover(&[candidate("x", CandidateKind::Program, 800_000)]);
    engine.add_region(DarkMatterRegion {
        region_id: "r1".to_string(),
        kind: DarkMatterRegionKind::UntestedCodePath,
        mass_millionths: 200_000,
        retired: false,
        discovered_at_epoch_secs: 0,
        retired_at_epoch_secs: None,
        priority_weight_millionths: MILLION,
    });
    engine.reset(SecurityEpoch::from_raw(2));
    assert_eq!(engine.summary().total_cycles, 0);
    assert!(engine.history().is_empty());
    assert!(engine.regions().is_empty());
}

#[test]
fn test_reset_allows_reuse() {
    let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
    let _ = engine.discover(&[candidate("x", CandidateKind::Program, 800_000)]);
    engine.reset(SecurityEpoch::from_raw(2));
    let r = engine
        .discover(&[candidate("y", CandidateKind::Program, 800_000)])
        .unwrap();
    assert_eq!(r.seq, 1);
}

// --- Error display ---

#[test]
fn test_error_display() {
    assert!(format!("{}", DarkMatterEngineError::NoCandidates).contains("no candidates"));
    assert!(format!("{}", DarkMatterEngineError::BoardNotInitialized).contains("not initialized"));
    assert!(
        format!(
            "{}",
            DarkMatterEngineError::ConfigError {
                detail: "bad".to_string()
            }
        )
        .contains("bad")
    );
}

// --- Evidence corpus ---

#[test]
fn test_corpus_all_pass() {
    let inv = run_dark_matter_corpus();
    for e in &inv.evidences {
        assert_eq!(
            e.verdict,
            DarkMatterVerdict::Pass,
            "failed: {} - {}",
            e.specimen_id,
            e.details
        );
    }
}

#[test]
fn test_corpus_covers_families() {
    let corpus = dark_matter_corpus();
    for family in DarkMatterSpecimenFamily::ALL {
        assert!(
            corpus.iter().any(|s| s.family == *family),
            "missing: {family:?}"
        );
    }
}

#[test]
fn test_corpus_deterministic() {
    let i1 = run_dark_matter_corpus();
    let i2 = run_dark_matter_corpus();
    assert_eq!(i1.inventory_hash, i2.inventory_hash);
}

// --- Promotion cap ---

#[test]
fn test_promotion_cap() {
    let config = DarkMatterEngineConfig {
        max_promotions_per_cycle: 2,
        ..DarkMatterEngineConfig::default()
    };
    let mut engine = DarkMatterEngineOrchestrator::new(test_epoch(), config);
    let candidates = vec![
        candidate("h1", CandidateKind::Program, 900_000),
        candidate("h2", CandidateKind::Program, 800_000),
        candidate("h3", CandidateKind::Program, 700_000),
        candidate("h4", CandidateKind::Program, 600_000),
    ];
    let result = engine.discover(&candidates).unwrap();
    let (promoted, rejected, _, _) = expected_cycle_metrics(&engine.config, &candidates);
    assert_eq!(result.candidates_promoted, promoted);
    assert_eq!(result.candidates_rejected, rejected);
}

#[test]
fn test_discover_uses_contract_scoring_not_description_length_proxy() {
    let config = DarkMatterEngineConfig {
        scoring_config: ScoringConfig {
            dimension_weights: vec![DimensionWeight::new(NoveltyDimension::Obstruction, MILLION)],
            mdl_baseline_bits: 10_000,
            information_gain_threshold_millionths: 50_000,
            frontier_proximity_decay_millionths: 100_000,
            min_novelty_threshold_millionths: 200_000,
        },
        promotion_threshold_millionths: 500_000,
        ..DarkMatterEngineConfig::default()
    };
    let mut engine = DarkMatterEngineOrchestrator::new(test_epoch(), config);
    let candidates = vec![
        candidate_with_features(
            "proxy_favored_by_length",
            CandidateKind::Program,
            900_000,
            vec![0, 0, 0, 0, 0, 0, 0, 0],
        ),
        candidate_with_features(
            "contract_favored_by_obstruction",
            CandidateKind::Program,
            100_000,
            vec![0, 0, 900_000, 0, 0, 0, 0, 0],
        ),
    ];

    let result = engine.discover(&candidates).unwrap();
    let receipts = result
        .candidate_receipts
        .iter()
        .map(|receipt| (receipt.candidate_id.as_str(), receipt.promoted))
        .collect::<std::collections::BTreeMap<_, _>>();

    assert_eq!(
        receipts.get("proxy_favored_by_length"),
        Some(&false),
        "description length alone should no longer drive promotion decisions"
    );
    assert_eq!(
        receipts.get("contract_favored_by_obstruction"),
        Some(&true),
        "real novelty scoring evidence should control promotion"
    );
}
