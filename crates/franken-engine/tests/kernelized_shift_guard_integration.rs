//! Integration tests for kernelized_shift_guard (RGC-706).

use frankenengine_engine::distribution_shift_monitor::EmbeddingVector;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::kernelized_shift_guard::{
    BoardFreshness, ShiftGuardConfig, ShiftGuardError, ShiftGuardOrchestrator,
    ShiftGuardSpecimenFamily, ShiftGuardVerdict, run_shift_guard_corpus, shift_guard_corpus,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn stable_embs(dim: usize, count: usize, val: u64) -> Vec<EmbeddingVector> {
    (0..count)
        .map(|i| EmbeddingVector {
            dimensions: vec![val; dim],
            source_hash: ContentHash::compute(format!("s-{i}").as_bytes()),
        })
        .collect()
}

fn shifted_embs(dim: usize, count: usize, val: u64) -> Vec<EmbeddingVector> {
    (0..count)
        .map(|i| EmbeddingVector {
            dimensions: vec![val.saturating_add(500_000 * (i as u64 + 1)); dim],
            source_hash: ContentHash::compute(format!("d-{i}").as_bytes()),
        })
        .collect()
}

// --- Construction ---

#[test]
fn test_construction_defaults() {
    let guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    assert_eq!(guard.board_freshness(), BoardFreshness::Unknown);
    assert!(guard.history().is_empty());
}

#[test]
fn test_set_baseline() {
    let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    guard.set_baseline(stable_embs(4, 10, 500_000));
    assert_eq!(guard.board_freshness(), BoardFreshness::Healthy);
}

// --- Error cases ---

#[test]
fn test_no_baseline_error() {
    let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    assert!(matches!(
        guard.check_shift(stable_embs(4, 5, 500_000)),
        Err(ShiftGuardError::NoBaseline)
    ));
}

#[test]
fn test_empty_stream_error() {
    let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    guard.set_baseline(stable_embs(4, 5, 500_000));
    assert!(matches!(
        guard.check_shift(vec![]),
        Err(ShiftGuardError::EmptyLiveStream)
    ));
}

// --- Stable checks ---

#[test]
fn test_stable_check_succeeds() {
    let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    guard.set_baseline(stable_embs(4, 10, 500_000));
    let result = guard.check_shift(stable_embs(4, 10, 500_000)).unwrap();
    assert_eq!(result.seq, 1);
}

#[test]
fn test_multiple_stable_checks() {
    let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    guard.set_baseline(stable_embs(4, 10, 500_000));
    for i in 1..=5 {
        let r = guard.check_shift(stable_embs(4, 10, 500_000)).unwrap();
        assert_eq!(r.seq, i);
    }
    assert_eq!(guard.summary().total_checks, 5);
}

// --- Shift detection ---

#[test]
fn test_shifted_stream_processed() {
    let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    guard.set_baseline(stable_embs(4, 10, 100_000));
    let result = guard.check_shift(shifted_embs(4, 10, 5_000_000)).unwrap();
    assert_eq!(result.seq, 1);
}

// --- Summary ---

#[test]
fn test_summary_initial() {
    let guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    let summary = guard.summary();
    assert_eq!(summary.total_checks, 0);
    assert_eq!(summary.shifts_detected, 0);
    assert_eq!(summary.passes, 0);
}

#[test]
fn test_summary_after_checks() {
    let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    guard.set_baseline(stable_embs(4, 10, 500_000));
    let _ = guard.check_shift(stable_embs(4, 10, 500_000));
    let _ = guard.check_shift(stable_embs(4, 10, 500_000));
    let summary = guard.summary();
    assert_eq!(summary.total_checks, 2);
    assert_eq!(
        summary.shifts_detected + summary.passes,
        summary.total_checks
    );
}

#[test]
fn test_summary_deterministic() {
    let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    guard.set_baseline(stable_embs(4, 5, 500_000));
    let _ = guard.check_shift(stable_embs(4, 5, 500_000));
    let s1 = guard.summary();
    let s2 = guard.summary();
    assert_eq!(s1.content_hash, s2.content_hash);
}

// --- History ---

#[test]
fn test_history_recorded() {
    let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    guard.set_baseline(stable_embs(4, 5, 500_000));
    let _ = guard.check_shift(stable_embs(4, 5, 500_000));
    let _ = guard.check_shift(stable_embs(4, 5, 500_000));
    assert_eq!(guard.history().len(), 2);
}

#[test]
fn test_history_bounded() {
    let config = ShiftGuardConfig {
        max_history: 3,
        ..ShiftGuardConfig::default()
    };
    let mut guard = ShiftGuardOrchestrator::new(test_epoch(), config);
    guard.set_baseline(stable_embs(4, 5, 500_000));
    for _ in 0..10 {
        let _ = guard.check_shift(stable_embs(4, 5, 500_000));
    }
    assert!(guard.history().len() <= 3);
}

// --- Reset ---

#[test]
fn test_reset_clears() {
    let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    guard.set_baseline(stable_embs(4, 5, 500_000));
    let _ = guard.check_shift(stable_embs(4, 5, 500_000));
    guard.reset(SecurityEpoch::from_raw(2));
    assert_eq!(guard.summary().total_checks, 0);
    assert_eq!(guard.board_freshness(), BoardFreshness::Unknown);
    assert!(guard.history().is_empty());
}

#[test]
fn test_reset_requires_new_baseline() {
    let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    guard.set_baseline(stable_embs(4, 5, 500_000));
    let _ = guard.check_shift(stable_embs(4, 5, 500_000));
    guard.reset(SecurityEpoch::from_raw(2));
    assert!(matches!(
        guard.check_shift(stable_embs(4, 5, 500_000)),
        Err(ShiftGuardError::NoBaseline)
    ));
}

// --- Error display ---

#[test]
fn test_error_display() {
    assert!(format!("{}", ShiftGuardError::NoBaseline).contains("baseline"));
    assert!(format!("{}", ShiftGuardError::EmptyLiveStream).contains("empty"));
    assert!(
        format!(
            "{}",
            ShiftGuardError::DetectionFailed {
                detail: "oops".to_string()
            }
        )
        .contains("oops")
    );
}

// --- Evidence corpus ---

#[test]
fn test_corpus_all_pass() {
    let inv = run_shift_guard_corpus();
    for e in &inv.evidences {
        assert_eq!(
            e.verdict,
            ShiftGuardVerdict::Pass,
            "failed: {} - {}",
            e.specimen_id,
            e.details
        );
    }
}

#[test]
fn test_corpus_covers_families() {
    let corpus = shift_guard_corpus();
    for family in ShiftGuardSpecimenFamily::ALL {
        assert!(
            corpus.iter().any(|s| s.family == *family),
            "missing: {family:?}"
        );
    }
}

#[test]
fn test_corpus_deterministic() {
    let i1 = run_shift_guard_corpus();
    let i2 = run_shift_guard_corpus();
    assert_eq!(i1.inventory_hash, i2.inventory_hash);
}

// --- Board freshness ---

#[test]
fn test_freshness_unknown_initially() {
    let guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    assert_eq!(guard.board_freshness(), BoardFreshness::Unknown);
}

#[test]
fn test_freshness_healthy_after_baseline() {
    let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
    guard.set_baseline(stable_embs(4, 5, 500_000));
    assert_eq!(guard.board_freshness(), BoardFreshness::Healthy);
}

// --- Auto expand config ---

#[test]
fn test_auto_expand_disabled() {
    let config = ShiftGuardConfig {
        auto_expand_on_shift: false,
        ..ShiftGuardConfig::default()
    };
    let mut guard = ShiftGuardOrchestrator::new(test_epoch(), config);
    guard.set_baseline(stable_embs(4, 10, 100_000));
    let result = guard.check_shift(shifted_embs(4, 10, 5_000_000)).unwrap();
    assert!(!result.expansion_triggered);
}
