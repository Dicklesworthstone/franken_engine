//! Integration coverage for the claim ⇄ evidence soundness scorer (CEI A.1,
//! `bd-sde5e.1.1`). Runs the scorer against the *real* committed claim-to-proof
//! matrix and the *real* git working tree, proving the foundation works on live
//! data — not a fixture.
//!
//! The assertions are logical invariants of the scorer (determinism + the
//! soundness predicate), so they remain true as the rest of the CEI epic commits
//! evidence and raises coverage toward 1.0. They never hard-assert the *current*
//! (drifted) coverage value, which is exactly what tracks B/C/D are fixing.

use std::path::PathBuf;

use frankenengine_engine::claim_evidence_lattice::{
    COVERAGE_SCALE, ClaimAssertionState, EvidenceTier, IntegrityReport, ceiling,
    matrix_canonical_states, scan_document_consistency, tier,
};

/// Repo root = two levels above this crate's manifest dir (`crates/franken-engine`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root is two levels above crate manifest")
        .to_path_buf()
}

fn matrix_path() -> PathBuf {
    repo_root().join("docs/claim_to_proof_matrix_v1.json")
}

/// A fixed reference instant (2026-06-19T00:00:00Z) so the test is deterministic
/// and does not read the wall clock.
const NOW_UNIX: i64 = 1_781_827_200;

#[test]
fn scorer_runs_on_the_real_matrix_and_is_deterministic() {
    let report = IntegrityReport::score_inputs_or_panic();
    // Determinism: scoring the same inputs twice yields an identical digest.
    let again = IntegrityReport::score_inputs_or_panic();
    assert_eq!(
        report.coverage_digest, again.coverage_digest,
        "coverage digest must be deterministic"
    );
    assert_eq!(report.coverage_millionths, again.coverage_millionths);
    assert_eq!(report.coverage_digest.len(), 64);

    // The real matrix has rows; coverage is a valid fixed-point ratio.
    assert!(report.total_rows >= 20, "expected the full claim matrix");
    assert!(
        report.coverage_millionths <= COVERAGE_SCALE,
        "coverage cannot exceed 1.0"
    );

    eprintln!(
        "[CEI A.1] claim-integrity-coverage = {}/{} = {} millionths (digest {})",
        report.sound_rows, report.total_rows, report.coverage_millionths, report.coverage_digest
    );
    for v in report.unsound() {
        eprintln!(
            "[CEI A.1] OVER-PROMOTED {} asserts={} but evidence tier={} ceiling={} :: {}",
            v.claim_id,
            v.asserted_state,
            v.evidence_tier,
            v.ceiling,
            v.notes.join("; ")
        );
    }
}

/// The load-bearing soundness invariant on real data: any row that asserts
/// `observed` while its evidence does not reach the `Reproduced` tier MUST be
/// flagged unsound. This is true at today's drifted HEAD (artifacts are
/// git-ignored) and remains true after the epic lands (no such row will exist).
#[test]
fn every_observed_row_below_reproduced_tier_is_flagged() {
    let report = IntegrityReport::score_inputs_or_panic();
    for verdict in report.verdicts.values() {
        if verdict.asserted_state == ClaimAssertionState::Observed {
            let licenses_observed = ceiling(verdict.evidence_tier) >= ClaimAssertionState::Observed;
            assert_eq!(
                verdict.sound, licenses_observed,
                "row {} soundness must equal whether its tier licenses observed",
                verdict.claim_id
            );
            if !licenses_observed {
                assert!(
                    verdict.evidence_tier < EvidenceTier::Reproduced,
                    "row {} flagged unsound only when below Reproduced tier",
                    verdict.claim_id
                );
            }
        }
    }
}

/// At the current (pre-track-B) HEAD the reproducibility bundles are git-ignored,
/// so the scorer must observe real drift. This is an *advisory* lower bound on the
/// honesty signal; if a future state commits all evidence it converges to 1.0 and
/// this test's soft check is logged rather than failing the suite.
#[test]
fn drift_is_visible_at_current_head() {
    let report = IntegrityReport::score_inputs_or_panic();
    if report.coverage_millionths == COVERAGE_SCALE {
        eprintln!("[CEI A.1] matrix is fully sound — all evidence committed & verified");
    } else {
        eprintln!(
            "[CEI A.1] drift detected: {} of {} rows over-promote (coverage {} < 1.0)",
            report.total_rows - report.sound_rows,
            report.total_rows,
            report.coverage_millionths
        );
        assert!(
            !report.unsound().is_empty(),
            "coverage < 1.0 must list at least one over-promoted row"
        );
    }
}

/// CEI A.2 (bd-sde5e.1.2): the whole-document consistency index must find the
/// real README/PLAN/CHANGELOG internally consistent now that Track C reconciled
/// FE-CLAIM-004 / FE-CLAIM-006. A contradiction here means a claim is asserted at
/// two different states in two sections — the precise drift the gate must catch.
#[test]
fn real_docs_are_claim_state_consistent_after_track_c() {
    let root = repo_root();
    let canonical = matrix_canonical_states(&matrix_path()).expect("matrix canonical states");
    let mut docs = Vec::new();
    for rel in [
        "README.md",
        "docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md",
        "CHANGELOG.md",
    ] {
        let p = root.join(rel);
        if let Ok(text) = std::fs::read_to_string(&p) {
            docs.push((rel.to_string(), text));
        }
    }
    assert!(
        !docs.is_empty(),
        "expected at least README.md to be readable"
    );

    let report = scan_document_consistency(&canonical, &docs);
    // Determinism.
    let again = scan_document_consistency(&canonical, &docs);
    assert_eq!(report.digest, again.digest);
    assert_eq!(report.digest.len(), 64);

    for claim_id in &report.contradictions {
        eprintln!("[CEI A.2] CONTRADICTION {claim_id}:");
        for a in &report.assertions[claim_id] {
            eprintln!(
                "    {} @ {} {}",
                a.state,
                a.location,
                if a.canonical {
                    "(matrix canonical)"
                } else {
                    ""
                }
            );
        }
    }
    assert!(
        report.is_consistent(),
        "real docs must be claim-state consistent after Track C reconciliation; \
         contradictions: {:?}",
        report.contradictions
    );
}

#[test]
fn ceiling_and_tier_agree_with_module_contract() {
    // Sanity tie-in: the public API exposed for the gate behaves as documented.
    assert_eq!(
        ceiling(EvidenceTier::Unbacked),
        ClaimAssertionState::Hypothesis
    );
    assert_eq!(
        ceiling(EvidenceTier::Reproduced),
        ClaimAssertionState::Observed
    );
    let _ = tier; // referenced for the import to be load-bearing
}

// Helper attached via an extension trait so the integration test stays terse.
trait ScoreInputs {
    fn score_inputs_or_panic() -> IntegrityReport;
}

impl ScoreInputs for IntegrityReport {
    fn score_inputs_or_panic() -> IntegrityReport {
        frankenengine_engine::claim_evidence_lattice::score_matrix_file(
            &matrix_path(),
            &repo_root(),
            NOW_UNIX,
            None,
        )
        .expect("scoring the real matrix file must succeed")
    }
}
