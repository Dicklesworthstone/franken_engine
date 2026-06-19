//! CEI A.3 (`bd-sde5e.1.3`) integration coverage: the claim-evidence integrity
//! gate enforces `asserted_state <= ceiling(evidence_tier)`, where the tier is
//! derived only from machine-checkable facts. This is the enforcement direction
//! (matrix <= evidence) the historical claim-to-proof gate never checked.
//!
//! These tests pin the *blocking criterion* — what the gate must reject — at the
//! library level (so they are fast and deterministic), then confirm the live
//! scorer applies exactly that criterion to the real committed matrix.

use std::path::PathBuf;

use frankenengine_engine::claim_evidence_lattice::{
    ClaimAssertionState, EvidenceFacts, EvidenceTier, ceiling, score_matrix_file, tier,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root is two levels above crate manifest")
        .to_path_buf()
}

/// Fixed reference instant (2026-06-19T00:00:00Z) for deterministic freshness.
const NOW_UNIX: i64 = 1_781_827_200;

/// The A.3 acceptance: a committed artifact alone (pending/backfill receipt) must
/// NOT license `Observed`; only a real, non-pending, reproduced receipt does.
#[test]
fn pending_receipt_does_not_license_observed_but_real_pass_does() {
    // Committed but receipt still pending/backfill — exactly Track B's "before".
    let committed_pending = EvidenceFacts {
        artifact_git_tracked: true,
        verification_passed: false, // pending / backfill
        receipt_exit_zero: true,
        repro_lock_present: true,
        fresh: true,
        ..EvidenceFacts::default()
    };
    let t = tier(&committed_pending);
    assert!(
        ceiling(t) < ClaimAssertionState::Observed,
        "a committed-but-not-verified row must not license Observed (tier={t}, ceiling={})",
        ceiling(t)
    );

    // Real live receipt: committed + passed + zero-exit + repro.lock + fresh.
    let real_pass = EvidenceFacts {
        artifact_git_tracked: true,
        verification_passed: true,
        receipt_exit_zero: true,
        repro_lock_present: true,
        fresh: true,
        ..EvidenceFacts::default()
    };
    let t2 = tier(&real_pass);
    assert_eq!(
        ceiling(t2),
        ClaimAssertionState::Observed,
        "a committed + real-passed + reproduced row must license Observed (tier={t2})"
    );
    assert_eq!(t2, EvidenceTier::Reproduced);
}

/// A git-ignored artifact (the pre-Track-B state) is Unbacked -> Hypothesis.
#[test]
fn untracked_artifact_is_unbacked() {
    let untracked = EvidenceFacts::default();
    assert_eq!(tier(&untracked), EvidenceTier::Unbacked);
    assert_eq!(ceiling(tier(&untracked)), ClaimAssertionState::Hypothesis);
}

/// The live scorer flags a row as unsound **iff** its asserted state exceeds the
/// ceiling its committed evidence licenses — the exact predicate the gate blocks
/// on. This must hold on the real matrix at any point in the epic.
#[test]
fn live_audit_flags_exactly_the_over_promoted_rows() {
    let report = score_matrix_file(
        &repo_root().join("docs/claim_to_proof_matrix_v1.json"),
        &repo_root(),
        NOW_UNIX,
        None,
    )
    .expect("scoring the real matrix must succeed");

    for verdict in report.verdicts.values() {
        let over_promoted = verdict.asserted_state > ceiling(verdict.evidence_tier);
        assert_eq!(
            !verdict.sound, over_promoted,
            "row {} unsound iff asserted ({}) > ceiling ({})",
            verdict.claim_id, verdict.asserted_state, verdict.ceiling
        );
    }

    // The advisory gate reports a real coverage scalar in [0, 1].
    assert!(report.coverage_millionths <= 1_000_000);
    assert!(report.total_rows >= 20);
    eprintln!(
        "[CEI A.3] integrity audit: {}/{} sound; {} over-promoted",
        report.sound_rows,
        report.total_rows,
        report.unsound().len()
    );
}
