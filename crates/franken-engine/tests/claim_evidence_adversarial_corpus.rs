//! CEI A.5 (`bd-sde5e.1.5`): adversarial + metamorphic self-audit corpus for the
//! claim-evidence integrity gate (A.3, `bd-sde5e.1.3`).
//!
//! Proves the gate is *differentially* sound, not merely unit-tested:
//!  1. a curated corpus of crafted over-promotions must each be rejected;
//!  2. a `tracked -> untracked` mutation must flip the gate verdict;
//!  3. a metamorphic monotonicity relation holds across the entire evidence-fact
//!     space (weakening any input can never raise the licensed ceiling);
//!  4. a document that silently asserts a different state than the matrix
//!     canonical is caught as a contradiction.
//!
//! These back the reflexive soundness claim (`FE-CLAIM-025`, CEI-H.2): the gate
//! that polices over-promotion is itself held to a checkable standard.

use frankenengine_engine::claim_evidence_lattice::{
    ClaimAssertionState, ClaimRow, EvidenceFacts, IntegrityReport, ceiling,
    scan_document_consistency, tier,
};

/// A "fully sound" evidence set that legitimately licenses Observed: committed,
/// real-passed, zero-exit receipt, committed repro.lock, fresh.
fn fully_sound() -> EvidenceFacts {
    EvidenceFacts {
        artifact_git_tracked: true,
        verification_passed: true,
        receipt_exit_zero: true,
        repro_lock_present: true,
        fresh: true,
        ..EvidenceFacts::default()
    }
}

fn observed_row(claim_id: &str, facts: EvidenceFacts) -> ClaimRow {
    ClaimRow {
        claim_id: claim_id.to_string(),
        asserted_state: ClaimAssertionState::Observed,
        facts,
    }
}

/// Adversarial corpus: every crafted over-promotion (an OBSERVED row whose
/// evidence has been weakened along one axis) MUST be flagged unsound.
#[test]
fn adversarial_overpromotions_are_all_rejected() {
    // Sanity: the un-weakened row is sound, so rejections below are meaningful.
    let baseline = IntegrityReport::score(&[observed_row("FE-CLAIM-BASE", fully_sound())]);
    assert!(
        baseline.verdicts["FE-CLAIM-BASE"].sound,
        "the fully-evidenced OBSERVED row must be sound"
    );

    // Each weakening is one corpus case the hardened gate must reject. These map to
    // the bead's enumerated cases: gitignored artifact, pending/backfill receipt,
    // and evidence aged past the freshness bound.
    type WeakeningCase = (&'static str, fn(&mut EvidenceFacts));
    let cases: Vec<WeakeningCase> = vec![
        ("gitignored-artifact", |f| f.artifact_git_tracked = false),
        ("pending-or-backfill-receipt", |f| {
            f.verification_passed = false
        }),
        ("nonzero-or-missing-receipt", |f| {
            f.receipt_exit_zero = false
        }),
        ("missing-repro-lock", |f| f.repro_lock_present = false),
        ("stale-past-freshness-bound", |f| f.fresh = false),
    ];
    for (name, weaken) in cases {
        let mut facts = fully_sound();
        weaken(&mut facts);
        let report = IntegrityReport::score(&[observed_row("FE-CLAIM-ADV", facts)]);
        let v = &report.verdicts["FE-CLAIM-ADV"];
        assert!(
            !v.sound,
            "adversarial corpus case '{name}' must be rejected, but the gate accepted it \
             (tier={}, ceiling={})",
            v.evidence_tier, v.ceiling
        );
        assert!(
            v.ceiling < ClaimAssertionState::Observed,
            "case '{name}': committed evidence must not license Observed"
        );
    }
}

/// Mutation: flipping the artifact from git-tracked to untracked must flip the
/// gate verdict from sound to unsound.
#[test]
fn tracked_to_untracked_mutation_flips_the_verdict() {
    let sound = IntegrityReport::score(&[observed_row("FE-CLAIM-MUT", fully_sound())]);
    assert!(sound.verdicts["FE-CLAIM-MUT"].sound);

    let mut mutated = fully_sound();
    mutated.artifact_git_tracked = false;
    let flipped = IntegrityReport::score(&[observed_row("FE-CLAIM-MUT", mutated)]);
    assert!(
        !flipped.verdicts["FE-CLAIM-MUT"].sound,
        "untracking the artifact must flip the verdict from sound to unsound"
    );
}

/// Enumerate the full boolean evidence-fact space (6 booleans -> 64 sets).
fn all_fact_combos() -> Vec<EvidenceFacts> {
    (0u8..64)
        .map(|bits| EvidenceFacts {
            artifact_git_tracked: bits & 1 != 0,
            verification_passed: bits & 2 != 0,
            receipt_exit_zero: bits & 4 != 0,
            repro_lock_present: bits & 8 != 0,
            fresh: bits & 16 != 0,
            adversarially_verified: bits & 32 != 0,
            ..EvidenceFacts::default()
        })
        .collect()
}

/// Metamorphic monotonicity (exhaustive): for ANY pair of fact sets where A
/// dominates B (A is at least as strong on every axis), weakening to B must NEVER
/// raise the licensed ceiling. Both `tier` and `ceiling` are monotone.
#[test]
fn weakening_evidence_never_raises_the_ceiling() {
    let space = all_fact_combos();
    let mut checked = 0u64;
    for a in &space {
        for b in &space {
            if a.dominates(b) {
                checked += 1;
                assert!(
                    tier(a) >= tier(b),
                    "tier monotonicity violated: stronger evidence scored a lower tier"
                );
                assert!(
                    ceiling(tier(a)) >= ceiling(tier(b)),
                    "ceiling monotonicity violated: weaker evidence licensed a higher state"
                );
            }
        }
    }
    // Every set dominates itself, so the relation is always exercised.
    assert!(checked >= space.len() as u64);
    eprintln!("[CEI A.5] metamorphic monotonicity holds over {checked} dominating pairs");
}

/// A document that asserts a known claim at a state different from the matrix
/// canonical is an internal contradiction the consistency index must catch — and
/// a re-statement of the same state must NOT be a false positive.
#[test]
fn silently_contradicting_document_is_flagged() {
    let canonical = vec![(
        "FE-CLAIM-901".to_string(),
        ClaimAssertionState::Observed,
        "matrix:1".to_string(),
    )];

    // Consistent doc: re-states OBSERVED -> no contradiction.
    let consistent = vec![(
        "ok.md".to_string(),
        "Row FE-CLAIM-901 stays OBSERVED in tree.".to_string(),
    )];
    assert!(
        scan_document_consistency(&canonical, &consistent).is_consistent(),
        "re-stating the canonical state must not be a false contradiction"
    );

    // Adversarial doc: silently asserts TARGETED for the same claim.
    let contradictory = vec![(
        "adversary.md".to_string(),
        "Row FE-CLAIM-901 is quietly TARGETED now.".to_string(),
    )];
    let report = scan_document_consistency(&canonical, &contradictory);
    assert!(
        !report.is_consistent() && report.contradictions.contains(&"FE-CLAIM-901".to_string()),
        "a doc asserting a different state than the matrix canonical must be a contradiction"
    );
}
