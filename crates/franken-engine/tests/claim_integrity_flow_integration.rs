//! Integration tests for over-promotion as an information-flow violation
//! (CEI track H.3, bead `bd-sde5e.8.3`).
//!
//! Scans the *real* claim-to-proof matrix + committed evidence and confirms that
//! the integrity-flow check (1) agrees with the A.1 audit on which claims
//! over-promote, and (2) lets an explicit evidence-promotion receipt endorse a
//! specific over-promotion.

use std::path::{Path, PathBuf};

use frankenengine_engine::claim_evidence_lattice::{
    ClaimAssertionState, EvidenceTier, score_matrix_file,
};
use frankenengine_engine::claim_integrity_flow::{
    EvidencePromotionReceipt, scan_claim_integrity_flows,
};

fn repo_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("docs/claim_to_proof_matrix_v1.json").is_file() {
            return dir;
        }
        assert!(dir.pop(), "could not locate repo root");
    }
}

fn matrix_path(root: &Path) -> PathBuf {
    root.join("docs/claim_to_proof_matrix_v1.json")
}

/// A fixed instant so freshness (hence tier) is deterministic in CI. Chosen well
/// past the evidence commit dates so the test does not flap as wall-clock moves;
/// the live A.3 audit owns wall-clock freshness, this test owns the flow algebra.
const AS_OF_UNIX: i64 = 1_781_000_000;

#[test]
fn flow_violations_match_the_a1_over_promotions() {
    let root = repo_root();
    let mp = matrix_path(&root);

    // The A.1 scorer's notion of over-promotion (state > ceiling(tier)).
    let report = score_matrix_file(&mp, &root, AS_OF_UNIX, None).expect("score matrix");
    let mut a1_over: Vec<String> = report
        .unsound()
        .iter()
        .map(|v| v.claim_id.clone())
        .collect();
    a1_over.sort();

    // The integrity-flow notion of violation (no receipts supplied).
    let flow = scan_claim_integrity_flows(&mp, &root, AS_OF_UNIX, None, &[]).expect("scan flows");
    let mut flow_violations: Vec<String> = flow
        .violating_claims()
        .iter()
        .map(|s| s.to_string())
        .collect();
    flow_violations.sort();

    assert_eq!(
        a1_over, flow_violations,
        "integrity-flow violations must be exactly the A.1 over-promotions"
    );
    assert_eq!(flow.violations as usize, flow.violating_claims().len());
}

#[test]
fn an_evidence_promotion_receipt_endorses_exactly_one_violation() {
    let root = repo_root();
    let mp = matrix_path(&root);

    // Baseline: collect the violations with no receipts.
    let baseline = scan_claim_integrity_flows(&mp, &root, AS_OF_UNIX, None, &[]).expect("scan");
    let violations = baseline.violating_claims();
    if violations.is_empty() {
        // Matrix is fully sound — nothing to endorse; the endorsement path is
        // exercised by the module unit tests instead.
        return;
    }

    // Pick one violating claim and read its true (state, tier) so the receipt
    // matches exactly.
    let target = violations[0].to_string();
    let report = score_matrix_file(&mp, &root, AS_OF_UNIX, None).expect("score");
    let verdict = report.verdicts.get(&target).expect("verdict for target");
    let (state, tier): (ClaimAssertionState, EvidenceTier) =
        (verdict.asserted_state, verdict.evidence_tier);

    let receipt = EvidencePromotionReceipt {
        claim_id: target.clone(),
        from_tier: tier,
        to_state: state,
        authorized_by: "operator:cei-test".into(),
        justification: "documented waiver for the integration test".into(),
    };

    let endorsed =
        scan_claim_integrity_flows(&mp, &root, AS_OF_UNIX, None, std::slice::from_ref(&receipt))
            .expect("scan with receipt");

    // Exactly one fewer violation; the target is no longer violating.
    assert_eq!(
        endorsed.violations,
        baseline.violations - 1,
        "the receipt must clear exactly one violation"
    );
    assert_eq!(endorsed.endorsed, 1);
    assert!(
        !endorsed.violating_claims().contains(&target.as_str()),
        "the endorsed claim must no longer be a violation"
    );
}

#[test]
fn every_record_has_a_consistent_verdict() {
    let root = repo_root();
    let flow = scan_claim_integrity_flows(&matrix_path(&root), &root, AS_OF_UNIX, None, &[])
        .expect("scan");
    // One record per claim, and counts agree with the per-record verdicts.
    let counted_violations = flow
        .records
        .iter()
        .filter(|r| r.verdict.is_violation())
        .count() as u64;
    assert_eq!(flow.violations, counted_violations);
    assert!(!flow.records.is_empty(), "the matrix has claims");
}
