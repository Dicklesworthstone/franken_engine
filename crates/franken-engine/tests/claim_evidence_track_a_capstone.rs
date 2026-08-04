//! CEI A.6 (`bd-sde5e.1.6`): Track-A capstone integration test.
//!
//! The per-bead tests (A.1 scorer, A.2 consistency, A.3 gate, A.4 freshness,
//! A.5 adversarial corpus) each prove one slice. This capstone proves the
//! slices *compose* on the real, committed repository — in particular that the
//! A.4 e-process freshness collector actually runs against the committed
//! `docs/evidence/<CLAIM>/` bundles (not just synthetic fixtures), and that the
//! A.1 whole-matrix scorer remains deterministic and sound-flagging on top of it.

use std::path::PathBuf;

use frankenengine_engine::claim_evidence_lattice::{
    ClaimAssertionState, EvidenceTier, IntegrityReport, ceiling, collect_evidence_facts,
    score_matrix_file,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root two levels above crate manifest")
        .to_path_buf()
}

fn matrix_path() -> PathBuf {
    repo_root().join("docs/claim_to_proof_matrix_v1.json")
}

/// A fixed reference instant so the capstone is deterministic.
const NOW_UNIX: i64 = 1_781_827_200; // 2026-06-19T00:00:00Z

/// A.4 wired into A.1 on REAL committed evidence: the collector computes a real
/// age and an e-process verdict for a committed, git-tracked bundle — never the
/// authored matrix `freshness_days` (which is now null everywhere).
#[test]
fn freshness_eprocess_runs_against_committed_evidence_bundles() {
    let root = repo_root();
    // Pick any committed evidence bundle that exists at HEAD.
    let mut checked = 0usize;
    for claim in ["FE-CLAIM-001", "FE-CLAIM-004", "FE-CLAIM-009"] {
        let rel = format!("docs/evidence/{claim}");
        if !root.join(&rel).join("manifest.json").exists() {
            continue;
        }
        let facts = collect_evidence_facts(&root, &rel, NOW_UNIX, 30);
        // The bundle is committed, so a real age and an e-process verdict must
        // have been computed (manifest timestamp or git-commit-time fallback).
        assert!(
            facts.freshness_days.is_some(),
            "{claim}: real age must be computed, got notes={:?}",
            facts.notes
        );
        let v = facts
            .freshness_eprocess
            .expect("e-process verdict must be attached for a dated bundle");
        // The boundary is derived, not authored: default horizon 30 -> bound 31.
        assert_eq!(v.horizon_days, 30);
        assert_eq!(v.bound_days, 31);
        // fresh iff age strictly below the bound; consistency between the two.
        assert_eq!(v.fresh, v.age_days < v.bound_days);
        checked += 1;
    }
    assert!(
        checked > 0,
        "expected at least one committed evidence bundle under docs/evidence/"
    );
}

/// The whole-matrix scorer composes the A.1-A.4 pipeline deterministically and
/// keeps the load-bearing soundness invariant after A.4: a row may license
/// `Observed` only when its evidence reaches the `Reproduced` tier.
fn score() -> IntegrityReport {
    score_matrix_file(&matrix_path(), &repo_root(), NOW_UNIX, None)
        .expect("scoring the real matrix must succeed")
}

#[test]
fn track_a_pipeline_is_deterministic_and_sound_flagging() {
    let report = score();
    let again = score();
    assert_eq!(
        report.coverage_digest, again.coverage_digest,
        "deterministic"
    );
    assert_eq!(report.coverage_digest.len(), 64);
    assert!(report.total_rows >= 20, "expected the full claim matrix");

    for v in report.verdicts.values() {
        if v.asserted_state == ClaimAssertionState::Observed {
            let licenses = ceiling(v.evidence_tier) >= ClaimAssertionState::Observed;
            assert_eq!(v.sound, licenses, "{} soundness vs ceiling", v.claim_id);
            if !licenses {
                assert!(
                    v.evidence_tier < EvidenceTier::Reproduced,
                    "{} flagged unsound only below Reproduced",
                    v.claim_id
                );
            }
        }
    }
}

/// The matrix is the single source of freshness *policy* and authors no
/// per-claim freshness *measurement* (A.4 acceptance, checked at the integration
/// boundary alongside the scorer).
#[test]
fn matrix_authors_policy_not_measurements() {
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(matrix_path()).expect("read matrix"))
            .expect("parse matrix");
    let policy = &json["freshness_eprocess_policy"];
    assert!(
        policy.is_object(),
        "matrix must declare freshness_eprocess_policy"
    );
    assert_eq!(policy["alpha_millionths"].as_i64(), Some(50_000));
    for c in json["claims"].as_array().expect("claims") {
        assert!(
            c.get("freshness_days")
                .map(serde_json::Value::is_null)
                .unwrap_or(true),
            "claim {} authors a freshness measurement",
            c["claim_id"]
        );
    }
}
