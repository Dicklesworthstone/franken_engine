//! Integration coverage for CEI B.1 (`bd-sde5e.2.1`): committed, content-addressed
//! evidence manifests must let a fresh clone verify every OBSERVED claim's evidence
//! **offline** — with no access to the git-ignored `artifacts/` tree.
//!
//! Acceptance (from the bead):
//!   * `git ls-files` lists a committed manifest for every OBSERVED claim;
//!   * a clone with `artifacts/` deleted re-verifies each artifact content-hash
//!     against its committed manifest;
//!   * the check actually checks (a tampered hash is rejected).
//!
//! These assertions read the *real* matrix and the *real* committed manifests, so
//! they fail closed the moment evidence drifts from its content hash.

use std::path::{Path, PathBuf};
use std::process::Command;

use frankenengine_engine::evidence_manifest::{
    EVIDENCE_DIR, HashSource, load_manifest, verify_manifest_offline,
};
use serde_json::Value;

/// Repo root = two levels above this crate's manifest dir.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root is two levels above crate manifest")
        .to_path_buf()
}

/// OBSERVED claim ids, read from the real matrix (single source of truth).
fn observed_claim_ids(root: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(root.join("docs/claim_to_proof_matrix_v1.json"))
        .expect("read matrix");
    let matrix: Value = serde_json::from_str(&text).expect("parse matrix");
    matrix["claims"]
        .as_array()
        .expect("claims array")
        .iter()
        .filter(|c| c["allowed_state"].as_str() == Some("observed"))
        .map(|c| c["claim_id"].as_str().expect("claim_id").to_string())
        .collect()
}

fn git_tracked(root: &Path, rel: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("ls-files")
        .arg("--")
        .arg(rel)
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

#[test]
fn every_observed_claim_has_a_tracked_manifest_that_verifies_offline() {
    let root = repo_root();
    let ids = observed_claim_ids(&root);
    // Floor tracks the current OBSERVED set (16 after FE-CLAIM-012 was downgraded
    // to `target`; see bd-sde5e). The floor guards against the matrix parser
    // silently returning an empty/short set, not against deliberate downgrades.
    assert!(
        ids.len() >= 16,
        "expected the full OBSERVED set (>=16), found {}",
        ids.len()
    );

    let mut verified = 0usize;
    for id in &ids {
        // (1) A committed manifest exists and is git-tracked.
        let rel = format!("{EVIDENCE_DIR}/{id}/evidence_manifest.json");
        assert!(
            git_tracked(&root, &rel),
            "OBSERVED claim {id} has no git-tracked evidence manifest at {rel}"
        );

        // (2) It loads and re-verifies offline against the live tree.
        let manifest =
            load_manifest(&root, id).unwrap_or_else(|e| panic!("load manifest for {id}: {e}"));
        assert_eq!(manifest.claim_id, *id);
        assert_eq!(manifest.allowed_state, "observed");

        let report = verify_manifest_offline(&root, &manifest);
        assert!(
            report.ok(),
            "offline verification failed for {id}: mismatches={:?} missing={:?}",
            report.mismatches,
            report.missing
        );

        // (3) The offline guarantee rests on a git-tracked primary artifact hashed
        //     from the committed blob — exactly what survives `artifacts/` deletion.
        let primary = manifest
            .verifiable_inputs
            .iter()
            .find(|h| h.role == "primary_artifact")
            .unwrap_or_else(|| panic!("{id} manifest has no primary_artifact input"));
        assert_eq!(primary.source, HashSource::HeadBlob);
        assert!(
            git_tracked(&root, &primary.path),
            "{id} primary artifact {} must be git-tracked",
            primary.path
        );
        assert_eq!(primary.sha256.len(), 64);

        verified += 1;
    }
    eprintln!(
        "[CEI B.1] {verified} OBSERVED claims re-verified offline against committed manifests"
    );
}

#[test]
fn verification_is_deterministic() {
    let root = repo_root();
    let ids = observed_claim_ids(&root);
    let id = ids.first().expect("at least one observed claim");
    let manifest = load_manifest(&root, id).expect("load");
    let a = verify_manifest_offline(&root, &manifest);
    let b = verify_manifest_offline(&root, &manifest);
    assert_eq!(a, b, "offline verification must be deterministic");
    assert!(a.ok());
}

/// The verifier must actually verify: tampering with any recorded hash must be
/// rejected. A check that always passes would not back FE-CLAIM-009.
#[test]
fn tampered_hash_is_rejected() {
    let root = repo_root();
    let ids = observed_claim_ids(&root);
    let id = ids.first().expect("at least one observed claim");
    let mut manifest = load_manifest(&root, id).expect("load");

    // Flip the primary artifact's recorded hash to a valid-but-wrong digest.
    let primary = manifest
        .verifiable_inputs
        .iter_mut()
        .find(|h| h.role == "primary_artifact")
        .expect("primary input");
    primary.sha256 = "0".repeat(64);

    let report = verify_manifest_offline(&root, &manifest);
    assert!(
        !report.ok() && !report.mismatches.is_empty(),
        "a tampered content hash must be rejected, got {report:?}"
    );
}

/// A bundle file recorded as git-tracked but absent from the index must be flagged
/// (models a manifest that points at evidence which was never committed).
#[test]
fn untracked_recorded_input_is_flagged() {
    let root = repo_root();
    let ids = observed_claim_ids(&root);
    let id = ids.first().expect("at least one observed claim");
    let mut manifest = load_manifest(&root, id).expect("load");

    // Point the primary at a path that does not exist at HEAD while keeping the
    // recorded git_tracked flag — the verifier must report it missing.
    if let Some(primary) = manifest
        .verifiable_inputs
        .iter_mut()
        .find(|h| h.role == "primary_artifact")
    {
        primary.path = "docs/this_artifact_does_not_exist_in_head.md".to_string();
    }
    let report = verify_manifest_offline(&root, &manifest);
    assert!(
        !report.ok() && !report.missing.is_empty(),
        "a recorded-tracked input absent from HEAD must be flagged, got {report:?}"
    );
}
