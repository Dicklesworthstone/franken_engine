//! Integration coverage for CEI B.4 (`bd-sde5e.2.4`): the "No artifact, no claim"
//! guarantee (FE-CLAIM-009) must hold for an EXTERNAL verifier — a fresh clone
//! that has only the committed git tree, with no git-ignored `artifacts/<gate>/
//! <timestamp>/` bundles and none of the working tree's uncommitted edits.
//!
//! These tests prove the property *structurally* (every hashed input a verifier
//! re-checks is committed, never a git-ignored bundle); the end-to-end proof —
//! a real `git worktree` checkout of HEAD with `franken_evidence_manifest verify`
//! run against it — lives in `scripts/e2e/fresh_clone_evidence_verification_smoke.sh`,
//! whose presence is asserted here so the two cannot drift apart.

use std::path::{Path, PathBuf};
use std::process::Command;

use frankenengine_engine::evidence_manifest::{EVIDENCE_DIR, load_manifest};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root is two levels above crate manifest")
        .to_path_buf()
}

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
        .arg("--error-unmatch")
        .arg("--")
        .arg(rel)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Every input a fresh-clone verifier re-hashes must be a committed file, so that
/// verification needs nothing under the git-ignored `artifacts/` bundle tree.
#[test]
fn every_observed_evidence_input_is_git_tracked_and_offline_sourced() {
    let root = repo_root();
    let ids = observed_claim_ids(&root);
    assert!(
        ids.len() >= 16,
        "expected the OBSERVED set, found {}",
        ids.len()
    );

    let mut checked = 0usize;
    for id in &ids {
        let manifest =
            load_manifest(&root, id).unwrap_or_else(|e| panic!("load manifest for {id}: {e}"));

        for input in manifest
            .verifiable_inputs
            .iter()
            .chain(manifest.bundle_files.iter())
        {
            // (1) Committed — present in a fresh clone.
            assert!(
                git_tracked(&root, &input.path),
                "{id}: evidence input {} (role={}) is not git-tracked; a fresh clone could not re-verify it",
                input.path,
                input.role
            );
            // (2) Not sourced from a git-ignored, timestamped gate-output bundle.
            //     Committed evidence lives under docs/evidence/<CLAIM>/ or is a
            //     committed primary artifact (README.md, scripts/*, src/*, docs/*),
            //     never under artifacts/<gate>/<timestamp>/.
            assert!(
                !is_under_gitignored_bundle(&input.path),
                "{id}: evidence input {} resolves into the git-ignored artifacts/ bundle tree",
                input.path
            );
            checked += 1;
        }
    }
    eprintln!("[CEI B.4] {checked} OBSERVED evidence inputs are committed + offline-sourced");
}

/// A timestamped gate-output bundle path looks like `artifacts/<gate>/<RUN>/...`
/// where `<RUN>` ends in `Z` (the UTC stamp). Committed `artifacts/*/README.md`
/// docs are not bundles and are allowed.
fn is_under_gitignored_bundle(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.first() != Some(&"artifacts") {
        return false;
    }
    parts
        .iter()
        .any(|seg| seg.ends_with('Z') && seg.len() >= 9 && seg.contains('T'))
}

/// Every OBSERVED claim must own a committed bundle directory under
/// `docs/evidence/`, so the committed tree is self-contained for verification.
#[test]
fn every_observed_claim_has_a_committed_evidence_dir() {
    let root = repo_root();
    for id in observed_claim_ids(&root) {
        let rel = format!("{EVIDENCE_DIR}/{id}/evidence_manifest.json");
        assert!(
            git_tracked(&root, &rel),
            "OBSERVED claim {id} has no committed evidence_manifest.json at {rel}"
        );
        let manifest_rel = format!("{EVIDENCE_DIR}/{id}/manifest.json");
        assert!(
            git_tracked(&root, &manifest_rel),
            "OBSERVED claim {id} has no committed manifest.json at {manifest_rel}"
        );
    }
}

/// The end-to-end fresh-clone proof script must exist and be executable; it is
/// the operator-facing companion to these structural tests (a true `git worktree`
/// checkout + `franken_evidence_manifest verify`).
#[test]
fn fresh_clone_e2e_script_is_present_and_executable() {
    let root = repo_root();
    let script = root.join("scripts/e2e/fresh_clone_evidence_verification_smoke.sh");
    assert!(
        script.is_file(),
        "fresh-clone e2e script is missing at {script:?}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&script)
            .expect("stat e2e script")
            .permissions()
            .mode();
        assert!(
            mode & 0o111 != 0,
            "fresh-clone e2e script is not executable (mode {mode:o})"
        );
    }

    // It must actually drive the committed verifier against a fresh worktree.
    let body = std::fs::read_to_string(&script).expect("read e2e script");
    assert!(
        body.contains("git worktree add") && body.contains("franken_evidence_manifest"),
        "fresh-clone e2e must materialize a worktree and run franken_evidence_manifest verify"
    );
}
