//! Integration tests for the Merkle-committed Claim-Evidence Ledger
//! (CEI track H.1, bead `bd-sde5e.8.1`).
//!
//! These exercise the *real* repository: the committed root file
//! (`docs/claim_evidence_ledger_root.txt`), the live claim-to-proof matrix, and
//! the committed per-claim evidence manifests under `docs/evidence/`. They prove:
//!
//! 1. the committed root parses and is internally well-formed;
//! 2. the committed root is consistent with the live matrix + evidence at its
//!    pinned `as_of_unix` (the gate is green at HEAD);
//! 3. every leaf carries a valid RFC-6962 inclusion proof against the root;
//! 4. a silent matrix edit (an over-promotion) changes the root — the gate would
//!    fail closed until the root is regenerated.

use std::path::{Path, PathBuf};

use frankenengine_engine::claim_evidence_ledger::{
    ClaimEvidenceLedger, LedgerCommitment, load_committed_commitment, verify_against_committed,
};

/// Walk up from this crate's manifest dir to the repo root (dir holding the matrix).
fn repo_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("docs/claim_to_proof_matrix_v1.json").is_file() {
            return dir;
        }
        assert!(
            dir.pop(),
            "could not locate repo root from CARGO_MANIFEST_DIR"
        );
    }
}

fn matrix_path(root: &Path) -> PathBuf {
    root.join("docs/claim_to_proof_matrix_v1.json")
}

fn committed(root: &Path) -> LedgerCommitment {
    load_committed_commitment(root).expect(
        "docs/claim_evidence_ledger_root.txt must exist and parse \
         (regenerate with `franken_claim_evidence_ledger generate`)",
    )
}

#[test]
fn committed_root_file_parses_and_is_well_formed() {
    let root = repo_root();
    let c = committed(&root);
    assert_eq!(c.schema, "franken-engine.claim-evidence-ledger.v1");
    assert_eq!(c.root.len(), 64, "root is a hex sha256");
    assert!(c.root.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert_eq!(c.leaf_count, c.leaves.len() as u64);
    assert!(c.leaf_count > 0, "the ledger must commit at least one leaf");
    assert_eq!(c.leaves_digest.len(), 64);
}

#[test]
fn committed_root_is_consistent_with_live_matrix_and_evidence() {
    let root = repo_root();
    let verification =
        verify_against_committed(&matrix_path(&root), &root, None).expect("verification runs");
    assert!(
        verification.ok(),
        "committed ledger root diverges from live matrix/evidence — \
         regenerate docs/claim_evidence_ledger_root.txt. Mismatches: {:?}",
        verification.mismatches
    );
    assert!(verification.root_matches);
    assert!(verification.leaf_count_matches);
    assert!(verification.leaves_digest_matches);
    assert!(verification.leaves_match);
    assert!(verification.inclusion_proofs_ok);
}

#[test]
fn every_leaf_has_a_valid_inclusion_proof() {
    let root = repo_root();
    let c = committed(&root);
    // Rebuild at the pinned instant so tiers match the committed leaves.
    let ledger = ClaimEvidenceLedger::build(&matrix_path(&root), &root, c.as_of_unix, None)
        .expect("ledger builds");
    ledger
        .verify_all_inclusions()
        .expect("every leaf includes against the recomputed root");
    assert_eq!(ledger.leaf_count(), c.leaf_count);
}

#[test]
fn leaf_count_equals_matrix_row_count() {
    let root = repo_root();
    let text = std::fs::read_to_string(matrix_path(&root)).expect("read matrix");
    let json: serde_json::Value = serde_json::from_str(&text).expect("matrix json");
    let rows = json
        .get("claims")
        .and_then(|c| c.as_array())
        .expect("claims array")
        .len();
    let c = committed(&root);
    assert_eq!(
        c.leaf_count as usize, rows,
        "the ledger must commit exactly one leaf per matrix claim"
    );
}

#[test]
fn silent_matrix_over_promotion_changes_the_root() {
    let root = repo_root();
    let c = committed(&root);

    // Build the honest live ledger at the pinned instant.
    let honest = ClaimEvidenceLedger::build(&matrix_path(&root), &root, c.as_of_unix, None)
        .expect("honest ledger");
    let honest_root = honest.root_hex().expect("honest root");
    assert_eq!(
        honest_root, c.root,
        "sanity: live root equals committed root"
    );

    // Mutate one matrix row's allowed_state in a temp copy (a silent
    // over-promotion that did NOT regenerate the committed root).
    let text = std::fs::read_to_string(matrix_path(&root)).expect("read matrix");
    let mut json: serde_json::Value = serde_json::from_str(&text).expect("matrix json");
    {
        let claims = json
            .get_mut("claims")
            .and_then(|c| c.as_array_mut())
            .expect("claims array");
        let row = claims.first_mut().expect("at least one claim");
        let current = row
            .get("allowed_state")
            .and_then(|s| s.as_str())
            .unwrap_or("hypothesis")
            .to_string();
        // Flip to a different state so the leaf necessarily changes.
        let flipped = if current == "observed" {
            "hypothesis"
        } else {
            "observed"
        };
        row.as_object_mut().unwrap().insert(
            "allowed_state".into(),
            serde_json::Value::String(flipped.into()),
        );
    }

    let tmp = std::env::temp_dir().join(format!("franken_cel_tamper_{}.json", std::process::id()));
    std::fs::write(&tmp, serde_json::to_string_pretty(&json).unwrap()).expect("write temp matrix");

    let tampered = ClaimEvidenceLedger::build(&tmp, &root, c.as_of_unix, None)
        .expect("tampered ledger builds");
    let tampered_root = tampered.root_hex().expect("tampered root");

    let _ = std::fs::remove_file(&tmp);

    assert_ne!(
        honest_root, tampered_root,
        "a silent matrix over-promotion must change the committed root (tamper-evidence)"
    );
}
