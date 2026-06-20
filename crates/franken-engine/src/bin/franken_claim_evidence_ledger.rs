//! `franken_claim_evidence_ledger` — build, commit, and verify the Merkle-committed
//! Claim-Evidence Ledger (CEI track H.1, bead `bd-sde5e.8.1`).
//!
//! Subcommands:
//!
//! * `generate` — recompute the ledger from the live matrix + committed evidence
//!   at the **current** wall-clock time and (over)write
//!   `docs/claim_evidence_ledger_root.txt`. This is the only path that reads the
//!   wall clock; it pins that instant into the committed file as `as_of_unix`.
//! * `verify` — recompute against the **pinned** `as_of_unix` from the committed
//!   file and fail (exit 1) on any divergence: root, leaf count, leaves digest,
//!   per-leaf record, or a broken RFC-6962 inclusion proof.
//! * `show` — print the recomputed commitment + per-leaf audit table without
//!   touching the committed file.
//!
//! The binary resolves the repo root by walking up from the current directory to
//! the directory that holds `docs/claim_to_proof_matrix_v1.json`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use frankenengine_engine::claim_evidence_ledger::{
    ClaimEvidenceLedger, LEDGER_ROOT_FILE, load_committed_commitment, verify_against_committed,
    write_committed_commitment,
};

fn main() -> ExitCode {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "verify".to_string());

    let repo_root = match find_repo_root() {
        Some(r) => r,
        None => {
            eprintln!(
                "error: could not locate repo root (no docs/claim_to_proof_matrix_v1.json upward)"
            );
            return ExitCode::from(2);
        }
    };
    let matrix_path = repo_root.join("docs/claim_to_proof_matrix_v1.json");

    match mode.as_str() {
        "generate" => generate(&repo_root, &matrix_path),
        "verify" => verify(&repo_root, &matrix_path),
        "show" => show(&repo_root, &matrix_path),
        other => {
            eprintln!("usage: franken_claim_evidence_ledger [generate|verify|show]");
            eprintln!("error: unknown mode {other:?}");
            ExitCode::from(2)
        }
    }
}

/// Recompute at wall-clock time and (over)write the committed root file.
fn generate(repo_root: &Path, matrix_path: &Path) -> ExitCode {
    let now_unix = wall_clock_unix();
    let ledger = match ClaimEvidenceLedger::build(matrix_path, repo_root, now_unix, None) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("generate: failed to build ledger: {e}");
            return ExitCode::from(2);
        }
    };
    let commitment = match ledger.commitment() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("generate: failed to commit: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = write_committed_commitment(repo_root, &commitment) {
        eprintln!("generate: failed to write {LEDGER_ROOT_FILE}: {e}");
        return ExitCode::from(2);
    }
    println!(
        "generate: wrote {LEDGER_ROOT_FILE}\n  root         = {}\n  leaf_count   = {}\n  leaves_digest= {}\n  as_of_unix   = {}",
        commitment.root, commitment.leaf_count, commitment.leaves_digest, commitment.as_of_unix
    );
    ExitCode::SUCCESS
}

/// Verify the live matrix + evidence against the committed root file.
fn verify(repo_root: &Path, matrix_path: &Path) -> ExitCode {
    let verification = match verify_against_committed(matrix_path, repo_root, None) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("verify: error: {e}");
            return ExitCode::from(2);
        }
    };
    println!(
        "committed root = {} ({} leaves, as_of_unix {})",
        verification.committed.root,
        verification.committed.leaf_count,
        verification.committed.as_of_unix
    );
    println!("recomputed root = {}", verification.recomputed.root);
    println!(
        "checks: root={} leaf_count={} leaves_digest={} leaves={} inclusion_proofs={}",
        verification.root_matches,
        verification.leaf_count_matches,
        verification.leaves_digest_matches,
        verification.leaves_match,
        verification.inclusion_proofs_ok,
    );
    if verification.ok() {
        println!(
            "verify: PASS — committed root is consistent with live matrix + evidence; every leaf includes"
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("verify: FAIL — committed root diverges from live matrix/evidence:");
        for m in &verification.mismatches {
            eprintln!("  - {m}");
        }
        eprintln!(
            "  (if this change is intentional and evidence-consistent, regenerate the root with `generate`)"
        );
        ExitCode::FAILURE
    }
}

/// Print the recomputed commitment table without writing anything. Uses the
/// committed `as_of_unix` when a committed file exists, else wall-clock time.
fn show(repo_root: &Path, matrix_path: &Path) -> ExitCode {
    let as_of_unix = load_committed_commitment(repo_root)
        .map(|c| c.as_of_unix)
        .unwrap_or_else(|_| wall_clock_unix());
    let ledger = match ClaimEvidenceLedger::build(matrix_path, repo_root, as_of_unix, None) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("show: failed to build ledger: {e}");
            return ExitCode::from(2);
        }
    };
    let commitment = match ledger.commitment() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("show: failed to commit: {e}");
            return ExitCode::from(2);
        }
    };
    print!("{}", commitment.to_root_file());
    ExitCode::SUCCESS
}

fn wall_clock_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Walk up from the current directory to the repo root (dir holding the matrix).
fn find_repo_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join("docs/claim_to_proof_matrix_v1.json").is_file() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}
