//! `franken-evidence-manifest` — CEI evidence operator tool (B.1 `bd-sde5e.2.1`,
//! A.3 `bd-sde5e.1.3`).
//!
//! Generates and verifies the content-addressed, git-tracked evidence manifests
//! under `docs/evidence/<CLAIM>/` for every OBSERVED claim in the claim-to-proof
//! matrix, and audits the matrix against that committed evidence. See
//! [`frankenengine_engine::evidence_manifest`] for the schema and the
//! offline-verification contract, and [`frankenengine_engine::claim_evidence_lattice`]
//! for the soundness scorer.
//!
//! Usage:
//!   franken_evidence_manifest generate          # copy bundles into docs/evidence/ + write manifests
//!   franken_evidence_manifest verify            # re-verify every committed manifest offline (CI)
//!   franken_evidence_manifest audit [--blocking] # CEI-A.3: report rows that assert more than their evidence licenses
//!
//! `verify` is deterministic and needs no access to the git-ignored `artifacts/`
//! tree; it exits non-zero if any recorded content hash fails to re-verify.
//! `audit` is advisory (exit 0) unless `--blocking` is passed (exit 1 on any
//! over-promoted row).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use frankenengine_engine::claim_evidence_lattice::score_matrix_file;
use frankenengine_engine::evidence_manifest::{
    BUNDLE_FILES, EVIDENCE_DIR, build_manifest, load_manifest, verify_manifest_offline,
};
use serde_json::Value;

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

    let claims = match observed_claims(&repo_root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    match mode.as_str() {
        "generate" => generate(&repo_root, &claims),
        "verify" => verify(&repo_root, &claims),
        "audit" => audit(&repo_root, std::env::args().any(|a| a == "--blocking")),
        other => {
            eprintln!("unknown mode '{other}': expected 'generate', 'verify', or 'audit'");
            ExitCode::from(2)
        }
    }
}

/// One OBSERVED claim row distilled from the matrix.
struct ObservedClaim {
    claim_id: String,
    owning_bead: String,
    artifact_path: String,
}

fn observed_claims(repo_root: &Path) -> Result<Vec<ObservedClaim>, String> {
    let matrix_path = repo_root.join("docs/claim_to_proof_matrix_v1.json");
    let text = std::fs::read_to_string(&matrix_path)
        .map_err(|e| format!("read {}: {e}", matrix_path.display()))?;
    let matrix: Value = serde_json::from_str(&text).map_err(|e| format!("parse matrix: {e}"))?;
    let claims = matrix
        .get("claims")
        .and_then(Value::as_array)
        .ok_or("matrix has no claims array")?;
    let mut out = Vec::new();
    for c in claims {
        if c.get("allowed_state").and_then(Value::as_str) != Some("observed") {
            continue;
        }
        let claim_id = c
            .get("claim_id")
            .and_then(Value::as_str)
            .ok_or("claim missing claim_id")?
            .to_string();
        let owning_bead = c
            .get("owning_bead")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let artifact_path = c
            .get("artifact_path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        out.push(ObservedClaim {
            claim_id,
            owning_bead,
            artifact_path,
        });
    }
    Ok(out)
}

fn generate(repo_root: &Path, claims: &[ObservedClaim]) -> ExitCode {
    let mut failed = 0usize;
    for claim in claims {
        let committed_dir = format!("{EVIDENCE_DIR}/{}", claim.claim_id);
        let committed_abs = repo_root.join(&committed_dir);
        if let Err(e) = std::fs::create_dir_all(&committed_abs) {
            eprintln!("[{}] mkdir failed: {e}", claim.claim_id);
            failed += 1;
            continue;
        }

        // Copy the three bundle files from the matrix-declared source into the
        // committed location (no-op if the source already *is* that location).
        let source_dir = if claim.artifact_path.is_empty() {
            format!("artifacts/reproducibility_bundles/{}", claim.claim_id)
        } else {
            claim.artifact_path.clone()
        };
        let mut copy_err = false;
        for name in BUNDLE_FILES {
            let src = repo_root.join(&source_dir).join(name);
            let dst = committed_abs.join(name);
            if src == dst {
                continue;
            }
            if let Err(e) = std::fs::copy(&src, &dst) {
                eprintln!(
                    "[{}] copy {} -> {}: {e}",
                    claim.claim_id,
                    src.display(),
                    dst.display()
                );
                copy_err = true;
            }
        }
        if copy_err {
            failed += 1;
            continue;
        }

        // Build from the committed copy (single source of truth post-copy).
        match build_manifest(
            repo_root,
            &claim.claim_id,
            &claim.owning_bead,
            "observed",
            &committed_dir,
            &committed_dir,
        ) {
            Ok(manifest) => {
                let out = committed_abs.join("evidence_manifest.json");
                if let Err(e) = std::fs::write(&out, manifest.to_canonical_json()) {
                    eprintln!("[{}] write manifest: {e}", claim.claim_id);
                    failed += 1;
                } else {
                    println!(
                        "[{}] wrote {} (primary {}, receipt {})",
                        claim.claim_id,
                        out.strip_prefix(repo_root).unwrap_or(&out).display(),
                        manifest
                            .verifiable_inputs
                            .first()
                            .map(|h| h.path.as_str())
                            .unwrap_or("?"),
                        manifest.receipt.verification_result,
                    );
                }
            }
            Err(e) => {
                eprintln!("[{}] build_manifest: {e}", claim.claim_id);
                failed += 1;
            }
        }
    }
    println!("generate: {} ok, {} failed", claims.len() - failed, failed);
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn verify(repo_root: &Path, claims: &[ObservedClaim]) -> ExitCode {
    let mut failed = 0usize;
    for claim in claims {
        match load_manifest(repo_root, &claim.claim_id) {
            Ok(manifest) => {
                let report = verify_manifest_offline(repo_root, &manifest);
                if report.ok() {
                    println!(
                        "[{}] OK ({} inputs re-verified)",
                        claim.claim_id, report.checked
                    );
                } else {
                    failed += 1;
                    eprintln!(
                        "[{}] FAIL: {} mismatches, {} missing",
                        claim.claim_id,
                        report.mismatches.len(),
                        report.missing.len()
                    );
                    for m in &report.mismatches {
                        eprintln!("    mismatch: {m}");
                    }
                    for m in &report.missing {
                        eprintln!("    missing:  {m}");
                    }
                }
            }
            Err(e) => {
                failed += 1;
                eprintln!("[{}] FAIL: no committed manifest ({e})", claim.claim_id);
            }
        }
    }
    println!(
        "verify: {} ok, {} failed (of {})",
        claims.len() - failed,
        failed,
        claims.len()
    );
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// CEI-A.3 (`bd-sde5e.1.3`): score the live matrix against committed evidence and
/// report every row whose asserted state exceeds what its git-tracked, non-pending
/// evidence licenses (the bidirectional `state <= ceiling(tier)` check).
///
/// Advisory by default (exit 0, prints the over-promotion list); `--blocking`
/// fails closed (exit 1) on any unsound row. The G.1 meta-gate runs it with
/// `--blocking` once Track B has committed real receipts for every OBSERVED row.
fn audit(repo_root: &Path, blocking: bool) -> ExitCode {
    let matrix_path = repo_root.join("docs/claim_to_proof_matrix_v1.json");
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let report = match score_matrix_file(&matrix_path, repo_root, now_unix, None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("audit: failed to score matrix: {e:?}");
            return ExitCode::from(2);
        }
    };
    println!(
        "claim-integrity-coverage = {}/{} sound ({} millionths, digest {})",
        report.sound_rows, report.total_rows, report.coverage_millionths, report.coverage_digest
    );
    let unsound = report.unsound();
    for v in &unsound {
        println!(
            "  OVER-PROMOTED {}: asserts={} but evidence tier={} licenses <= {} :: {}",
            v.claim_id,
            v.asserted_state,
            v.evidence_tier,
            v.ceiling,
            v.notes.join("; ")
        );
    }
    if unsound.is_empty() {
        println!(
            "audit: PASS — every claim's asserted state is within its committed-evidence ceiling"
        );
        ExitCode::SUCCESS
    } else if blocking {
        eprintln!(
            "audit: FAIL (blocking) — {} claim(s) assert more than their committed evidence licenses",
            unsound.len()
        );
        ExitCode::FAILURE
    } else {
        println!(
            "audit: ADVISORY — {} over-promoted claim(s); not failing (pass --blocking to enforce)",
            unsound.len()
        );
        ExitCode::SUCCESS
    }
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
