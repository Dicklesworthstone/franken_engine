//! `franken-evidence-manifest` — CEI B.1 (`bd-sde5e.2.1`) operator tool.
//!
//! Generates and verifies the content-addressed, git-tracked evidence manifests
//! under `docs/evidence/<CLAIM>/` for every OBSERVED claim in the claim-to-proof
//! matrix. See [`frankenengine_engine::evidence_manifest`] for the schema and the
//! offline-verification contract.
//!
//! Usage:
//!   franken_evidence_manifest generate   # copy bundles into docs/evidence/ + write manifests
//!   franken_evidence_manifest verify     # re-verify every committed manifest offline (CI)
//!
//! `verify` is deterministic and needs no access to the git-ignored `artifacts/`
//! tree; it exits non-zero if any recorded content hash fails to re-verify.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
        other => {
            eprintln!("unknown mode '{other}': expected 'generate' or 'verify'");
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
