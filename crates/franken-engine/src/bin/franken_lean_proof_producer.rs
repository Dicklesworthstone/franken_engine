#![forbid(unsafe_code)]

//! Operator surface for the E6.T2 Lean proof producer (bd-fqlfw.6.2).
//!
//! Runs `lake build` over a Lean proof corpus (default: `proofs/lean4/`),
//! captures tool identity and content hashes, and writes the strict
//! [`ProofProducerArtifact`] `proof.json` defined by the E6.T1 contract.
//!
//! Exit codes:
//! - `0` — checker verdict `Passed`; the artifact validates fail-closed.
//! - `4` — the producer ran but the verdict is non-`Passed` (`Unavailable`);
//!   the artifact is still written so operators can inspect the reason, but
//!   it can never promote a claim (validation rejects it).
//! - `2` — usage error or producer I/O failure (no artifact written).

use std::path::PathBuf;
use std::time::Duration;
use std::{env, process};

use frankenengine_engine::lean_proof_producer::{
    LeanProofProducerConfig, write_lean_proof_artifact,
};
use frankenengine_engine::proof_schema::ProofCheckerResult;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(err) => {
            eprintln!("franken_lean_proof_producer: {err}");
            process::exit(2);
        }
    }
}

fn print_usage() {
    println!(
        "Usage: franken_lean_proof_producer [OPTIONS]\n\
         \n\
         Options:\n\
         \x20 --proof-dir <dir>       Lean proof corpus (default: proofs/lean4)\n\
         \x20 --out <path>            Output proof.json path (default: <proof-dir>/proof.json)\n\
         \x20 --claim-id <id>         Claim ID backed by the corpus (repeatable; default: FE-CLAIM-016)\n\
         \x20 --invocation-id <id>    Tool invocation ID for audit correlation\n\
         \x20 --ticks <n>             Replay tick for this producer run (default: 0)\n\
         \x20 --epoch <n>             Security epoch for this producer run (default: 1)\n\
         \x20 --timeout-secs <n>      Per-command timeout in seconds (default: 300)\n\
         \x20 --help                  Show this help"
    );
}

fn run() -> Result<i32, String> {
    let mut proof_dir = PathBuf::from("proofs/lean4");
    let mut out: Option<PathBuf> = None;
    let mut claim_ids: Vec<String> = Vec::new();
    let mut invocation_id: Option<String> = None;
    let mut ticks: u64 = 0;
    let mut epoch: u64 = 1;
    let mut timeout_secs: u64 = 300;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut take = |name: &str| -> Result<String, String> {
            args.next()
                .ok_or_else(|| format!("missing value for {name}"))
        };
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                return Ok(0);
            }
            "--proof-dir" => proof_dir = PathBuf::from(take("--proof-dir")?),
            "--out" => out = Some(PathBuf::from(take("--out")?)),
            "--claim-id" => claim_ids.push(take("--claim-id")?),
            "--invocation-id" => invocation_id = Some(take("--invocation-id")?),
            "--ticks" => {
                ticks = take("--ticks")?
                    .parse()
                    .map_err(|e| format!("invalid --ticks: {e}"))?;
            }
            "--epoch" => {
                epoch = take("--epoch")?
                    .parse()
                    .map_err(|e| format!("invalid --epoch: {e}"))?;
            }
            "--timeout-secs" => {
                timeout_secs = take("--timeout-secs")?
                    .parse()
                    .map_err(|e| format!("invalid --timeout-secs: {e}"))?;
            }
            other => return Err(format!("unknown argument: {other} (see --help)")),
        }
    }

    let out = out.unwrap_or_else(|| proof_dir.join("proof.json"));
    let mut config = LeanProofProducerConfig::new(&proof_dir);
    if !claim_ids.is_empty() {
        config.claim_ids = claim_ids;
    }
    if let Some(invocation_id) = invocation_id {
        config.tool_invocation_id = invocation_id;
    }
    config.timestamp_ticks = ticks;
    config.logical_epoch = SecurityEpoch::from_raw(epoch);
    config.command_timeout = Some(Duration::from_secs(timeout_secs));

    let report = write_lean_proof_artifact(&config, &out).map_err(|err| err.to_string())?;

    let verdict = match &report.artifact.checker_result {
        ProofCheckerResult::Passed => "passed",
        ProofCheckerResult::Failed { .. } => "failed",
        ProofCheckerResult::Unavailable { .. } => "unavailable",
        ProofCheckerResult::Inconclusive { .. } => "inconclusive",
        ProofCheckerResult::FixtureOnly { .. } => "fixture_only",
    };
    println!(
        "{}",
        serde_json::json!({
            "schema": "franken-engine.lean-proof-producer-summary.v1",
            "proof_json": out.display().to_string(),
            "verdict": verdict,
            "checker_result": report.artifact.checker_result,
            "claim_ids": report.artifact.claim_ids,
            "theorem_count": report.theorem_ids.len(),
            "theorem_ids": report.theorem_ids,
            "tool_identity": report.artifact.tool_identity.to_string(),
            "content_hash": format!("{:?}", report.artifact.content_hash()),
        })
    );

    if matches!(report.artifact.checker_result, ProofCheckerResult::Passed) {
        Ok(0)
    } else {
        // Non-Passed artifacts are written for triage but must never read as
        // success: mirror the degraded/insufficient-data exit-code convention.
        Ok(4)
    }
}
