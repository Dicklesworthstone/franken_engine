#![forbid(unsafe_code)]

//! Real-toolchain integration lane for the E6.T2 Lean proof producer
//! (bd-fqlfw.6.2).
//!
//! These tests drive the *actual* `lake` / `lean` binaries — no mocked
//! command specs. Skip-vs-fail discipline: when the external toolchain is
//! absent the lane records an explicit skip (an evidence state distinct from
//! "green"), mirroring the cross-repo suite convention; it never fakes a
//! verdict.
//!
//! Two lanes:
//! - green corpus: `proofs/lean4/` builds green and yields a `Passed`
//!   artifact that `validate_proof_producer_artifact` accepts for
//!   FE-CLAIM-016. This lane additionally requires the mathlib package cache
//!   to be present (a cold fetch inside a unit test would be a network
//!   dependency, which this suite refuses).
//! - broken corpus: a self-contained temp package (no external requires)
//!   with a false theorem must yield `Unavailable`, and the strict validator
//!   must reject the artifact as non-promotable.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use frankenengine_engine::lean_proof_producer::{
    LEAN_PROOF_CLAIM_ID, LeanProofProducerConfig, produce_lean_proof_artifact,
    write_lean_proof_artifact,
};
use frankenengine_engine::proof_schema::{
    ProofCheckerResult, ProofProducerArtifact, validate_proof_producer_artifact,
};

fn repo_proof_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("proofs/lean4")
}

fn toolchain_available() -> bool {
    let has = |program: &str| {
        Command::new(program)
            .arg("--version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    };
    has("lake") && has("lean")
}

#[test]
fn green_lake_build_yields_passed_artifact_for_fe_claim_016() {
    if !toolchain_available() {
        eprintln!("SKIP: lake/lean toolchain not on PATH — real-toolchain lane not exercised");
        return;
    }
    let proof_dir = repo_proof_dir();
    if !proof_dir.join(".lake/packages/mathlib").is_dir() {
        eprintln!(
            "SKIP: mathlib package cache absent under {} — cold fetch is a network \
             dependency this suite refuses; run `lake build` there once (or \
             scripts/run_lean_proof_check.sh ci) to enable this lane",
            proof_dir.display()
        );
        return;
    }

    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("FE-CLAIM-016.proof.json");
    let mut config = LeanProofProducerConfig::new(&proof_dir);
    config.tool_invocation_id = "lean-proof-producer-integration-green".to_string();
    // The warm-cache corpus rebuild is quick, but a cold `.lake/build` for the
    // repo libraries can take a few minutes; keep the default 300s timeout.

    let report = write_lean_proof_artifact(&config, &out_path).expect("producer run");

    assert_eq!(
        report.artifact.checker_result,
        ProofCheckerResult::Passed,
        "repo Lean corpus must build green; checker said: {:?}",
        report.artifact.checker_result
    );
    assert_eq!(report.artifact.claim_ids, vec![LEAN_PROOF_CLAIM_ID]);
    validate_proof_producer_artifact(&report.artifact)
        .expect("strict schema must accept a Passed artifact from the real corpus");

    // The flagship isomorphism theorems must be part of the checked corpus.
    for theorem in [
        "rust_implementation_isomorphic",
        "rust_satisfies_lattice_axioms",
        "rust_flow_properties",
    ] {
        assert!(
            report.theorem_ids.iter().any(|id| id == theorem),
            "theorem `{theorem}` missing from checked corpus: {:?}",
            report.theorem_ids
        );
    }

    // The written proof.json round-trips and still validates.
    let written: ProofProducerArtifact =
        serde_json::from_slice(&fs::read(&out_path).expect("read proof.json")).expect("json");
    assert_eq!(written, report.artifact);
    validate_proof_producer_artifact(&written).expect("round-tripped artifact validates");

    // Tool identity captured from the real toolchain, not a placeholder.
    assert!(written.tool_identity.tool_version.contains("lean:"));
    assert!(!written.tool_identity.tool_version.contains("unavailable"));
}

#[test]
fn broken_lake_build_yields_unavailable_artifact() {
    if !toolchain_available() {
        eprintln!("SKIP: lake/lean toolchain not on PATH — real-toolchain lane not exercised");
        return;
    }

    // Self-contained package: no `require`, so no network fetch. The pinned
    // toolchain file matches the repo corpus so elan resolves the same
    // already-installed Lean.
    let temp = tempfile::tempdir().expect("tempdir");
    let toolchain = fs::read_to_string(repo_proof_dir().join("lean-toolchain"))
        .unwrap_or_else(|_| "leanprover/lean4:v4.7.0\n".to_string());
    fs::write(temp.path().join("lean-toolchain"), toolchain).expect("write lean-toolchain");
    fs::write(
        temp.path().join("lakefile.lean"),
        "import Lake\nopen Lake DSL\n\npackage broken\n\n@[default_target]\nlean_lib \
         \u{ab}Broken\u{bb} where\n",
    )
    .expect("write lakefile");
    fs::write(
        temp.path().join("Broken.lean"),
        "theorem broken_claim : False := by trivial\n",
    )
    .expect("write broken theorem");

    let mut config = LeanProofProducerConfig::new(temp.path());
    config.tool_invocation_id = "lean-proof-producer-integration-broken".to_string();

    let report = produce_lean_proof_artifact(&config).expect("broken build still yields artifact");

    assert!(
        matches!(
            report.artifact.checker_result,
            ProofCheckerResult::Unavailable { ref reason } if reason.contains("lake build")
        ),
        "broken build must be Unavailable, got: {:?}",
        report.artifact.checker_result
    );
    assert!(report.theorem_ids.is_empty());
    // A non-Passed artifact must never validate as promotable evidence.
    validate_proof_producer_artifact(&report.artifact)
        .expect_err("strict schema must reject an Unavailable artifact");
}
