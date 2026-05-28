#![forbid(unsafe_code)]
//! Track-G proof bundle emitter (bd-cixqu.7.17.1 part 4).
//!
//! Drives `PolicyTheoremEngine` through a representative policy-rule
//! configuration, generates the Monotonicity / NonInterference / Attenuation
//! theorem corpus, verifies each through the real Z3 backend (when available),
//! and writes the per-claim `<FE-CLAIM-NNN>.proof.json` bundles into
//! `artifacts/rgc_theorem_backed_compiler_inputs/` so the
//! `scripts/run_fe_claim_016_021_promotion_gate.sh` gate sees fresh proofs.
//!
//! This binary is the part-4 "hook emit_proof_bundles into a binary or test
//! path" deliverable from bd-cixqu.7.17.1; the engine work (valid SMT-LIB +
//! default axioms) is the prerequisite that finally lets Z3 reach `unsat` on
//! non-trivial NI obligations.
//!
//! Usage:
//!   cargo run --release -p frankenengine-engine --bin emit_track_g_proof_bundles
//!
//! Environment:
//!   TRACK_G_BUNDLE_DIR   override the output directory (default:
//!                        artifacts/rgc_theorem_backed_compiler_inputs)
//!
//! Exit codes:
//!   0   bundles emitted; rerun the promotion gate to consume them
//!   1   Z3 is not on PATH or returned unsat on no theorem
//!   2   structural error (file write failed, etc.)

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::ExitCode;

use frankenengine_engine::policy_theorem_engine::{
    PolicyProperty, PolicyRule, PolicyTheoremEngine, SmtLogic, SmtSolver,
};

fn main() -> ExitCode {
    let bundle_dir: PathBuf = std::env::var("TRACK_G_BUNDLE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts/rgc_theorem_backed_compiler_inputs"));

    eprintln!("[track-g] bundle dir: {}", bundle_dir.display());

    let mut engine = PolicyTheoremEngine::new();
    engine.smt_context.solver_backend = SmtSolver::Z3;
    // ALL maps to Z3's `(set-logic ALL)` — enables quantifiers + all theories
    // so the engine-grounded axioms can instantiate against the obligation
    // shape.
    engine.smt_context.logic = SmtLogic::ALL;

    // Seed a monotonicity rule so generate_monotonicity_theorems produces
    // theorems for FE-CLAIM-018 (the policy-semantics row). The engine's
    // default decision lattice + the engine-grounded `policy_eval` monotonicity
    // axiom together prove the theorem's `ordering` obligation under Z3.
    engine.add_policy_rule(PolicyRule {
        rule_id: "default_monotonic_policy".to_string(),
        rule_type: PolicyProperty::Monotonicity,
        premise: "Policy decisions preserve ordering".to_string(),
        conclusion: "policy_eval is monotonic on the decision lattice".to_string(),
        security_context: BTreeMap::new(),
        capability_constraints: Vec::new(),
    });

    // Seed an attenuation hierarchy so generate_attenuation_theorems produces
    // theorems; the parent/child pair `Admin > Read` is the smallest non-trivial
    // shape. (Both names become `(declare-const Admin Capability)` /
    // `(declare-const Read Capability)` in the SMT prelude.)
    let mut admin_children: BTreeSet<String> = BTreeSet::new();
    admin_children.insert("Read".to_string());
    engine.add_capability_attenuation("Admin".to_string(), admin_children);

    eprintln!("[track-g] generating theorems...");
    let m = engine
        .generate_monotonicity_theorems()
        .expect("monotonicity gen");
    let n = engine
        .generate_non_interference_theorems()
        .expect("non-interference gen");
    let a = engine
        .generate_attenuation_theorems()
        .expect("attenuation gen");
    eprintln!("[track-g] generated {m} monotonicity + {n} non-interference + {a} attenuation");

    eprintln!("[track-g] verifying with Z3 (this may take ~timeout per obligation)...");
    let report = match engine.verify_all_theorems() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[track-g] verify_all_theorems failed: {e}");
            return ExitCode::from(2);
        }
    };
    eprintln!(
        "[track-g] verification report: total={} verified={} failed={} (failed_ids={:?})",
        report.total_theorems, report.verified_theorems, report.failed_theorems, report.failed_theorem_ids
    );

    if report.verified_theorems == 0 {
        eprintln!(
            "[track-g] no theorems proven — refusing to emit. Inspect smt_context.axioms + the obligation shapes."
        );
        return ExitCode::from(1);
    }

    eprintln!("[track-g] emitting proof bundles...");
    let emitted = match engine.emit_proof_bundles(&bundle_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[track-g] emit_proof_bundles failed: {e}");
            return ExitCode::from(2);
        }
    };
    for bundle in &emitted {
        eprintln!(
            "[track-g] emitted {} ({} theorems) -> {}",
            bundle.claim_id,
            bundle.theorem_count,
            bundle.path.display()
        );
    }
    eprintln!(
        "[track-g] done. Recheck with: ./scripts/run_fe_claim_016_021_promotion_gate.sh ci {}",
        bundle_dir.display()
    );
    ExitCode::SUCCESS
}
