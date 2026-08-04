#![forbid(unsafe_code)]
//! Integration tests for the corpus promotion pipeline (bd-cixqu.21.2, Track U.2).
//!
//! The pipeline minimizes a successful red-team attack, gates it through the
//! acquisition-experiment oracle so only genuine reproduced bypasses are
//! admitted, and renders a corpus-conformant `red-team-scenario.v1` manifest
//! pair. These tests exercise the four acceptance criteria and the three
//! required pins, all hermetically — the bypass oracle is the engine's own
//! ambient-authority containment (parse -> lower -> observe the verdict), with
//! no external runtime.
//!
//! Pins:
//!   * minimization is deterministic (`pin_minimization_is_deterministic`)
//!   * the promoted scenario reproduces the bypass and is corpus-schema valid
//!     (`pin_promoted_scenario_reproduces_bypass_and_is_schema_valid`)
//!   * the oracle rejects a non-reproducing candidate
//!     (`pin_oracle_rejects_non_reproducing_candidate`)

use std::cell::Cell;
use std::path::PathBuf;

use frankenengine_engine::corpus_promotion::{
    self, AttackCandidate, DEFAULT_REPRODUCTION_TRIALS, PromotedLedger, RED_TEAM_BASELINE_VERSION,
    RED_TEAM_SCENARIO_SCHEMA_VERSION,
};
use frankenengine_engine::hierarchical_delta_debug::StepOutcome;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringPipelineError, lower_ir0_to_ir1};
use frankenengine_engine::parser_api_stability::parse_module;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Engine-backed bypass oracle
// ---------------------------------------------------------------------------

/// A program "reproduces the bypass" when it still trips FrankenEngine's
/// ambient-authority containment at lowering time — the same `fail_closed`
/// signal the curated red-team corpus asserts. Deterministic: identical source
/// yields an identical verdict.
fn containment_oracle(source: &str) -> StepOutcome {
    let tree = match parse_module(source) {
        Ok(tree) => tree,
        Err(_) => return StepOutcome::SyntaxError,
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "corpus-promotion-candidate");
    match lower_ir0_to_ir1(&ir0) {
        Err(LoweringPipelineError::AmbientAuthorityViolation { .. }) => {
            StepOutcome::DefectPreserved
        }
        _ => StepOutcome::DefectLost,
    }
}

/// A genuine ambient-authority attack: reading `process` off `globalThis`
/// reaches ambient authority (`EnvRead`) even though `process` is never a free
/// identifier. The essential line is `const ambient = globalThis.process;`; the
/// surrounding `decoy*` bindings are removable filler that minimization strips.
fn ambient_authority_candidate() -> AttackCandidate {
    let source = concat!(
        "\"use strict\";\n",
        "const decoyPreambleValue = \"harmless-preamble-string-value\";\n",
        "const decoyCounterValue = 987654321;\n",
        "const ambient = globalThis.process;\n",
        "const decoyTrailerValue = \"harmless-trailer-string-value\";\n",
    );
    let mut candidate = AttackCandidate::new(
        "promoted_globalthis_ambient_env_read",
        "globalThis ambient env read bypasses static capability scan",
        "promoted_globalthis_ambient_env_read",
        source,
        "ambient_authority_via_globalthis_rejected",
    );
    candidate.cwe = vec!["CWE-470".to_string(), "CWE-668".to_string()];
    candidate.node_observable =
        "process env surface reached via globalThis.process alias".to_string();
    candidate.bun_observable =
        "process env surface reached via globalThis.process alias".to_string();
    candidate.frankenengine_observable =
        "capability-typed lowering rejects the globalThis.process member access with \
         AmbientAuthorityViolation (EnvRead) before the alias is bound"
            .to_string();
    candidate.failure_signal =
        "lowering refuses the ambient member access at compile time".to_string();
    candidate
}

/// A benign program: no ambient authority, so the containment oracle never
/// reports a bypass. Used as a non-reproducing candidate.
fn benign_candidate() -> AttackCandidate {
    let source = concat!(
        "\"use strict\";\n",
        "const first = 1 + 2;\n",
        "const second = first * 3;\n",
        "const third = second - 1;\n",
    );
    AttackCandidate::new(
        "benign_arithmetic_non_attack",
        "benign arithmetic that never reaches ambient authority",
        "benign_arithmetic_non_attack",
        source,
        "never_denied",
    )
}

// ---------------------------------------------------------------------------
// Schema conformance helper (mirrors the authoritative corpus validator)
// ---------------------------------------------------------------------------

fn nested<'a>(manifest: &'a Value, path: &[&str]) -> &'a Value {
    let mut value = manifest;
    for key in path {
        value = value
            .get(*key)
            .unwrap_or_else(|| panic!("manifest missing nested field {}", path.join(".")));
    }
    value
}

fn nested_str<'a>(manifest: &'a Value, path: &[&str]) -> &'a str {
    nested(manifest, path)
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            panic!(
                "manifest field {} must be a non-empty string",
                path.join(".")
            )
        })
}

/// Assert the promoted manifest satisfies every field the curated
/// `red_team_scenario_manifest_validation` gate enforces.
fn assert_corpus_schema_valid(manifest_json: &str, name: &str) {
    let manifest: Value =
        serde_json::from_str(manifest_json).expect("promoted manifest must parse as JSON");

    assert_eq!(
        nested_str(&manifest, &["schema_version"]),
        RED_TEAM_SCENARIO_SCHEMA_VERSION
    );
    assert_eq!(
        nested_str(&manifest, &["baseline_version"]),
        RED_TEAM_BASELINE_VERSION
    );
    assert_eq!(nested_str(&manifest, &["name"]), name);
    assert_eq!(
        nested_str(&manifest, &["payload", "program"]),
        format!("{name}.js")
    );
    assert!(!nested_str(&manifest, &["payload", "success_criteria"]).is_empty());

    assert_eq!(
        nested_str(&manifest, &["expected_outcome", "node", "outcome"]),
        "succeeds"
    );
    assert_eq!(
        nested_str(&manifest, &["expected_outcome", "bun", "outcome"]),
        "succeeds"
    );
    assert_eq!(
        nested_str(&manifest, &["expected_outcome", "frankenengine", "outcome"]),
        "fail_closed"
    );
    assert!(!nested_str(&manifest, &["expected_outcome", "node", "observable"]).is_empty());
    assert!(!nested_str(&manifest, &["expected_outcome", "bun", "observable"]).is_empty());
    assert!(
        !nested_str(
            &manifest,
            &["expected_outcome", "frankenengine", "denial_reason"]
        )
        .is_empty()
    );
    assert!(!nested_str(&manifest, &["measurement", "success_signal"]).is_empty());
    assert!(!nested_str(&manifest, &["measurement", "failure_signal"]).is_empty());
}

/// Assert a promoted `<name>.js` program still trips ambient-authority
/// containment at lowering time — i.e. the bypass reproduces.
fn assert_program_reproduces_containment(program_js: &str) {
    assert_eq!(
        containment_oracle(program_js),
        StepOutcome::DefectPreserved,
        "promoted program must still be contained (fail_closed) at lowering time"
    );
}

fn unique_temp_dir(test_name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("franken_corpus_promotion_u2_{test_name}"))
}

// ---------------------------------------------------------------------------
// Pin 1 — minimization is deterministic
// ---------------------------------------------------------------------------

#[test]
fn pin_minimization_is_deterministic() {
    let candidate = ambient_authority_candidate();

    let (repro_a, trace_a) = corpus_promotion::minimize_attack(&candidate, containment_oracle);
    let (repro_b, trace_b) = corpus_promotion::minimize_attack(&candidate, containment_oracle);

    // Byte-identical minimization across independent runs.
    assert_eq!(
        repro_a.repro_id, repro_b.repro_id,
        "repro id must be deterministic"
    );
    assert_eq!(
        repro_a.source, repro_b.source,
        "minimized source must be deterministic"
    );
    assert_eq!(trace_a, trace_b, "minimization trace must be deterministic");

    // Minimization actually shrank the program.
    assert!(
        repro_a.reduced_size < repro_a.original_size,
        "minimization must remove at least one fragment ({} -> {})",
        repro_a.original_size,
        repro_a.reduced_size
    );

    // The essential ambient access survived and still reproduces the bypass; the
    // removable decoy bindings did not.
    assert!(
        repro_a.source.contains("globalThis.process"),
        "the essential ambient access must be preserved, got: {:?}",
        repro_a.source
    );
    assert!(
        !repro_a.source.contains("decoyPreambleValue")
            && !repro_a.source.contains("decoyTrailerValue"),
        "removable decoy bindings must be minimized away, got: {:?}",
        repro_a.source
    );
    assert_eq!(
        containment_oracle(&repro_a.source),
        StepOutcome::DefectPreserved
    );
}

// ---------------------------------------------------------------------------
// Pin 2 — the promoted scenario reproduces the bypass and is schema valid
// ---------------------------------------------------------------------------

#[test]
fn pin_promoted_scenario_reproduces_bypass_and_is_schema_valid() {
    let candidate = ambient_authority_candidate();
    let ledger = PromotedLedger::new();

    let plan = corpus_promotion::build_promotion_plan(
        std::slice::from_ref(&candidate),
        &ledger,
        DEFAULT_REPRODUCTION_TRIALS,
        containment_oracle,
    );

    assert_eq!(
        plan.promoted_count, 1,
        "the reproduced bypass must be admitted"
    );
    assert_eq!(plan.skipped_count, 0);
    let proposal = &plan.proposals[0];

    // The gate admitted it on the strength of full reproduction and zero regret.
    assert!(proposal.verdict.admitted);
    assert_eq!(
        proposal.verdict.reproduced_trials,
        DEFAULT_REPRODUCTION_TRIALS
    );
    assert_eq!(proposal.verdict.total_trials, DEFAULT_REPRODUCTION_TRIALS);
    assert_eq!(proposal.verdict.regret_millionths, 0);

    // The promoted program carries the provenance marker and STILL reproduces
    // the bypass (fails closed) at lowering time — a live regression contract.
    assert!(
        proposal
            .scenario
            .program_js
            .contains(corpus_promotion::CORPUS_PROMOTION_MARKER)
    );
    assert_program_reproduces_containment(&proposal.scenario.program_js);

    // The manifest satisfies the curated corpus schema contract verbatim.
    assert_corpus_schema_valid(&proposal.scenario.manifest_json, &candidate.name);
}

// ---------------------------------------------------------------------------
// Pin 3 — the oracle rejects a non-reproducing candidate
// ---------------------------------------------------------------------------

#[test]
fn pin_oracle_rejects_non_reproducing_candidate() {
    let candidate = benign_candidate();
    let ledger = PromotedLedger::new();

    let plan = corpus_promotion::build_promotion_plan(
        std::slice::from_ref(&candidate),
        &ledger,
        DEFAULT_REPRODUCTION_TRIALS,
        containment_oracle,
    );

    // Nothing is promoted; the candidate is skipped with a recorded verdict.
    assert_eq!(
        plan.promoted_count, 0,
        "a non-reproducing candidate must not be promoted"
    );
    assert_eq!(plan.skipped_count, 1);
    let skipped = &plan.skipped[0];
    assert_eq!(skipped.candidate_name, candidate.name);
    let verdict = skipped
        .verdict
        .as_ref()
        .expect("a gated rejection carries a verdict");
    assert!(!verdict.admitted);
    assert_eq!(verdict.reproduced_trials, 0);
    // Zero reproduction -> zero realized gain -> maximal regret.
    assert_eq!(verdict.actual_gain_millionths, 0);
    assert_eq!(verdict.regret_millionths, verdict.expected_gain_millionths);
}

#[test]
fn flaky_candidate_is_rejected_by_the_gate() {
    // A flaky oracle reproduces on some trials but not others: the gate demands
    // full reproduction, so partial stability is rejected.
    let candidate = ambient_authority_candidate();
    let counter = Cell::new(0u32);
    let flaky = |_source: &str| -> StepOutcome {
        let n = counter.get();
        counter.set(n + 1);
        if n.is_multiple_of(2) {
            StepOutcome::DefectPreserved
        } else {
            StepOutcome::DefectLost
        }
    };

    let verdict = corpus_promotion::gate_candidate(
        &candidate,
        &candidate.source,
        DEFAULT_REPRODUCTION_TRIALS,
        &flaky,
    );

    assert!(!verdict.admitted, "a flaky candidate must not be admitted");
    assert!(verdict.reproduced_trials < verdict.total_trials);
    assert!(
        verdict.regret_millionths > 0,
        "partial reproduction must incur regret"
    );
}

// ---------------------------------------------------------------------------
// Determinism of the plan digest
// ---------------------------------------------------------------------------

#[test]
fn plan_digest_is_stable_across_runs_and_sensitive_to_inputs() {
    let candidate = ambient_authority_candidate();
    let ledger = PromotedLedger::new();

    let plan_a = corpus_promotion::build_promotion_plan(
        std::slice::from_ref(&candidate),
        &ledger,
        DEFAULT_REPRODUCTION_TRIALS,
        containment_oracle,
    );
    let plan_b = corpus_promotion::build_promotion_plan(
        std::slice::from_ref(&candidate),
        &ledger,
        DEFAULT_REPRODUCTION_TRIALS,
        containment_oracle,
    );
    assert_eq!(
        plan_a.plan_digest, plan_b.plan_digest,
        "identical inputs -> identical digest"
    );

    // A different candidate set yields a different digest.
    let benign = benign_candidate();
    let plan_c = corpus_promotion::build_promotion_plan(
        &[candidate, benign],
        &ledger,
        DEFAULT_REPRODUCTION_TRIALS,
        containment_oracle,
    );
    assert_ne!(
        plan_a.plan_digest, plan_c.plan_digest,
        "a changed candidate set must change the digest"
    );
}

// ---------------------------------------------------------------------------
// Idempotency via the ledger
// ---------------------------------------------------------------------------

#[test]
fn promotion_is_idempotent_via_ledger() {
    let candidate = ambient_authority_candidate();
    let mut ledger = PromotedLedger::new();

    // First promotion: admitted and executed into a fresh directory.
    let plan = corpus_promotion::build_promotion_plan(
        std::slice::from_ref(&candidate),
        &ledger,
        DEFAULT_REPRODUCTION_TRIALS,
        containment_oracle,
    );
    assert_eq!(plan.promoted_count, 1);

    let target = unique_temp_dir("idempotent");
    let audits = corpus_promotion::execute_plan(&plan, &target, &mut ledger)
        .expect("execute_plan writes the promoted pair");
    assert_eq!(audits.len(), 1);
    assert!(audits[0].program_path.is_file());
    assert!(audits[0].manifest_path.is_file());
    assert!(ledger.contains(&candidate.name));

    // Second planning run with the populated ledger: the candidate is skipped as
    // already-promoted, so nothing new is proposed.
    let replan = corpus_promotion::build_promotion_plan(
        std::slice::from_ref(&candidate),
        &ledger,
        DEFAULT_REPRODUCTION_TRIALS,
        containment_oracle,
    );
    assert_eq!(
        replan.promoted_count, 0,
        "an already-promoted candidate must not re-promote"
    );
    assert_eq!(replan.skipped_count, 1);
    assert!(replan.skipped[0].reason.contains("already promoted"));
}

// ---------------------------------------------------------------------------
// Execute writes a corpus-valid, reproducing pair to disk
// ---------------------------------------------------------------------------

#[test]
fn execute_plan_writes_corpus_valid_reproducing_pair() {
    let candidate = ambient_authority_candidate();
    let mut ledger = PromotedLedger::new();

    let plan = corpus_promotion::build_promotion_plan(
        std::slice::from_ref(&candidate),
        &ledger,
        DEFAULT_REPRODUCTION_TRIALS,
        containment_oracle,
    );
    let target = unique_temp_dir("execute");
    let audits = corpus_promotion::execute_plan(&plan, &target, &mut ledger)
        .expect("execute_plan writes the promoted pair");
    assert_eq!(audits.len(), 1);

    // Re-read from disk and re-validate: the written manifest is corpus-schema
    // valid and the written program still reproduces containment.
    let program = std::fs::read_to_string(&audits[0].program_path).expect("program readable");
    let manifest = std::fs::read_to_string(&audits[0].manifest_path).expect("manifest readable");
    assert_corpus_schema_valid(&manifest, &candidate.name);
    assert_program_reproduces_containment(&program);
}

// ---------------------------------------------------------------------------
// Logging discipline (bd-cixqu.45): the trace and verdict are serializable
// ---------------------------------------------------------------------------

#[test]
fn minimization_trace_and_oracle_verdict_are_serializable() {
    let candidate = ambient_authority_candidate();
    let ledger = PromotedLedger::new();
    let plan = corpus_promotion::build_promotion_plan(
        std::slice::from_ref(&candidate),
        &ledger,
        DEFAULT_REPRODUCTION_TRIALS,
        containment_oracle,
    );
    let proposal = &plan.proposals[0];

    let trace_json =
        serde_json::to_string(&proposal.minimization).expect("trace serializes to JSON");
    let verdict_json =
        serde_json::to_string(&proposal.verdict).expect("verdict serializes to JSON");

    assert!(trace_json.contains("repro_id"));
    assert!(trace_json.contains(&proposal.minimization.repro_id));
    assert!(verdict_json.contains("regret_millionths"));

    // Round-trip both structured logs.
    let trace_back: Value = serde_json::from_str(&trace_json).expect("trace round-trips");
    let verdict_back: Value = serde_json::from_str(&verdict_json).expect("verdict round-trips");
    assert_eq!(trace_back["candidate_name"], candidate.name);
    assert_eq!(verdict_back["admitted"], Value::Bool(true));
}

// ---------------------------------------------------------------------------
// Committed golden corpus (AC2)
// ---------------------------------------------------------------------------
//
// The pipeline promotes a minimized bypass into
// `tests/red_team_scenarios/promoted/` as a committed regression. That
// subdirectory is deliberately invisible to the curated-corpus scanners (they
// filter to top-level `*.js`), so the committed golden is validated only by the
// guard below: a hermetic regression that is green on a build that still
// contains the attack and red if containment ever regresses.

fn promoted_golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/red_team_scenarios/promoted")
}

/// Regenerate the committed golden corpus by running the pipeline end to end and
/// writing the promoted manifest pair. Ignored in normal runs; invoke manually
/// with `--ignored` to refresh the golden after an intentional pipeline change.
#[test]
#[ignore = "golden regenerator; run with --ignored to refresh tests/red_team_scenarios/promoted/"]
fn regenerate_promoted_corpus_golden() {
    let candidate = ambient_authority_candidate();
    let mut ledger = PromotedLedger::new();
    let plan = corpus_promotion::build_promotion_plan(
        std::slice::from_ref(&candidate),
        &ledger,
        DEFAULT_REPRODUCTION_TRIALS,
        containment_oracle,
    );
    assert_eq!(
        plan.promoted_count, 1,
        "the golden candidate must be admitted"
    );
    let audits = corpus_promotion::execute_plan(&plan, &promoted_golden_dir(), &mut ledger)
        .expect("execute_plan writes the golden pair");
    assert_eq!(audits.len(), 1);
}

/// Guard: every committed promoted scenario is corpus-schema valid and still
/// reproduces containment at lowering time — the regression contract.
#[test]
fn promoted_corpus_golden_is_schema_valid_and_reproduces() {
    let dir = promoted_golden_dir();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("promoted corpus dir {dir:?} must be readable: {err}"));

    let mut checked = 0usize;
    for entry in entries {
        let path = entry.expect("readable dir entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("js") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("promoted program has a UTF-8 stem");
        let program = std::fs::read_to_string(&path).expect("promoted program readable");
        let manifest_path = dir.join(format!("{stem}.manifest.json"));
        let manifest = std::fs::read_to_string(&manifest_path).expect("promoted manifest readable");

        assert_corpus_schema_valid(&manifest, stem);
        assert_program_reproduces_containment(&program);
        checked += 1;
    }

    assert!(
        checked >= 1,
        "expected at least one committed promoted scenario in {dir:?}"
    );
}
