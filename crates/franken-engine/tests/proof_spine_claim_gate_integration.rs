#![forbid(unsafe_code)]

//! Integration lane for the proof-spine claim gate (bd-fqlfw.6.5, E6.T5).
//!
//! Exercises the acceptance matrix end-to-end through the real producers:
//! the Lean producer (with deterministic stub commands — the real-toolchain
//! lane lives in `lean_proof_producer_integration.rs`) feeds FE-CLAIM-016,
//! the translation-validation witness bridge feeds FE-CLAIM-017, and the
//! v2-deferred claims (FE-CLAIM-018..021) must stay HYPOTHESIS via
//! Unavailable even when handed a fabricated `Passed` artifact.

use std::fs;
use std::path::Path;

use frankenengine_engine::lean_proof_producer::{
    CommandSpec, LeanProofProducerConfig, produce_lean_proof_artifact,
};
use frankenengine_engine::proof_schema::{ProofCheckerResult, ProofProducerArtifact};
use frankenengine_engine::proof_spine_claim_gate::{
    ClaimSpineAction, ClaimSpineFailure, PROOF_SPINE_V2_DEFERRED_CLAIMS, decide_all_spine_claims,
    decide_claim_state,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::slot_registry::SlotId;
use frankenengine_engine::translation_validation_proof_carrier::{
    TranslationValidationProof, TranslationValidationWitnessArtifact, ValidationResult,
    create_slot_specification,
};

fn write_lean_fixture(dir: &Path) {
    fs::write(dir.join("lakefile.lean"), "import Lake\nopen Lake DSL\n").expect("lakefile");
    fs::write(dir.join("lean-toolchain"), "leanprover/lean4:4.7.0\n").expect("toolchain");
    fs::write(
        dir.join("IFCLatticeIsomorphism.lean"),
        "theorem rust_implementation_isomorphic : True := by trivial\n",
    )
    .expect("theorem");
}

fn lean_config(dir: &Path, build: CommandSpec) -> LeanProofProducerConfig {
    let mut config = LeanProofProducerConfig::new(dir);
    config.tool_invocation_id = "proof-spine-gate-integration".to_string();
    config.timestamp_ticks = 11;
    config.logical_epoch = SecurityEpoch::from_raw(3);
    config.command_timeout = None;
    config.lean_version = CommandSpec::new("sh").args(["-c", "printf 'Lean 4.7.0\\n'"]);
    config.lake_version = CommandSpec::new("sh").args(["-c", "printf 'Lake 5.0.0\\n'"]);
    config.lake_build = build;
    config
}

fn witness_proof(result: ValidationResult) -> TranslationValidationProof {
    TranslationValidationProof {
        proof_id: frankenengine_engine::engine_object_id::EngineObjectId([0x5Au8; 32]),
        source_spec: create_slot_specification(
            SlotId::new("src").expect("src slot"),
            b"source program",
            "javascript",
        ),
        target_spec: create_slot_specification(
            SlotId::new("tgt").expect("tgt slot"),
            b"target program",
            "javascript",
        ),
        validation_result: result,
        validation_logs: vec![],
        formal_proof_ref: None,
        transformation_witness: vec![],
        test_case_digest: "digest".to_string(),
        validation_timestamp_ns: 99,
        security_epoch: SecurityEpoch::from_raw(3),
        zone: "proof-spine-gate-integration".to_string(),
    }
}

#[test]
fn green_lean_producer_promotes_fe_claim_016_through_the_gate() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_lean_fixture(temp.path());
    let config = lean_config(
        temp.path(),
        CommandSpec::new("sh").args(["-c", "printf 'build ok\\n'"]),
    );

    let report = produce_lean_proof_artifact(&config).expect("producer run");
    let verdict = decide_claim_state("FE-CLAIM-016", false, &[report.artifact]);

    assert_eq!(verdict.action, ClaimSpineAction::PromoteObserved);
    assert!(verdict.findings.iter().all(|f| f.failure.is_none()));
}

#[test]
fn broken_lean_build_keeps_fe_claim_016_hypothesis_with_precise_failure() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_lean_fixture(temp.path());
    let config = lean_config(
        temp.path(),
        CommandSpec::new("sh").args(["-c", "printf 'boom\\n' >&2; exit 3"]),
    );

    let report = produce_lean_proof_artifact(&config).expect("broken build yields artifact");
    let verdict = decide_claim_state("FE-CLAIM-016", false, &[report.artifact]);

    assert_eq!(verdict.action, ClaimSpineAction::StayHypothesis);
    assert!(matches!(
        verdict.findings[0].failure,
        Some(ClaimSpineFailure::BackendUnavailable { .. })
    ));
}

#[test]
fn regressed_lean_build_demotes_a_currently_observed_fe_claim_016() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_lean_fixture(temp.path());
    let config = lean_config(
        temp.path(),
        CommandSpec::new("sh").args(["-c", "printf 'boom\\n' >&2; exit 3"]),
    );

    let report = produce_lean_proof_artifact(&config).expect("artifact");
    let verdict = decide_claim_state("FE-CLAIM-016", true, &[report.artifact]);

    assert_eq!(verdict.action, ClaimSpineAction::Demote);
}

#[test]
fn witness_bridge_drives_fe_claim_017_promote_and_demote() {
    let proven = TranslationValidationWitnessArtifact::from_proof(
        "full-ir-validator",
        &witness_proof(ValidationResult::Success {
            test_cases_passed: 16,
            test_cases_total: 16,
            success_rate_percent: 100,
        }),
    )
    .to_proof_producer_artifact();
    let verdict = decide_claim_state("FE-CLAIM-017", false, std::slice::from_ref(&proven));
    assert_eq!(verdict.action, ClaimSpineAction::PromoteObserved);

    let counterexample = TranslationValidationWitnessArtifact::from_proof(
        "iterator-validator",
        &witness_proof(ValidationResult::Failed {
            test_cases_passed: 15,
            test_cases_total: 16,
            success_rate_percent: 93,
            failure_reasons: vec!["iterator close order diverged".to_string()],
        }),
    )
    .to_proof_producer_artifact();
    // A counterexample in the pool beats the proven artifact: demote.
    let verdict = decide_claim_state("FE-CLAIM-017", true, &[proven, counterexample]);
    assert_eq!(verdict.action, ClaimSpineAction::Demote);
    assert!(verdict.findings.iter().any(|f| matches!(
        f.failure,
        Some(ClaimSpineFailure::CounterexampleFound { .. })
    )));
}

#[test]
fn v2_deferred_claims_stay_hypothesis_even_with_fabricated_passed_artifacts() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_lean_fixture(temp.path());
    let config = lean_config(
        temp.path(),
        CommandSpec::new("sh").args(["-c", "printf 'build ok\\n'"]),
    );
    let mut fabricated: ProofProducerArtifact = produce_lean_proof_artifact(&config)
        .expect("artifact")
        .artifact;
    assert_eq!(fabricated.checker_result, ProofCheckerResult::Passed);

    for claim_id in PROOF_SPINE_V2_DEFERRED_CLAIMS {
        fabricated.claim_ids = vec![claim_id.to_string()];
        fabricated.signature_or_content_hash =
            frankenengine_engine::proof_schema::ProofSignatureOrContentHash::ContentHash(
                fabricated.content_hash(),
            );
        let verdict = decide_claim_state(claim_id, false, std::slice::from_ref(&fabricated));
        assert_eq!(
            verdict.action,
            ClaimSpineAction::StayHypothesis,
            "{claim_id} must never promote in proof-spine v1"
        );
        assert!(matches!(
            verdict.findings[0].failure,
            Some(ClaimSpineFailure::V2Deferred { .. })
        ));
    }
}

#[test]
fn whole_spine_sweep_reports_every_claim_deterministically() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_lean_fixture(temp.path());
    let config = lean_config(
        temp.path(),
        CommandSpec::new("sh").args(["-c", "printf 'build ok\\n'"]),
    );
    let lean = produce_lean_proof_artifact(&config)
        .expect("artifact")
        .artifact;

    let verdicts = decide_all_spine_claims(&[], std::slice::from_ref(&lean));
    assert_eq!(verdicts.len(), 6, "2 v1 claims + 4 v2-deferred claims");

    let by_claim = |id: &str| {
        verdicts
            .iter()
            .find(|v| v.claim_id == id)
            .unwrap_or_else(|| panic!("verdict for {id}"))
    };
    assert_eq!(
        by_claim("FE-CLAIM-016").action,
        ClaimSpineAction::PromoteObserved
    );
    // No translation-validation artifact in the pool: producer did not run.
    assert_eq!(
        by_claim("FE-CLAIM-017").action,
        ClaimSpineAction::StayHypothesis
    );
    assert!(matches!(
        by_claim("FE-CLAIM-017").findings[0].failure,
        Some(ClaimSpineFailure::ProducerDidNotRun { ref expected_tool })
            if expected_tool == "translation-validator"
    ));
    for deferred in PROOF_SPINE_V2_DEFERRED_CLAIMS {
        assert_eq!(by_claim(deferred).action, ClaimSpineAction::StayHypothesis);
    }

    // Determinism: the same pool yields byte-identical verdict JSON.
    let first = serde_json::to_string(&verdicts).expect("serialize");
    let second = serde_json::to_string(&decide_all_spine_claims(&[], std::slice::from_ref(&lean)))
        .expect("serialize");
    assert_eq!(first, second);
}
