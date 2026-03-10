//! Integration tests for the `frontier_demo_gate` module.
#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::frontier_demo_gate::*;
use frankenengine_engine::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_gate_id(suffix: &str) -> EngineObjectId {
    derive_id(
        ObjectDomain::EvidenceRecord,
        suffix,
        &SchemaId::from_definition(b"frontier-demo-gate"),
        b"frontier-demo-gate",
    )
    .unwrap()
}

fn test_artifact(category: ArtifactCategory, suffix: &str) -> DemoArtifact {
    DemoArtifact {
        artifact_id: test_gate_id(suffix),
        category,
        content_hash: ContentHash::compute(suffix.as_bytes()),
        producing_commit: "abc123".to_string(),
        test_run_id: "run-001".to_string(),
        summary: format!("test artifact for {category}"),
        public_eligible: true,
    }
}

fn passing_verification(artifact: &DemoArtifact) -> ArtifactVerification {
    ArtifactVerification {
        artifact_id: artifact.artifact_id.clone(),
        category: artifact.category,
        schema_compliant: true,
        integrity_valid: true,
        reproducible: true,
        external_verification: Some(VerificationResult::Passed {
            details: "external check ok".to_string(),
        }),
        overall: VerificationResult::Passed {
            details: "all checks passed".to_string(),
        },
    }
}

fn failing_verification(artifact: &DemoArtifact, reason: &str) -> ArtifactVerification {
    ArtifactVerification {
        artifact_id: artifact.artifact_id.clone(),
        category: artifact.category,
        schema_compliant: true,
        integrity_valid: true,
        reproducible: false,
        external_verification: None,
        overall: VerificationResult::Failed {
            reason: reason.to_string(),
        },
    }
}

fn make_override() -> OverrideJustification {
    OverrideJustification {
        authorizer: "admin@example.com".to_string(),
        justification: "Emergency release approved by CTO".to_string(),
        signature: "sig-abc123".to_string(),
    }
}

/// Build a GateEvaluationInput that satisfies all required categories for a
/// program, with passing verifications and external verification present.
fn fully_passing_input(program: FrontierProgram, gate_suffix: &str) -> GateEvaluationInput {
    let gate = GateDefinition::for_program(program, test_gate_id(gate_suffix));
    let mut artifacts = Vec::new();
    let mut verifications = Vec::new();

    for (i, category) in gate.required_categories.iter().enumerate() {
        let suffix = format!("{gate_suffix}-art-{i}");
        let artifact = test_artifact(*category, &suffix);
        verifications.push(passing_verification(&artifact));
        artifacts.push(artifact);
    }

    GateEvaluationInput {
        gate,
        artifacts,
        verifications,
        override_justification: None,
    }
}

// ===========================================================================
// 1. FrontierProgram
// ===========================================================================

#[test]
fn frontier_program_all_returns_ten() {
    assert_eq!(FrontierProgram::all().len(), 10);
}

#[test]
fn frontier_program_codes_are_unique() {
    let codes: BTreeSet<&str> = FrontierProgram::all().iter().map(|p| p.code()).collect();
    assert_eq!(codes.len(), 10, "all 10 codes must be unique");
}

#[test]
fn frontier_program_codes_format_9h() {
    for p in FrontierProgram::all() {
        let code = p.code();
        assert!(code.starts_with("9H."), "code {code} must start with 9H.");
        let suffix: u32 = code.strip_prefix("9H.").unwrap().parse().unwrap();
        assert!((1..=10).contains(&suffix), "suffix must be 1..=10");
    }
}

#[test]
fn frontier_program_display_all_non_empty() {
    for p in FrontierProgram::all() {
        let display = p.to_string();
        assert!(!display.is_empty(), "display for {p:?} must not be empty");
    }
}

#[test]
fn frontier_program_display_specific_values() {
    assert_eq!(
        FrontierProgram::ProofCarryingOptimizer.to_string(),
        "Proof-Carrying Adaptive Optimizer"
    );
    assert_eq!(
        FrontierProgram::FleetImmuneSystem.to_string(),
        "Fleet Immune System"
    );
    assert_eq!(
        FrontierProgram::CausalTimeMachine.to_string(),
        "Causal Time-Machine"
    );
    assert_eq!(
        FrontierProgram::AttestedExecutionCells.to_string(),
        "Attested Execution Cells"
    );
    assert_eq!(
        FrontierProgram::PolicyTheoremEngine.to_string(),
        "Policy Theorem Engine"
    );
    assert_eq!(
        FrontierProgram::AutonomousRedBlue.to_string(),
        "Autonomous Red/Blue"
    );
    assert_eq!(
        FrontierProgram::TrustEconomics.to_string(),
        "Trust Economics"
    );
    assert_eq!(
        FrontierProgram::ReputationGraph.to_string(),
        "Reputation Graph"
    );
    assert_eq!(
        FrontierProgram::OperatorCopilot.to_string(),
        "Operator Copilot"
    );
    assert_eq!(
        FrontierProgram::BenchmarkStandard.to_string(),
        "Benchmark Standard"
    );
}

#[test]
fn frontier_program_serde_roundtrip() {
    for p in FrontierProgram::all() {
        let json = serde_json::to_string(p).unwrap();
        let back: FrontierProgram = serde_json::from_str(&json).unwrap();
        assert_eq!(*p, back);
    }
}

#[test]
fn frontier_program_ordering_consistent() {
    let all = FrontierProgram::all();
    for window in all.windows(2) {
        assert!(
            window[0] < window[1],
            "{:?} should be less than {:?}",
            window[0],
            window[1]
        );
    }
}

// ===========================================================================
// 2. ArtifactCategory
// ===========================================================================

#[test]
fn artifact_category_display_returns_variant_name() {
    assert_eq!(
        ArtifactCategory::TranslationValidation.to_string(),
        "TranslationValidation"
    );
    assert_eq!(
        ArtifactCategory::PerformanceBenchmark.to_string(),
        "PerformanceBenchmark"
    );
    assert_eq!(ArtifactCategory::RollbackTest.to_string(), "RollbackTest");
    assert_eq!(
        ArtifactCategory::ReplayFidelity.to_string(),
        "ReplayFidelity"
    );
}

#[test]
fn artifact_category_serde_roundtrip() {
    let categories = [
        ArtifactCategory::TranslationValidation,
        ArtifactCategory::PerformanceBenchmark,
        ArtifactCategory::RollbackTest,
        ArtifactCategory::ConvergenceMeasurement,
        ArtifactCategory::ErrorRateEvidence,
        ArtifactCategory::PartitionBehavior,
        ArtifactCategory::ReplayFidelity,
        ArtifactCategory::CounterfactualAnalysis,
        ArtifactCategory::CrossNodeReplay,
        ArtifactCategory::AttestationChain,
        ArtifactCategory::AttestationFallback,
        ArtifactCategory::PropertyProof,
        ArtifactCategory::CounterexampleEvidence,
        ArtifactCategory::CampaignEvolution,
        ArtifactCategory::DefenseImprovement,
        ArtifactCategory::DecisionScoring,
        ArtifactCategory::AttackerRoiTrend,
        ArtifactCategory::CompromiseWindowReduction,
        ArtifactCategory::OperatorWorkflow,
        ArtifactCategory::IndependentReproduction,
        ArtifactCategory::CrossRuntimeFairness,
    ];
    for c in &categories {
        let json = serde_json::to_string(c).unwrap();
        let back: ArtifactCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

#[test]
fn artifact_category_all_21_unique_display() {
    let categories = [
        ArtifactCategory::TranslationValidation,
        ArtifactCategory::PerformanceBenchmark,
        ArtifactCategory::RollbackTest,
        ArtifactCategory::ConvergenceMeasurement,
        ArtifactCategory::ErrorRateEvidence,
        ArtifactCategory::PartitionBehavior,
        ArtifactCategory::ReplayFidelity,
        ArtifactCategory::CounterfactualAnalysis,
        ArtifactCategory::CrossNodeReplay,
        ArtifactCategory::AttestationChain,
        ArtifactCategory::AttestationFallback,
        ArtifactCategory::PropertyProof,
        ArtifactCategory::CounterexampleEvidence,
        ArtifactCategory::CampaignEvolution,
        ArtifactCategory::DefenseImprovement,
        ArtifactCategory::DecisionScoring,
        ArtifactCategory::AttackerRoiTrend,
        ArtifactCategory::CompromiseWindowReduction,
        ArtifactCategory::OperatorWorkflow,
        ArtifactCategory::IndependentReproduction,
        ArtifactCategory::CrossRuntimeFairness,
    ];
    let displays: BTreeSet<String> = categories.iter().map(|c| c.to_string()).collect();
    assert_eq!(
        displays.len(),
        21,
        "all 21 categories must have unique Display"
    );
}

#[test]
fn artifact_category_display_no_whitespace_prefix() {
    let categories = [
        ArtifactCategory::TranslationValidation,
        ArtifactCategory::CompromiseWindowReduction,
        ArtifactCategory::CrossRuntimeFairness,
    ];
    for c in &categories {
        let s = c.to_string();
        assert_eq!(
            s,
            s.trim(),
            "display for {c:?} must not have leading/trailing whitespace"
        );
    }
}

// ===========================================================================
// 3. VerificationResult
// ===========================================================================

#[test]
fn verification_result_is_passed() {
    let passed = VerificationResult::Passed {
        details: "ok".to_string(),
    };
    assert!(passed.is_passed());
    assert!(!passed.is_failed());
}

#[test]
fn verification_result_is_failed() {
    let failed = VerificationResult::Failed {
        reason: "bad".to_string(),
    };
    assert!(failed.is_failed());
    assert!(!failed.is_passed());
}

#[test]
fn verification_result_skipped_is_neither() {
    let skipped = VerificationResult::Skipped {
        reason: "no verifier".to_string(),
    };
    assert!(!skipped.is_passed());
    assert!(!skipped.is_failed());
}

#[test]
fn verification_result_display() {
    let passed = VerificationResult::Passed {
        details: "ok".to_string(),
    };
    assert_eq!(passed.to_string(), "passed: ok");

    let failed = VerificationResult::Failed {
        reason: "bad".to_string(),
    };
    assert_eq!(failed.to_string(), "failed: bad");

    let skipped = VerificationResult::Skipped {
        reason: "no verifier".to_string(),
    };
    assert_eq!(skipped.to_string(), "skipped: no verifier");
}

#[test]
fn verification_result_serde_roundtrip() {
    let variants = [
        VerificationResult::Passed {
            details: "ok".to_string(),
        },
        VerificationResult::Failed {
            reason: "bad".to_string(),
        },
        VerificationResult::Skipped {
            reason: "no verifier".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: VerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// 4. ArtifactVerification
// ===========================================================================

#[test]
fn artifact_verification_passes_when_all_ok() {
    let artifact = test_artifact(ArtifactCategory::TranslationValidation, "av-ok");
    let v = passing_verification(&artifact);
    assert!(v.passes());
}

#[test]
fn artifact_verification_fails_on_schema_compliant_false() {
    let artifact = test_artifact(ArtifactCategory::TranslationValidation, "av-schema");
    let mut v = passing_verification(&artifact);
    v.schema_compliant = false;
    assert!(!v.passes());
}

#[test]
fn artifact_verification_fails_on_integrity_valid_false() {
    let artifact = test_artifact(ArtifactCategory::TranslationValidation, "av-integrity");
    let mut v = passing_verification(&artifact);
    v.integrity_valid = false;
    assert!(!v.passes());
}

#[test]
fn artifact_verification_fails_on_reproducible_false() {
    let artifact = test_artifact(ArtifactCategory::TranslationValidation, "av-repro");
    let mut v = passing_verification(&artifact);
    v.reproducible = false;
    assert!(!v.passes());
}

#[test]
fn artifact_verification_fails_on_overall_failed() {
    let artifact = test_artifact(ArtifactCategory::TranslationValidation, "av-overall");
    let mut v = passing_verification(&artifact);
    v.overall = VerificationResult::Failed {
        reason: "nope".to_string(),
    };
    assert!(!v.passes());
}

// ===========================================================================
// 5. GateDefinition
// ===========================================================================

#[test]
fn gate_definition_optimizer_requires_three_categories() {
    let gate =
        GateDefinition::for_program(FrontierProgram::ProofCarryingOptimizer, test_gate_id("g-1"));
    assert_eq!(gate.required_categories.len(), 3);
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::TranslationValidation)
    );
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::PerformanceBenchmark)
    );
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::RollbackTest)
    );
}

#[test]
fn gate_definition_reputation_graph_requires_one_category() {
    let gate = GateDefinition::for_program(FrontierProgram::ReputationGraph, test_gate_id("g-rep"));
    assert_eq!(gate.required_categories.len(), 1);
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::CompromiseWindowReduction)
    );
}

#[test]
fn gate_definition_for_each_program_non_empty_categories() {
    for program in FrontierProgram::all() {
        let gate = GateDefinition::for_program(*program, test_gate_id("g-each"));
        assert!(
            !gate.required_categories.is_empty(),
            "gate for {program:?} must have at least one required category"
        );
    }
}

#[test]
fn gate_definition_all_require_external_verification() {
    for program in FrontierProgram::all() {
        let gate = GateDefinition::for_program(*program, test_gate_id("g-ext"));
        assert!(
            gate.requires_external_verification,
            "gate for {program:?} must require external verification"
        );
    }
}

#[test]
fn gate_definition_fleet_immune_system_categories() {
    let gate =
        GateDefinition::for_program(FrontierProgram::FleetImmuneSystem, test_gate_id("g-fleet"));
    assert_eq!(gate.required_categories.len(), 3);
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::ConvergenceMeasurement)
    );
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::ErrorRateEvidence)
    );
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::PartitionBehavior)
    );
}

#[test]
fn gate_definition_serde_roundtrip() {
    let gate =
        GateDefinition::for_program(FrontierProgram::ProofCarryingOptimizer, test_gate_id("g-s"));
    let json = serde_json::to_string(&gate).unwrap();
    let back: GateDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, back);
}

#[test]
fn gate_definition_benchmark_standard_categories() {
    let gate =
        GateDefinition::for_program(FrontierProgram::BenchmarkStandard, test_gate_id("g-bench"));
    assert_eq!(gate.required_categories.len(), 2);
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::IndependentReproduction)
    );
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::CrossRuntimeFairness)
    );
}

// ===========================================================================
// 6. Gate evaluation — evaluate_gate()
// ===========================================================================

#[test]
fn evaluate_gate_all_categories_satisfied_promotes() {
    let input = fully_passing_input(FrontierProgram::ProofCarryingOptimizer, "eval-promote");
    let receipt = evaluate_gate(&input, 1000);
    assert_eq!(receipt.decision, PromotionDecision::Promote);
    assert!(!receipt.override_applied);
}

#[test]
fn evaluate_gate_missing_category_holds() {
    let gate = GateDefinition::for_program(
        FrontierProgram::ProofCarryingOptimizer,
        test_gate_id("eval-hold"),
    );
    // Only provide 2 of the 3 required categories
    let art1 = test_artifact(ArtifactCategory::TranslationValidation, "hold-1");
    let art2 = test_artifact(ArtifactCategory::PerformanceBenchmark, "hold-2");
    let v1 = passing_verification(&art1);
    let v2 = passing_verification(&art2);

    let input = GateEvaluationInput {
        gate,
        artifacts: vec![art1, art2],
        verifications: vec![v1, v2],
        override_justification: None,
    };
    let receipt = evaluate_gate(&input, 2000);
    assert_eq!(receipt.decision, PromotionDecision::Hold);
}

#[test]
fn evaluate_gate_failed_verification_rejects() {
    let gate = GateDefinition::for_program(
        FrontierProgram::ReputationGraph,
        test_gate_id("eval-reject"),
    );
    let artifact = test_artifact(ArtifactCategory::CompromiseWindowReduction, "rej-1");
    let verification = failing_verification(&artifact, "hash mismatch");

    let input = GateEvaluationInput {
        gate,
        artifacts: vec![artifact],
        verifications: vec![verification],
        override_justification: None,
    };
    let receipt = evaluate_gate(&input, 3000);
    assert_eq!(receipt.decision, PromotionDecision::Reject);
}

#[test]
fn evaluate_gate_missing_external_verification_holds() {
    let gate =
        GateDefinition::for_program(FrontierProgram::ReputationGraph, test_gate_id("eval-noext"));
    let artifact = test_artifact(ArtifactCategory::CompromiseWindowReduction, "noext-1");
    let mut verification = passing_verification(&artifact);
    // Remove external verification
    verification.external_verification = None;

    let input = GateEvaluationInput {
        gate,
        artifacts: vec![artifact],
        verifications: vec![verification],
        override_justification: None,
    };
    let receipt = evaluate_gate(&input, 4000);
    assert_eq!(receipt.decision, PromotionDecision::Hold);
}

#[test]
fn evaluate_gate_override_forces_promote_from_hold() {
    let gate = GateDefinition::for_program(
        FrontierProgram::ProofCarryingOptimizer,
        test_gate_id("eval-override-hold"),
    );
    // Empty artifacts => Hold
    let input = GateEvaluationInput {
        gate,
        artifacts: vec![],
        verifications: vec![],
        override_justification: Some(make_override()),
    };
    let receipt = evaluate_gate(&input, 5000);
    assert_eq!(receipt.decision, PromotionDecision::Promote);
    assert!(receipt.override_applied);
}

#[test]
fn evaluate_gate_override_forces_promote_from_reject() {
    let gate = GateDefinition::for_program(
        FrontierProgram::ReputationGraph,
        test_gate_id("eval-override-rej"),
    );
    let artifact = test_artifact(ArtifactCategory::CompromiseWindowReduction, "ovr-rej-1");
    let verification = failing_verification(&artifact, "bad data");

    let input = GateEvaluationInput {
        gate,
        artifacts: vec![artifact],
        verifications: vec![verification],
        override_justification: Some(make_override()),
    };
    let receipt = evaluate_gate(&input, 6000);
    assert_eq!(receipt.decision, PromotionDecision::Promote);
    assert!(receipt.override_applied);
}

#[test]
fn evaluate_gate_override_not_applied_when_already_promote() {
    let mut input = fully_passing_input(FrontierProgram::ReputationGraph, "eval-promote-ovr");
    input.override_justification = Some(make_override());
    let receipt = evaluate_gate(&input, 7000);
    assert_eq!(receipt.decision, PromotionDecision::Promote);
    assert!(!receipt.override_applied);
}

#[test]
fn evaluate_gate_empty_artifacts_holds() {
    let gate =
        GateDefinition::for_program(FrontierProgram::OperatorCopilot, test_gate_id("eval-empty"));
    let input = GateEvaluationInput {
        gate,
        artifacts: vec![],
        verifications: vec![],
        override_justification: None,
    };
    let receipt = evaluate_gate(&input, 8000);
    assert_eq!(receipt.decision, PromotionDecision::Hold);
}

#[test]
fn evaluate_gate_receipt_hash_deterministic() {
    let input = fully_passing_input(FrontierProgram::TrustEconomics, "eval-det");
    let r1 = evaluate_gate(&input, 9000);
    let r2 = evaluate_gate(&input, 9000);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn evaluate_gate_receipt_hash_changes_with_timestamp() {
    let input = fully_passing_input(FrontierProgram::TrustEconomics, "eval-ts");
    let r1 = evaluate_gate(&input, 9000);
    let r2 = evaluate_gate(&input, 9001);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn evaluate_gate_verification_summaries_populated() {
    let input = fully_passing_input(FrontierProgram::ProofCarryingOptimizer, "eval-summ");
    let receipt = evaluate_gate(&input, 10_000);
    assert_eq!(receipt.verification_summaries.len(), 3);
    for entry in &receipt.verification_summaries {
        assert!(entry.passed);
    }
}

#[test]
fn evaluate_gate_category_coverage_populated() {
    let input = fully_passing_input(FrontierProgram::FleetImmuneSystem, "eval-cov");
    let receipt = evaluate_gate(&input, 11_000);
    assert_eq!(receipt.category_coverage.len(), 3);
    for covered in receipt.category_coverage.values() {
        assert!(covered);
    }
}

// ===========================================================================
// 7. GateRegistry
// ===========================================================================

#[test]
fn gate_registry_empty() {
    let registry = GateRegistry::new();
    let readiness = registry.readiness();
    assert_eq!(readiness.total_gates, 0);
    assert_eq!(readiness.gates_passed, 0);
    assert_eq!(readiness.gates_pending, 0);
}

#[test]
fn gate_registry_default_equals_new() {
    let a = GateRegistry::new();
    let b = GateRegistry::default();
    assert_eq!(a, b);
}

#[test]
fn gate_registry_register_and_query_status() {
    let mut registry = GateRegistry::new();
    let gate = GateDefinition::for_program(
        FrontierProgram::ProofCarryingOptimizer,
        test_gate_id("reg-1"),
    );
    registry.register_gate(gate);

    let status = registry.program_status(FrontierProgram::ProofCarryingOptimizer);
    assert!(status.gate_defined);
    assert_eq!(status.categories_required, 3);
    assert_eq!(status.categories_satisfied, 0);
    assert!(status.latest_decision.is_none());
}

#[test]
fn gate_registry_record_receipt_and_can_promote() {
    let mut registry = GateRegistry::new();
    let gate = GateDefinition::for_program(
        FrontierProgram::ReputationGraph,
        test_gate_id("reg-promote"),
    );
    registry.register_gate(gate.clone());

    let input = fully_passing_input(FrontierProgram::ReputationGraph, "reg-promote");
    let receipt = evaluate_gate(&input, 12_000);
    registry.record_receipt(receipt);

    assert!(registry.can_promote(FrontierProgram::ReputationGraph));
}

#[test]
fn gate_registry_replace_gate_for_same_program() {
    let mut registry = GateRegistry::new();
    let gate1 = GateDefinition::for_program(
        FrontierProgram::OperatorCopilot,
        test_gate_id("reg-replace-1"),
    );
    let gate2 = GateDefinition::for_program(
        FrontierProgram::OperatorCopilot,
        test_gate_id("reg-replace-2"),
    );
    registry.register_gate(gate1);
    registry.register_gate(gate2.clone());

    // Should only have one gate for OperatorCopilot
    let copilot_gates: Vec<_> = registry
        .gates
        .iter()
        .filter(|g| g.program == FrontierProgram::OperatorCopilot)
        .collect();
    assert_eq!(copilot_gates.len(), 1);
    assert_eq!(copilot_gates[0].gate_id, gate2.gate_id);
}

#[test]
fn gate_registry_replace_receipt_for_same_gate_id() {
    let mut registry = GateRegistry::new();
    let gate_id = test_gate_id("reg-rcpt-replace");
    let gate = GateDefinition::for_program(FrontierProgram::ReputationGraph, gate_id.clone());
    registry.register_gate(gate);

    let input = fully_passing_input(FrontierProgram::ReputationGraph, "reg-rcpt-replace");
    let receipt1 = evaluate_gate(&input, 13_000);
    let receipt2 = evaluate_gate(&input, 14_000);
    registry.record_receipt(receipt1);
    registry.record_receipt(receipt2);

    // Only one receipt for this gate
    let rep_receipts: Vec<_> = registry
        .latest_receipts
        .iter()
        .filter(|r| r.gate_id == gate_id)
        .collect();
    assert_eq!(rep_receipts.len(), 1);
    assert_eq!(rep_receipts[0].evaluation_timestamp_ms, 14_000);
}

#[test]
fn gate_registry_readiness_all_passed() {
    let mut registry = GateRegistry::new();
    for program in FrontierProgram::all() {
        let suffix = format!("readiness-all-{}", program.code());
        let gate = GateDefinition::for_program(*program, test_gate_id(&suffix));
        registry.register_gate(gate);

        let input = fully_passing_input(*program, &suffix);
        let receipt = evaluate_gate(&input, 15_000);
        registry.record_receipt(receipt);
    }

    let readiness = registry.readiness();
    assert_eq!(readiness.total_gates, 10);
    assert_eq!(readiness.gates_passed, 10);
    assert_eq!(readiness.gates_held, 0);
    assert_eq!(readiness.gates_rejected, 0);
    assert_eq!(readiness.gates_pending, 0);
    assert_eq!(readiness.readiness_millionths, 1_000_000);
}

#[test]
fn gate_registry_readiness_partial() {
    let mut registry = GateRegistry::new();
    let programs = FrontierProgram::all();

    // Register all 10 but only pass the first 5
    for (i, program) in programs.iter().enumerate() {
        let suffix = format!("readiness-partial-{}", program.code());
        let gate = GateDefinition::for_program(*program, test_gate_id(&suffix));
        registry.register_gate(gate);

        if i < 5 {
            let input = fully_passing_input(*program, &suffix);
            let receipt = evaluate_gate(&input, 16_000);
            registry.record_receipt(receipt);
        }
    }

    let readiness = registry.readiness();
    assert_eq!(readiness.total_gates, 10);
    assert_eq!(readiness.gates_passed, 5);
    assert_eq!(readiness.gates_pending, 5);
    assert_eq!(readiness.readiness_millionths, 500_000);
}

#[test]
fn gate_registry_program_status_for_unregistered() {
    let registry = GateRegistry::new();
    let status = registry.program_status(FrontierProgram::ProofCarryingOptimizer);
    assert!(!status.gate_defined);
    assert!(status.latest_decision.is_none());
    assert_eq!(status.categories_required, 0);
    assert_eq!(status.categories_satisfied, 0);
}

// ===========================================================================
// 8. Release readiness
// ===========================================================================

#[test]
fn release_readiness_all_gates_pass() {
    let mut registry = GateRegistry::new();
    for program in FrontierProgram::all() {
        let suffix = format!("release-all-{}", program.code());
        let gate = GateDefinition::for_program(*program, test_gate_id(&suffix));
        registry.register_gate(gate);

        let input = fully_passing_input(*program, &suffix);
        let receipt = evaluate_gate(&input, 17_000);
        registry.record_receipt(receipt);
    }

    let check = check_release_readiness(&registry, FrontierProgram::all());
    assert!(check.release_allowed);
    assert_eq!(check.passed.len(), 10);
    assert!(check.blocked.is_empty());
    assert!(check.undefined.is_empty());
}

#[test]
fn release_readiness_missing_gate_not_allowed() {
    let registry = GateRegistry::new();
    let check = check_release_readiness(&registry, &[FrontierProgram::ProofCarryingOptimizer]);
    assert!(!check.release_allowed);
    assert!(check.passed.is_empty());
    assert!(check.blocked.is_empty());
    assert_eq!(check.undefined.len(), 1);
}

#[test]
fn release_readiness_gate_not_passed_blocked() {
    let mut registry = GateRegistry::new();
    let gate = GateDefinition::for_program(
        FrontierProgram::OperatorCopilot,
        test_gate_id("release-blocked"),
    );
    registry.register_gate(gate.clone());

    // Evaluate with empty artifacts => Hold
    let input = GateEvaluationInput {
        gate,
        artifacts: vec![],
        verifications: vec![],
        override_justification: None,
    };
    let receipt = evaluate_gate(&input, 18_000);
    registry.record_receipt(receipt);

    let check = check_release_readiness(&registry, &[FrontierProgram::OperatorCopilot]);
    assert!(!check.release_allowed);
    assert!(check.passed.is_empty());
    assert_eq!(check.blocked.len(), 1);
}

#[test]
fn release_readiness_mixed_outcomes() {
    let mut registry = GateRegistry::new();

    // Program 1: passes
    let suffix1 = "release-mix-pass";
    let gate1 =
        GateDefinition::for_program(FrontierProgram::ReputationGraph, test_gate_id(suffix1));
    registry.register_gate(gate1);
    let input1 = fully_passing_input(FrontierProgram::ReputationGraph, suffix1);
    registry.record_receipt(evaluate_gate(&input1, 19_000));

    // Program 2: blocked (Hold)
    let gate2 = GateDefinition::for_program(
        FrontierProgram::OperatorCopilot,
        test_gate_id("release-mix-hold"),
    );
    registry.register_gate(gate2.clone());
    let input2 = GateEvaluationInput {
        gate: gate2,
        artifacts: vec![],
        verifications: vec![],
        override_justification: None,
    };
    registry.record_receipt(evaluate_gate(&input2, 19_001));

    // Program 3: undefined
    let check = check_release_readiness(
        &registry,
        &[
            FrontierProgram::ReputationGraph,
            FrontierProgram::OperatorCopilot,
            FrontierProgram::TrustEconomics,
        ],
    );
    assert!(!check.release_allowed);
    assert_eq!(check.passed.len(), 1);
    assert_eq!(check.blocked.len(), 1);
    assert_eq!(check.undefined.len(), 1);
}

#[test]
fn release_readiness_empty_required_programs_allowed() {
    let registry = GateRegistry::new();
    let check = check_release_readiness(&registry, &[]);
    assert!(check.release_allowed);
    assert!(check.passed.is_empty());
    assert!(check.blocked.is_empty());
    assert!(check.undefined.is_empty());
}

// ===========================================================================
// 9. Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_gate_evaluation_receipt() {
    let input = fully_passing_input(FrontierProgram::ProofCarryingOptimizer, "serde-receipt");
    let receipt = evaluate_gate(&input, 20_000);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GateEvaluationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn serde_roundtrip_gate_registry() {
    let mut registry = GateRegistry::new();
    let gate = GateDefinition::for_program(
        FrontierProgram::FleetImmuneSystem,
        test_gate_id("serde-reg"),
    );
    registry.register_gate(gate);
    let input = fully_passing_input(FrontierProgram::FleetImmuneSystem, "serde-reg");
    let receipt = evaluate_gate(&input, 21_000);
    registry.record_receipt(receipt);

    let json = serde_json::to_string(&registry).unwrap();
    let back: GateRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(registry, back);
}

#[test]
fn serde_roundtrip_program_gate_status() {
    let mut registry = GateRegistry::new();
    let gate = GateDefinition::for_program(
        FrontierProgram::PolicyTheoremEngine,
        test_gate_id("serde-status"),
    );
    registry.register_gate(gate);

    let status = registry.program_status(FrontierProgram::PolicyTheoremEngine);
    let json = serde_json::to_string(&status).unwrap();
    let back: ProgramGateStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, back);
}

#[test]
fn serde_roundtrip_readiness_summary() {
    let mut registry = GateRegistry::new();
    let gate = GateDefinition::for_program(
        FrontierProgram::AutonomousRedBlue,
        test_gate_id("serde-ready"),
    );
    registry.register_gate(gate);

    let readiness = registry.readiness();
    let json = serde_json::to_string(&readiness).unwrap();
    let back: ReadinessSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(readiness, back);
}

#[test]
fn serde_roundtrip_release_gate_check() {
    let mut registry = GateRegistry::new();
    let gate = GateDefinition::for_program(
        FrontierProgram::ReputationGraph,
        test_gate_id("serde-release"),
    );
    registry.register_gate(gate);
    let input = fully_passing_input(FrontierProgram::ReputationGraph, "serde-release");
    registry.record_receipt(evaluate_gate(&input, 22_000));

    let check = check_release_readiness(
        &registry,
        &[
            FrontierProgram::ReputationGraph,
            FrontierProgram::OperatorCopilot,
        ],
    );
    let json = serde_json::to_string(&check).unwrap();
    let back: ReleaseGateCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, back);
}

#[test]
fn serde_roundtrip_override_justification() {
    let ovr = make_override();
    let json = serde_json::to_string(&ovr).unwrap();
    let back: OverrideJustification = serde_json::from_str(&json).unwrap();
    assert_eq!(ovr, back);
}

// ===========================================================================
// 10. Determinism
// ===========================================================================

#[test]
fn determinism_same_evaluation_twice_identical() {
    let input = fully_passing_input(FrontierProgram::CausalTimeMachine, "det-same");
    let r1 = evaluate_gate(&input, 23_000);
    let r2 = evaluate_gate(&input, 23_000);
    assert_eq!(r1, r2);
}

#[test]
fn determinism_same_registry_operations_identical() {
    let build_registry = || {
        let mut registry = GateRegistry::new();
        for program in FrontierProgram::all() {
            let suffix = format!("det-reg-{}", program.code());
            let gate = GateDefinition::for_program(*program, test_gate_id(&suffix));
            registry.register_gate(gate);
            let input = fully_passing_input(*program, &suffix);
            let receipt = evaluate_gate(&input, 24_000);
            registry.record_receipt(receipt);
        }
        registry
    };

    let r1 = build_registry();
    let r2 = build_registry();
    assert_eq!(r1.readiness(), r2.readiness());
}

// ===========================================================================
// 11. Multi-program integration
// ===========================================================================

#[test]
fn multi_program_all_ten_pass_full_readiness() {
    let mut registry = GateRegistry::new();
    for program in FrontierProgram::all() {
        let suffix = format!("multi-all-{}", program.code());
        let gate = GateDefinition::for_program(*program, test_gate_id(&suffix));
        registry.register_gate(gate);

        let input = fully_passing_input(*program, &suffix);
        let receipt = evaluate_gate(&input, 25_000);
        assert_eq!(
            receipt.decision,
            PromotionDecision::Promote,
            "program {} must promote",
            program
        );
        registry.record_receipt(receipt);
    }

    let readiness = registry.readiness();
    assert_eq!(readiness.readiness_millionths, 1_000_000);

    let check = check_release_readiness(&registry, FrontierProgram::all());
    assert!(check.release_allowed);
}

#[test]
fn multi_program_five_pass_half_readiness() {
    let mut registry = GateRegistry::new();
    let programs = FrontierProgram::all();

    for (i, program) in programs.iter().enumerate() {
        let suffix = format!("multi-half-{}", program.code());
        let gate = GateDefinition::for_program(*program, test_gate_id(&suffix));
        registry.register_gate(gate.clone());

        if i < 5 {
            let input = fully_passing_input(*program, &suffix);
            registry.record_receipt(evaluate_gate(&input, 26_000));
        } else {
            // Evaluate with empty => Hold
            let input = GateEvaluationInput {
                gate,
                artifacts: vec![],
                verifications: vec![],
                override_justification: None,
            };
            registry.record_receipt(evaluate_gate(&input, 26_000));
        }
    }

    let readiness = registry.readiness();
    assert_eq!(readiness.gates_passed, 5);
    assert_eq!(readiness.gates_held, 5);
    assert_eq!(readiness.readiness_millionths, 500_000);
}

#[test]
fn multi_program_mixed_flow_with_overrides_and_rejections() {
    let mut registry = GateRegistry::new();
    let programs = FrontierProgram::all();

    for (i, program) in programs.iter().enumerate() {
        let suffix = format!("multi-mixed-{}", program.code());
        let gate = GateDefinition::for_program(*program, test_gate_id(&suffix));
        registry.register_gate(gate.clone());

        match i % 3 {
            0 => {
                // Pass normally
                let input = fully_passing_input(*program, &suffix);
                registry.record_receipt(evaluate_gate(&input, 27_000));
            }
            1 => {
                // Reject (failed verification) then override
                let first_cat = gate.required_categories[0];
                let art = test_artifact(first_cat, &format!("{suffix}-art"));
                let ver = failing_verification(&art, "bad data");
                let input = GateEvaluationInput {
                    gate,
                    artifacts: vec![art],
                    verifications: vec![ver],
                    override_justification: Some(make_override()),
                };
                let receipt = evaluate_gate(&input, 27_001);
                assert!(receipt.override_applied);
                assert_eq!(receipt.decision, PromotionDecision::Promote);
                registry.record_receipt(receipt);
            }
            _ => {
                // Hold (empty)
                let input = GateEvaluationInput {
                    gate,
                    artifacts: vec![],
                    verifications: vec![],
                    override_justification: None,
                };
                registry.record_receipt(evaluate_gate(&input, 27_002));
            }
        }
    }

    let readiness = registry.readiness();
    // Programs 0,3,6,9 pass (i%3==0) => 4
    // Programs 1,4,7 override to promote (i%3==1) => 3
    // Programs 2,5,8 held (i%3==2) => 3
    assert_eq!(readiness.gates_passed, 7); // 4 normal + 3 overridden
    assert_eq!(readiness.gates_held, 3);
    assert_eq!(readiness.total_gates, 10);
}

// ===========================================================================
// Promotion decision Display
// ===========================================================================

#[test]
fn promotion_decision_display() {
    assert_eq!(PromotionDecision::Promote.to_string(), "promote");
    assert_eq!(PromotionDecision::Hold.to_string(), "hold");
    assert_eq!(PromotionDecision::Reject.to_string(), "reject");
}

#[test]
fn promotion_decision_serde_roundtrip() {
    let decisions = [
        PromotionDecision::Promote,
        PromotionDecision::Hold,
        PromotionDecision::Reject,
    ];
    for d in &decisions {
        let json = serde_json::to_string(d).unwrap();
        let back: PromotionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

// ===========================================================================
// Additional edge cases
// ===========================================================================

#[test]
fn evaluate_gate_receipt_contains_all_artifact_ids() {
    let input = fully_passing_input(FrontierProgram::FleetImmuneSystem, "art-ids");
    let receipt = evaluate_gate(&input, 28_000);
    assert_eq!(receipt.artifacts_presented.len(), input.artifacts.len());
    for artifact in &input.artifacts {
        assert!(receipt.artifacts_presented.contains(&artifact.artifact_id));
    }
}

#[test]
fn evaluate_gate_receipt_fields_populated() {
    let input = fully_passing_input(FrontierProgram::AutonomousRedBlue, "fields");
    let receipt = evaluate_gate(&input, 29_000);
    assert_eq!(receipt.program, FrontierProgram::AutonomousRedBlue);
    assert_eq!(receipt.evaluation_timestamp_ms, 29_000);
    assert!(receipt.has_external_verification);
    assert!(!receipt.rationale.is_empty());
}

#[test]
fn gate_registry_can_promote_returns_false_without_receipt() {
    let mut registry = GateRegistry::new();
    let gate =
        GateDefinition::for_program(FrontierProgram::TrustEconomics, test_gate_id("no-receipt"));
    registry.register_gate(gate);
    assert!(!registry.can_promote(FrontierProgram::TrustEconomics));
}

#[test]
fn gate_registry_can_promote_returns_false_when_held() {
    let mut registry = GateRegistry::new();
    let gate = GateDefinition::for_program(
        FrontierProgram::TrustEconomics,
        test_gate_id("held-receipt"),
    );
    registry.register_gate(gate.clone());
    let input = GateEvaluationInput {
        gate,
        artifacts: vec![],
        verifications: vec![],
        override_justification: None,
    };
    registry.record_receipt(evaluate_gate(&input, 30_000));
    assert!(!registry.can_promote(FrontierProgram::TrustEconomics));
}

#[test]
fn evaluate_gate_causal_time_machine_categories() {
    let gate = GateDefinition::for_program(FrontierProgram::CausalTimeMachine, test_gate_id("ctm"));
    assert_eq!(gate.required_categories.len(), 3);
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::ReplayFidelity)
    );
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::CounterfactualAnalysis)
    );
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::CrossNodeReplay)
    );
}

#[test]
fn evaluate_gate_attested_execution_cells_categories() {
    let gate =
        GateDefinition::for_program(FrontierProgram::AttestedExecutionCells, test_gate_id("aec"));
    assert_eq!(gate.required_categories.len(), 2);
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::AttestationChain)
    );
    assert!(
        gate.required_categories
            .contains(&ArtifactCategory::AttestationFallback)
    );
}
