#![forbid(unsafe_code)]

//! Enrichment integration tests for frontier_demo_gate.

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

// ── Helpers ──────────────────────────────────────────────────────────────

fn test_gate_id(suffix: &str) -> EngineObjectId {
    derive_id(
        ObjectDomain::EvidenceRecord,
        suffix,
        &SchemaId::from_definition(b"frontier-demo-gate-enrich"),
        b"frontier-demo-gate-enrich",
    )
    .unwrap()
}

fn test_artifact(category: ArtifactCategory, suffix: &str) -> DemoArtifact {
    DemoArtifact {
        artifact_id: test_gate_id(suffix),
        category,
        content_hash: ContentHash::compute(suffix.as_bytes()),
        producing_commit: "abc123".to_string(),
        test_run_id: "run-enrich-001".to_string(),
        summary: format!("enrichment artifact for {category}"),
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

fn fully_passing_input(program: FrontierProgram, gate_suffix: &str) -> GateEvaluationInput {
    let gate_id = test_gate_id(gate_suffix);
    let gate = GateDefinition::for_program(program, gate_id);
    let artifacts: Vec<DemoArtifact> = gate
        .required_categories
        .iter()
        .enumerate()
        .map(|(i, cat)| test_artifact(*cat, &format!("{gate_suffix}-art-{i}")))
        .collect();
    let verifications: Vec<ArtifactVerification> =
        artifacts.iter().map(passing_verification).collect();
    GateEvaluationInput {
        gate,
        artifacts,
        verifications,
        override_justification: None,
    }
}

// ===========================================================================
// 1. FrontierProgram — Copy, Ord, BTreeSet dedup, Display uniqueness
// ===========================================================================

#[test]
fn enrichment_frontier_program_copy_semantics() {
    let a = FrontierProgram::ProofCarryingOptimizer;
    let b = a;
    let c = a;
    assert_eq!(b, c);
    assert_eq!(a.code(), "9H.1");
}

#[test]
fn enrichment_frontier_program_ord_btreeset_dedup() {
    let set: BTreeSet<FrontierProgram> = FrontierProgram::all().iter().copied().collect();
    assert_eq!(set.len(), 10);
    // Insert duplicates
    let mut set2 = set.clone();
    for p in FrontierProgram::all() {
        set2.insert(*p);
    }
    assert_eq!(set2.len(), 10);
}

#[test]
fn enrichment_frontier_program_display_all_unique() {
    let displays: BTreeSet<String> = FrontierProgram::all()
        .iter()
        .map(|p| p.to_string())
        .collect();
    assert_eq!(displays.len(), 10);
}

#[test]
fn enrichment_frontier_program_debug_all_unique() {
    let debugs: BTreeSet<String> = FrontierProgram::all()
        .iter()
        .map(|p| format!("{p:?}"))
        .collect();
    assert_eq!(debugs.len(), 10);
}

#[test]
fn enrichment_frontier_program_codes_all_start_with_9h() {
    for p in FrontierProgram::all() {
        assert!(
            p.code().starts_with("9H."),
            "code {} should start with 9H.",
            p.code()
        );
    }
}

// ===========================================================================
// 2. ArtifactCategory — BTreeSet dedup, Display uniqueness
// ===========================================================================

#[test]
fn enrichment_artifact_category_btreeset_dedup_21_variants() {
    let all = [
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
    let set: BTreeSet<ArtifactCategory> = all.iter().copied().collect();
    assert_eq!(set.len(), 21);
}

#[test]
fn enrichment_artifact_category_debug_all_unique() {
    let all = [
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
    let debugs: BTreeSet<String> = all.iter().map(|c| format!("{c:?}")).collect();
    assert_eq!(debugs.len(), 21);
}

// ===========================================================================
// 3. VerificationResult — Clone independence, Display
// ===========================================================================

#[test]
fn enrichment_verification_result_clone_independence() {
    let original = VerificationResult::Passed {
        details: "original".to_string(),
    };
    let mut cloned = original.clone();
    if let VerificationResult::Passed { ref mut details } = cloned {
        *details = "mutated".to_string();
    }
    if let VerificationResult::Passed { details } = &original {
        assert_eq!(details, "original");
    }
}

#[test]
fn enrichment_verification_result_display_all_unique() {
    let variants = [
        VerificationResult::Passed {
            details: "d".to_string(),
        },
        VerificationResult::Failed {
            reason: "r".to_string(),
        },
        VerificationResult::Skipped {
            reason: "s".to_string(),
        },
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_verification_result_serde_all_variants() {
    let variants = [
        VerificationResult::Passed {
            details: "ok".to_string(),
        },
        VerificationResult::Failed {
            reason: "bad".to_string(),
        },
        VerificationResult::Skipped {
            reason: "skipped".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: VerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// ===========================================================================
// 4. PromotionDecision — Copy, Ord, Display, serde
// ===========================================================================

#[test]
fn enrichment_promotion_decision_copy_semantics() {
    let a = PromotionDecision::Promote;
    let b = a;
    let c = a;
    assert_eq!(b, c);
}

#[test]
fn enrichment_promotion_decision_ord_btreeset() {
    let set: BTreeSet<PromotionDecision> = [
        PromotionDecision::Promote,
        PromotionDecision::Hold,
        PromotionDecision::Reject,
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_promotion_decision_display_all_unique() {
    let displays: BTreeSet<String> = [
        PromotionDecision::Promote,
        PromotionDecision::Hold,
        PromotionDecision::Reject,
    ]
    .iter()
    .map(|d| d.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

// ===========================================================================
// 5. DemoArtifact — Clone independence, serde, JSON fields
// ===========================================================================

#[test]
fn enrichment_demo_artifact_clone_independence() {
    let original = test_artifact(ArtifactCategory::TranslationValidation, "clone-test");
    let mut cloned = original.clone();
    cloned.summary = "mutated".to_string();
    cloned.public_eligible = false;
    assert_eq!(
        original.summary,
        "enrichment artifact for TranslationValidation"
    );
    assert!(original.public_eligible);
    assert_eq!(cloned.summary, "mutated");
    assert!(!cloned.public_eligible);
}

#[test]
fn enrichment_demo_artifact_json_field_names() {
    let art = test_artifact(ArtifactCategory::PerformanceBenchmark, "json-fields");
    let json = serde_json::to_string(&art).unwrap();
    assert!(json.contains("\"artifact_id\""));
    assert!(json.contains("\"category\""));
    assert!(json.contains("\"content_hash\""));
    assert!(json.contains("\"producing_commit\""));
    assert!(json.contains("\"test_run_id\""));
    assert!(json.contains("\"summary\""));
    assert!(json.contains("\"public_eligible\""));
}

// ===========================================================================
// 6. ArtifactVerification — Clone independence
// ===========================================================================

#[test]
fn enrichment_artifact_verification_clone_independence() {
    let art = test_artifact(ArtifactCategory::TranslationValidation, "ver-clone");
    let original = passing_verification(&art);
    let mut cloned = original.clone();
    cloned.schema_compliant = false;
    assert!(original.schema_compliant);
    assert!(!cloned.schema_compliant);
    assert!(original.passes());
    assert!(!cloned.passes());
}

// ===========================================================================
// 7. GateDefinition — Clone independence, each program has categories
// ===========================================================================

#[test]
fn enrichment_gate_definition_clone_independence() {
    let gate = GateDefinition::for_program(
        FrontierProgram::ProofCarryingOptimizer,
        test_gate_id("gate-clone"),
    );
    let mut cloned = gate.clone();
    cloned.required_categories.clear();
    cloned.description = "mutated".to_string();
    assert!(!gate.required_categories.is_empty());
    assert!(cloned.required_categories.is_empty());
}

#[test]
fn enrichment_gate_definition_all_programs_have_nonempty_description() {
    for program in FrontierProgram::all() {
        let gate = GateDefinition::for_program(
            *program,
            test_gate_id(&format!("gate-{}", program.code())),
        );
        assert!(
            !gate.description.is_empty(),
            "{:?} has empty description",
            program
        );
        assert!(
            !gate.required_categories.is_empty(),
            "{:?} has no required categories",
            program
        );
    }
}

#[test]
fn enrichment_gate_definition_categories_unique_per_program() {
    for program in FrontierProgram::all() {
        let gate = GateDefinition::for_program(
            *program,
            test_gate_id(&format!("gate-u-{}", program.code())),
        );
        let set: BTreeSet<ArtifactCategory> = gate.required_categories.iter().copied().collect();
        assert_eq!(
            set.len(),
            gate.required_categories.len(),
            "{:?} has duplicate categories",
            program
        );
    }
}

// ===========================================================================
// 8. evaluate_gate — determinism, cross-cutting invariants
// ===========================================================================

#[test]
fn enrichment_evaluate_gate_determinism_five_runs() {
    let input = fully_passing_input(FrontierProgram::ProofCarryingOptimizer, "det-gate");
    let baseline = evaluate_gate(&input, 1000);
    let baseline_json = serde_json::to_string(&baseline).unwrap();
    for run in 1..=5 {
        let receipt = evaluate_gate(&input, 1000);
        let json = serde_json::to_string(&receipt).unwrap();
        assert_eq!(baseline_json, json, "run {run} diverged");
    }
}

#[test]
fn enrichment_evaluate_gate_receipt_hash_reproducible() {
    let input = fully_passing_input(FrontierProgram::FleetImmuneSystem, "hash-repro");
    let r1 = evaluate_gate(&input, 5000);
    let r2 = evaluate_gate(&input, 5000);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_evaluate_gate_receipt_hash_changes_with_decision() {
    // Get a promote receipt
    let input_pass = fully_passing_input(FrontierProgram::ProofCarryingOptimizer, "hash-dec-p");
    let receipt_pass = evaluate_gate(&input_pass, 1000);
    // Get a hold receipt (empty artifacts)
    let gate = GateDefinition::for_program(
        FrontierProgram::ProofCarryingOptimizer,
        test_gate_id("hash-dec-h"),
    );
    let input_hold = GateEvaluationInput {
        gate,
        artifacts: vec![],
        verifications: vec![],
        override_justification: None,
    };
    let receipt_hold = evaluate_gate(&input_hold, 1000);
    assert_ne!(receipt_pass.receipt_hash, receipt_hold.receipt_hash);
}

#[test]
fn enrichment_evaluate_gate_category_coverage_matches_required() {
    for program in FrontierProgram::all() {
        let input = fully_passing_input(*program, &format!("cov-{}", program.code()));
        let receipt = evaluate_gate(&input, 1000);
        assert_eq!(
            receipt.category_coverage.len(),
            input.gate.required_categories.len(),
            "coverage count mismatch for {:?}",
            program
        );
    }
}

#[test]
fn enrichment_evaluate_gate_all_programs_promote_with_full_input() {
    for program in FrontierProgram::all() {
        let input = fully_passing_input(*program, &format!("all-{}", program.code()));
        let receipt = evaluate_gate(&input, 2000);
        assert_eq!(
            receipt.decision,
            PromotionDecision::Promote,
            "{:?} should promote with all artifacts",
            program
        );
        assert!(!receipt.override_applied);
    }
}

// ===========================================================================
// 9. GateRegistry — Clone independence, Default
// ===========================================================================

#[test]
fn enrichment_gate_registry_clone_independence() {
    let mut registry = GateRegistry::new();
    registry.register_gate(GateDefinition::for_program(
        FrontierProgram::ProofCarryingOptimizer,
        test_gate_id("reg-clone"),
    ));
    let mut cloned = registry.clone();
    cloned.gates.clear();
    assert_eq!(registry.gates.len(), 1);
    assert!(cloned.gates.is_empty());
}

#[test]
fn enrichment_gate_registry_default_is_empty() {
    let reg = GateRegistry::default();
    assert!(reg.gates.is_empty());
    assert!(reg.latest_receipts.is_empty());
}

#[test]
fn enrichment_gate_registry_gates_sorted_by_program_after_register() {
    let mut registry = GateRegistry::new();
    // Register in reverse order
    registry.register_gate(GateDefinition::for_program(
        FrontierProgram::BenchmarkStandard,
        test_gate_id("reg-sort-10"),
    ));
    registry.register_gate(GateDefinition::for_program(
        FrontierProgram::ProofCarryingOptimizer,
        test_gate_id("reg-sort-1"),
    ));
    // Should be sorted by program Ord
    assert_eq!(
        registry.gates[0].program,
        FrontierProgram::ProofCarryingOptimizer
    );
    assert_eq!(
        registry.gates[1].program,
        FrontierProgram::BenchmarkStandard
    );
}

// ===========================================================================
// 10. ReadinessSummary — invariants
// ===========================================================================

#[test]
fn enrichment_readiness_components_sum_to_total() {
    let mut registry = GateRegistry::new();
    for program in FrontierProgram::all() {
        let gate_id = test_gate_id(&format!("ready-{}", program.code()));
        registry.register_gate(GateDefinition::for_program(*program, gate_id));
    }
    // Pass first 3 programs
    for (i, program) in FrontierProgram::all().iter().enumerate().take(3) {
        let input = fully_passing_input(*program, &format!("ready-pass-{i}"));
        let receipt = evaluate_gate(&input, 3000);
        registry.record_receipt(receipt);
    }
    let summary = registry.readiness();
    assert_eq!(
        summary.gates_passed + summary.gates_held + summary.gates_rejected + summary.gates_pending,
        summary.total_gates
    );
}

#[test]
fn enrichment_readiness_empty_registry() {
    let registry = GateRegistry::new();
    let summary = registry.readiness();
    assert_eq!(summary.total_gates, 0);
    assert_eq!(summary.readiness_millionths, 0);
}

#[test]
fn enrichment_readiness_all_ten_passed() {
    let mut registry = GateRegistry::new();
    for (i, program) in FrontierProgram::all().iter().enumerate() {
        let suffix = format!("full-{i}");
        let gate_id = test_gate_id(&suffix);
        registry.register_gate(GateDefinition::for_program(*program, gate_id));
        // Use the same suffix for both gate registration and evaluation
        // so gate_id matches between registry and receipt
        let input = fully_passing_input(*program, &suffix);
        let receipt = evaluate_gate(&input, 4000);
        registry.record_receipt(receipt);
    }
    let summary = registry.readiness();
    assert_eq!(summary.total_gates, 10);
    assert_eq!(summary.gates_passed, 10);
    assert_eq!(summary.readiness_millionths, 1_000_000);
}

// ===========================================================================
// 11. ReleaseGateCheck — edge cases
// ===========================================================================

#[test]
fn enrichment_release_check_empty_required_programs() {
    let registry = GateRegistry::new();
    let check = check_release_readiness(&registry, &[]);
    assert!(check.release_allowed);
    assert!(check.passed.is_empty());
    assert!(check.blocked.is_empty());
    assert!(check.undefined.is_empty());
}

#[test]
fn enrichment_release_check_undefined_blocks_release() {
    let registry = GateRegistry::new();
    let check = check_release_readiness(&registry, &[FrontierProgram::ProofCarryingOptimizer]);
    assert!(!check.release_allowed);
    assert_eq!(check.undefined.len(), 1);
}

// ===========================================================================
// 12. OverrideJustification — Clone, serde
// ===========================================================================

#[test]
fn enrichment_override_justification_clone_independence() {
    let original = OverrideJustification {
        authorizer: "admin@test".to_string(),
        justification: "emergency bypass".to_string(),
        signature: "sig123".to_string(),
    };
    let mut cloned = original.clone();
    cloned.authorizer = "hacker@evil".to_string();
    assert_eq!(original.authorizer, "admin@test");
    assert_eq!(cloned.authorizer, "hacker@evil");
}

#[test]
fn enrichment_override_justification_json_field_names() {
    let oj = OverrideJustification {
        authorizer: "a".to_string(),
        justification: "j".to_string(),
        signature: "s".to_string(),
    };
    let json = serde_json::to_string(&oj).unwrap();
    assert!(json.contains("\"authorizer\""));
    assert!(json.contains("\"justification\""));
    assert!(json.contains("\"signature\""));
}

// ===========================================================================
// 13. GateEvaluationReceipt — Clone, serde, JSON fields
// ===========================================================================

#[test]
fn enrichment_gate_evaluation_receipt_clone_independence() {
    let input = fully_passing_input(FrontierProgram::ProofCarryingOptimizer, "rcpt-clone");
    let receipt = evaluate_gate(&input, 5000);
    let mut cloned = receipt.clone();
    cloned.decision = PromotionDecision::Reject;
    cloned.rationale = "mutated".to_string();
    assert_eq!(receipt.decision, PromotionDecision::Promote);
    assert_eq!(cloned.decision, PromotionDecision::Reject);
}

#[test]
fn enrichment_gate_evaluation_receipt_json_field_names() {
    let input = fully_passing_input(FrontierProgram::FleetImmuneSystem, "rcpt-json");
    let receipt = evaluate_gate(&input, 6000);
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(json.contains("\"gate_id\""));
    assert!(json.contains("\"program\""));
    assert!(json.contains("\"evaluation_timestamp_ms\""));
    assert!(json.contains("\"artifacts_presented\""));
    assert!(json.contains("\"category_coverage\""));
    assert!(json.contains("\"verification_summaries\""));
    assert!(json.contains("\"has_external_verification\""));
    assert!(json.contains("\"decision\""));
    assert!(json.contains("\"rationale\""));
    assert!(json.contains("\"override_applied\""));
    assert!(json.contains("\"receipt_hash\""));
}

// ===========================================================================
// 14. ProgramGateStatus — serde, Debug
// ===========================================================================

#[test]
fn enrichment_program_gate_status_serde_roundtrip() {
    let status = ProgramGateStatus {
        program: FrontierProgram::TrustEconomics,
        gate_defined: true,
        latest_decision: Some(PromotionDecision::Hold),
        categories_required: 2,
        categories_satisfied: 1,
    };
    let json = serde_json::to_string(&status).unwrap();
    let restored: ProgramGateStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, restored);
}

#[test]
fn enrichment_program_gate_status_debug_nonempty() {
    let status = ProgramGateStatus {
        program: FrontierProgram::OperatorCopilot,
        gate_defined: false,
        latest_decision: None,
        categories_required: 0,
        categories_satisfied: 0,
    };
    let dbg = format!("{status:?}");
    assert!(dbg.contains("ProgramGateStatus"));
}

// ===========================================================================
// 15. Cross-cutting: each program's gate categories are a subset of 21
// ===========================================================================

#[test]
fn enrichment_all_gate_categories_are_valid_artifact_categories() {
    let all_categories: BTreeSet<ArtifactCategory> = [
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
    ]
    .iter()
    .copied()
    .collect();

    for program in FrontierProgram::all() {
        let gate = GateDefinition::for_program(
            *program,
            test_gate_id(&format!("valid-{}", program.code())),
        );
        for cat in &gate.required_categories {
            assert!(
                all_categories.contains(cat),
                "{:?} has unknown category {:?}",
                program,
                cat
            );
        }
    }
}

// ===========================================================================
// 16. VerificationSummaryEntry — serde, Debug
// ===========================================================================

#[test]
fn enrichment_verification_summary_entry_serde_roundtrip() {
    let entry = VerificationSummaryEntry {
        category: ArtifactCategory::TranslationValidation,
        passed: true,
        detail: "artifact verified".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let restored: VerificationSummaryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

#[test]
fn enrichment_verification_summary_entry_debug_nonempty() {
    let entry = VerificationSummaryEntry {
        category: ArtifactCategory::PerformanceBenchmark,
        passed: false,
        detail: "failed".to_string(),
    };
    let dbg = format!("{entry:?}");
    assert!(dbg.contains("VerificationSummaryEntry"));
}

// ===========================================================================
// 17. Serde roundtrip on full assembled types
// ===========================================================================

#[test]
fn enrichment_full_receipt_serde_roundtrip() {
    let input = fully_passing_input(FrontierProgram::CausalTimeMachine, "full-serde");
    let receipt = evaluate_gate(&input, 7000);
    let json = serde_json::to_string(&receipt).unwrap();
    let restored: GateEvaluationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
}

#[test]
fn enrichment_gate_registry_serde_roundtrip() {
    let mut registry = GateRegistry::new();
    registry.register_gate(GateDefinition::for_program(
        FrontierProgram::ProofCarryingOptimizer,
        test_gate_id("serde-reg"),
    ));
    let input = fully_passing_input(FrontierProgram::ProofCarryingOptimizer, "serde-reg");
    let receipt = evaluate_gate(&input, 8000);
    registry.record_receipt(receipt);
    let json = serde_json::to_string(&registry).unwrap();
    let restored: GateRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(registry, restored);
}

// ===========================================================================
// 18. can_promote false cases
// ===========================================================================

#[test]
fn enrichment_can_promote_false_for_held_program() {
    let mut registry = GateRegistry::new();
    let gate_id = test_gate_id("held-gate");
    registry.register_gate(GateDefinition::for_program(
        FrontierProgram::ProofCarryingOptimizer,
        gate_id,
    ));
    // Evaluate with no artifacts -> Hold
    let gate = GateDefinition::for_program(
        FrontierProgram::ProofCarryingOptimizer,
        test_gate_id("held-gate"),
    );
    let input = GateEvaluationInput {
        gate,
        artifacts: vec![],
        verifications: vec![],
        override_justification: None,
    };
    let receipt = evaluate_gate(&input, 9000);
    assert_eq!(receipt.decision, PromotionDecision::Hold);
    registry.record_receipt(receipt);
    assert!(!registry.can_promote(FrontierProgram::ProofCarryingOptimizer));
}

// ===========================================================================
// 19. Verification edge: skipped external doesn't count as external
// ===========================================================================

#[test]
fn enrichment_skipped_external_verification_holds_gate() {
    let gate_id = test_gate_id("skip-ext");
    let gate = GateDefinition::for_program(FrontierProgram::ReputationGraph, gate_id);
    let art = test_artifact(ArtifactCategory::CompromiseWindowReduction, "skip-ext-art");
    let ver = ArtifactVerification {
        artifact_id: art.artifact_id.clone(),
        category: art.category,
        schema_compliant: true,
        integrity_valid: true,
        reproducible: true,
        external_verification: Some(VerificationResult::Skipped {
            reason: "external verifier unavailable".to_string(),
        }),
        overall: VerificationResult::Passed {
            details: "internal ok".to_string(),
        },
    };
    let input = GateEvaluationInput {
        gate,
        artifacts: vec![art],
        verifications: vec![ver],
        override_justification: None,
    };
    let receipt = evaluate_gate(&input, 10_000);
    // Gate requires external verification but skipped doesn't count
    assert_eq!(receipt.decision, PromotionDecision::Hold);
    assert!(!receipt.has_external_verification);
}
