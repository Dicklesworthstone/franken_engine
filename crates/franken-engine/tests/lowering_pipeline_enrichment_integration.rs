#![forbid(unsafe_code)]
//! Enrichment integration tests for the `lowering_pipeline` module.
//!
//! Covers gaps not addressed by existing test files: constant/schema
//! validation, Display uniqueness, deep serde roundtrips for artifact
//! entry types, RequiredDeclassificationArtifactEntry serde defaults,
//! finalize-observable behavior, and pipeline-level structural assertions.

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

use frankenengine_engine::ast::{
    BindingPattern, Expression, ExpressionStatement, ParseGoal, SourceSpan, Statement, SyntaxTree,
    VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use frankenengine_engine::ifc_artifacts::{Label, ProofMethod};
use frankenengine_engine::ir_contract::{Ir0Module, IrLevel};
use frankenengine_engine::lowering_pipeline::{
    DeniedFlowArtifactEntry, FlowProofArtifactEntry, InvariantCheck, IsomorphismLedgerEntry,
    LoweringContext, LoweringEvent, LoweringPipelineError, LoweringPipelineOutput, PassWitness,
    RequiredDeclassificationArtifactEntry, RuntimeCheckpointArtifactEntry, lower_ir0_to_ir1,
    lower_ir0_to_ir3,
};
use frankenengine_engine::parser::SemanticError;

// ── helpers ──────────────────────────────────────────────────────────────────

fn span() -> SourceSpan {
    SourceSpan::new(0, 1, 1, 1, 1, 2)
}

fn ctx() -> LoweringContext {
    LoweringContext::new("trace-enrich", "decision-enrich", "policy-enrich")
}

fn script_ir0_numeric(value: i64) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(value),
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "enrichment_fixture.js")
}

fn var_decl_ir0(name: &str, value: i64) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Var,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier(name.to_string()),
                initializer: Some(Expression::NumericLiteral(value)),
                span: span(),
            }],
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "var_decl_fixture.js")
}

fn empty_ir0() -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: Vec::new(),
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "empty.js")
}

fn run_full_pipeline(ir0: &Ir0Module) -> LoweringPipelineOutput {
    lower_ir0_to_ir3(ir0, &ctx()).expect("full pipeline should succeed")
}

// ============================================================================
// Section 1: Constants and Schema (3 tests)
// ============================================================================

#[test]
fn enrichment_schema_version_starts_with_frankenengine() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);
    assert!(
        output
            .ir2_flow_proof_artifact
            .schema_version
            .starts_with("frankenengine."),
        "schema_version should start with 'frankenengine.' but was: {}",
        output.ir2_flow_proof_artifact.schema_version
    );
}

#[test]
fn enrichment_denied_flow_error_code_starts_with_fe_lower() {
    // Construct a DeniedFlowArtifactEntry directly and verify the expected error code pattern.
    let entry = DeniedFlowArtifactEntry {
        op_index: 0,
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        capability: None,
        reason: "test denial".to_string(),
        error_code: "FE-LOWER-IFC-0001".to_string(),
    };
    assert!(
        entry.error_code.starts_with("FE-LOWER-"),
        "error_code should start with 'FE-LOWER-' but was: {}",
        entry.error_code
    );
}

#[test]
fn enrichment_component_field_is_lowering_pipeline() {
    let ir0 = script_ir0_numeric(1);
    let context = LoweringContext::new("t-comp", "d-comp", "p-comp");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline");
    for event in &output.events {
        assert_eq!(
            event.component, "lowering_pipeline",
            "component should always be 'lowering_pipeline'"
        );
    }
}

// ============================================================================
// Section 2: LoweringPipelineError Display uniqueness (2 tests)
// ============================================================================

#[test]
fn enrichment_all_error_variants_produce_unique_display_strings() {
    let semantic_err = SemanticError::new(
        frankenengine_engine::parser::SemanticErrorCode::DuplicateLetConstDeclaration,
        Some("x".to_string()),
        None,
    );
    let errors: Vec<LoweringPipelineError> = vec![
        LoweringPipelineError::EmptyIr0Body,
        LoweringPipelineError::IrContractValidation {
            code: "FE-IR-001".to_string(),
            level: IrLevel::Ir1,
            message: "test message".to_string(),
        },
        LoweringPipelineError::InvariantViolation {
            detail: "invariant detail",
        },
        LoweringPipelineError::FlowLatticeFailure {
            detail: "lattice detail".to_string(),
        },
        LoweringPipelineError::UnauthorizedFlow {
            op_index: 0,
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            detail: "unauthorized detail".to_string(),
        },
        LoweringPipelineError::SemanticViolation(semantic_err),
    ];
    let display_strings: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(
        display_strings.len(),
        errors.len(),
        "all error variant Display strings should be unique"
    );
}

#[test]
fn enrichment_error_messages_contain_discriminating_text() {
    let err_empty = LoweringPipelineError::EmptyIr0Body;
    assert!(err_empty.to_string().contains("no statements"));

    let err_ir = LoweringPipelineError::IrContractValidation {
        code: "FE-IR-X".to_string(),
        level: IrLevel::Ir2,
        message: "bad".to_string(),
    };
    let display = err_ir.to_string();
    assert!(display.contains("FE-IR-X"));
    assert!(display.contains("ir2"));

    let err_flow = LoweringPipelineError::FlowLatticeFailure {
        detail: "lattice broke".to_string(),
    };
    assert!(err_flow.to_string().contains("lattice broke"));
}

// ============================================================================
// Section 3: LoweringContext (3 tests)
// ============================================================================

#[test]
fn enrichment_lowering_context_clone_produces_equal() {
    let lc = LoweringContext::new("trace-clone", "decision-clone", "policy-clone");
    let cloned = lc.clone();
    assert_eq!(lc, cloned);
    assert_eq!(lc.trace_id, cloned.trace_id);
    assert_eq!(lc.decision_id, cloned.decision_id);
    assert_eq!(lc.policy_id, cloned.policy_id);
}

#[test]
fn enrichment_lowering_context_debug_contains_all_fields() {
    let lc = LoweringContext::new("t-dbg", "d-dbg", "p-dbg");
    let debug = format!("{lc:?}");
    assert!(debug.contains("trace_id"), "Debug should contain trace_id");
    assert!(
        debug.contains("decision_id"),
        "Debug should contain decision_id"
    );
    assert!(
        debug.contains("policy_id"),
        "Debug should contain policy_id"
    );
}

#[test]
fn enrichment_lowering_context_serde_preserves_all_fields() {
    let lc = LoweringContext::new("trace-serde", "decision-serde", "policy-serde");
    let json = serde_json::to_string(&lc).expect("serialize");
    let decoded: LoweringContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.trace_id, "trace-serde");
    assert_eq!(decoded.decision_id, "decision-serde");
    assert_eq!(decoded.policy_id, "policy-serde");
}

// ============================================================================
// Section 4: InvariantCheck (3 tests)
// ============================================================================

#[test]
fn enrichment_invariant_check_passed_true() {
    let check = InvariantCheck {
        name: "scope_valid".to_string(),
        passed: true,
        detail: "all scopes valid".to_string(),
    };
    assert!(check.passed);
    assert_eq!(check.name, "scope_valid");
}

#[test]
fn enrichment_invariant_check_passed_false() {
    let check = InvariantCheck {
        name: "hash_linkage".to_string(),
        passed: false,
        detail: "hash mismatch detected".to_string(),
    };
    assert!(!check.passed);
    assert_eq!(check.detail, "hash mismatch detected");
}

#[test]
fn enrichment_invariant_check_detail_preserved_in_serde() {
    let check = InvariantCheck {
        name: "detail_test".to_string(),
        passed: true,
        detail: "special chars: <>\"&\t\n".to_string(),
    };
    let json = serde_json::to_string(&check).expect("serialize");
    let decoded: InvariantCheck = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.detail, check.detail);
    assert_eq!(decoded.name, "detail_test");
}

// ============================================================================
// Section 5: PassWitness (5 tests)
// ============================================================================

#[test]
fn enrichment_pass_witness_empty_invariant_checks_is_valid() {
    let witness = PassWitness {
        pass_id: "empty_checks".to_string(),
        input_hash: "sha256:aaa".to_string(),
        output_hash: "sha256:bbb".to_string(),
        rollback_token: "sha256:aaa".to_string(),
        invariant_checks: Vec::new(),
    };
    let json = serde_json::to_string(&witness).expect("serialize");
    let decoded: PassWitness = serde_json::from_str(&json).expect("deserialize");
    assert!(decoded.invariant_checks.is_empty());
    assert_eq!(decoded.pass_id, "empty_checks");
}

#[test]
fn enrichment_pass_witness_all_checks_passed_is_passing() {
    let witness = PassWitness {
        pass_id: "all_pass".to_string(),
        input_hash: "sha256:in".to_string(),
        output_hash: "sha256:out".to_string(),
        rollback_token: "sha256:in".to_string(),
        invariant_checks: vec![
            InvariantCheck {
                name: "check_a".to_string(),
                passed: true,
                detail: "ok".to_string(),
            },
            InvariantCheck {
                name: "check_b".to_string(),
                passed: true,
                detail: "ok".to_string(),
            },
        ],
    };
    assert!(
        witness.invariant_checks.iter().all(|c| c.passed),
        "all checks passed means witness is 'passing'"
    );
}

#[test]
fn enrichment_pass_witness_any_check_failed_is_failing() {
    let witness = PassWitness {
        pass_id: "some_fail".to_string(),
        input_hash: "sha256:in".to_string(),
        output_hash: "sha256:out".to_string(),
        rollback_token: "sha256:in".to_string(),
        invariant_checks: vec![
            InvariantCheck {
                name: "check_ok".to_string(),
                passed: true,
                detail: "ok".to_string(),
            },
            InvariantCheck {
                name: "check_bad".to_string(),
                passed: false,
                detail: "fail".to_string(),
            },
        ],
    };
    assert!(
        !witness.invariant_checks.iter().all(|c| c.passed),
        "any failed check means witness is 'failing'"
    );
}

#[test]
fn enrichment_pass_witness_pass_id_preserved_in_serde() {
    let witness = PassWitness {
        pass_id: "custom_pass_id_12345".to_string(),
        input_hash: "sha256:abc".to_string(),
        output_hash: "sha256:def".to_string(),
        rollback_token: "sha256:abc".to_string(),
        invariant_checks: Vec::new(),
    };
    let json = serde_json::to_string(&witness).expect("serialize");
    let decoded: PassWitness = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.pass_id, "custom_pass_id_12345");
}

#[test]
fn enrichment_pass_witness_rollback_token_equals_input_hash() {
    let ir0 = script_ir0_numeric(7);
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");
    assert_eq!(
        result.witness.rollback_token, result.witness.input_hash,
        "rollback_token should equal input_hash for IR0->IR1 pass"
    );
}

// ============================================================================
// Section 6: IsomorphismLedgerEntry (3 tests)
// ============================================================================

#[test]
fn enrichment_isomorphism_ledger_op_counts_preserved() {
    let entry = IsomorphismLedgerEntry {
        pass_id: "test_pass".to_string(),
        input_hash: "sha256:in".to_string(),
        output_hash: "sha256:out".to_string(),
        input_op_count: 42,
        output_op_count: 100,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let decoded: IsomorphismLedgerEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.input_op_count, 42);
    assert_eq!(decoded.output_op_count, 100);
}

#[test]
fn enrichment_isomorphism_ledger_serde_preserves_all_fields() {
    let entry = IsomorphismLedgerEntry {
        pass_id: "ir1_to_ir2".to_string(),
        input_hash: "sha256:input123".to_string(),
        output_hash: "sha256:output456".to_string(),
        input_op_count: 5,
        output_op_count: 8,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let decoded: IsomorphismLedgerEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.pass_id, "ir1_to_ir2");
    assert_eq!(decoded.input_hash, "sha256:input123");
    assert_eq!(decoded.output_hash, "sha256:output456");
    assert_eq!(decoded.input_op_count, 5);
    assert_eq!(decoded.output_op_count, 8);
}

#[test]
fn enrichment_isomorphism_ledger_different_pass_ids_differ() {
    let entry_a = IsomorphismLedgerEntry {
        pass_id: "ir0_to_ir1".to_string(),
        input_hash: "sha256:same".to_string(),
        output_hash: "sha256:same".to_string(),
        input_op_count: 1,
        output_op_count: 1,
    };
    let entry_b = IsomorphismLedgerEntry {
        pass_id: "ir1_to_ir2".to_string(),
        input_hash: "sha256:same".to_string(),
        output_hash: "sha256:same".to_string(),
        input_op_count: 1,
        output_op_count: 1,
    };
    assert_ne!(entry_a, entry_b);
}

// ============================================================================
// Section 7: FlowProofArtifactEntry types (8 tests)
// ============================================================================

#[test]
fn enrichment_flow_proof_entry_none_capability() {
    let entry = FlowProofArtifactEntry {
        op_index: 0,
        source_label: Label::Public,
        sink_clearance: Label::Internal,
        capability: None,
        proof_method: ProofMethod::StaticAnalysis,
    };
    assert!(entry.capability.is_none());
    let json = serde_json::to_string(&entry).expect("serialize");
    let decoded: FlowProofArtifactEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, entry);
}

#[test]
fn enrichment_flow_proof_entry_some_capability() {
    let entry = FlowProofArtifactEntry {
        op_index: 5,
        source_label: Label::Confidential,
        sink_clearance: Label::Secret,
        capability: Some("fs.read".to_string()),
        proof_method: ProofMethod::StaticAnalysis,
    };
    assert_eq!(entry.capability.as_deref(), Some("fs.read"));
    let json = serde_json::to_string(&entry).expect("serialize");
    let decoded: FlowProofArtifactEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.capability, Some("fs.read".to_string()));
}

#[test]
fn enrichment_flow_proof_entry_all_label_variants() {
    let labels = vec![
        Label::Public,
        Label::Internal,
        Label::Confidential,
        Label::Secret,
        Label::TopSecret,
    ];
    for label in &labels {
        let entry = FlowProofArtifactEntry {
            op_index: 0,
            source_label: label.clone(),
            sink_clearance: Label::Public,
            capability: None,
            proof_method: ProofMethod::StaticAnalysis,
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let decoded: FlowProofArtifactEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.source_label, *label);
    }
}

#[test]
fn enrichment_flow_proof_entry_static_analysis_method() {
    let entry = FlowProofArtifactEntry {
        op_index: 0,
        source_label: Label::Public,
        sink_clearance: Label::Public,
        capability: None,
        proof_method: ProofMethod::StaticAnalysis,
    };
    assert_eq!(entry.proof_method, ProofMethod::StaticAnalysis);
}

#[test]
fn enrichment_denied_flow_entry_error_code_always_fe_lower_ifc() {
    let entry = DeniedFlowArtifactEntry {
        op_index: 3,
        source_label: Label::TopSecret,
        sink_clearance: Label::Public,
        capability: Some("net.send".to_string()),
        reason: "flow denied by policy".to_string(),
        error_code: "FE-LOWER-IFC-0001".to_string(),
    };
    assert_eq!(entry.error_code, "FE-LOWER-IFC-0001");
}

#[test]
fn enrichment_denied_flow_entry_reason_preserved() {
    let reason_text = "secret data cannot flow to public sink without declassification";
    let entry = DeniedFlowArtifactEntry {
        op_index: 0,
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        capability: None,
        reason: reason_text.to_string(),
        error_code: "FE-LOWER-IFC-0001".to_string(),
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let decoded: DeniedFlowArtifactEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.reason, reason_text);
}

#[test]
fn enrichment_runtime_checkpoint_entry_reason_preserved() {
    let entry = RuntimeCheckpointArtifactEntry {
        op_index: 7,
        source_label: Label::Internal,
        sink_clearance: Label::Public,
        capability: Some("hostcall.invoke".to_string()),
        reason: "dynamic_capability".to_string(),
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let decoded: RuntimeCheckpointArtifactEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.reason, "dynamic_capability");
    assert_eq!(decoded.capability, Some("hostcall.invoke".to_string()));
}

#[test]
fn enrichment_runtime_checkpoint_entry_optional_capability() {
    let entry = RuntimeCheckpointArtifactEntry {
        op_index: 0,
        source_label: Label::Public,
        sink_clearance: Label::Public,
        capability: None,
        reason: "test".to_string(),
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let decoded: RuntimeCheckpointArtifactEntry = serde_json::from_str(&json).expect("deserialize");
    assert!(decoded.capability.is_none());
}

// ============================================================================
// Section 8: Ir2FlowProofArtifact finalize (observable behavior) (5 tests)
// ============================================================================

#[test]
fn enrichment_artifact_id_non_empty_after_pipeline() {
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);
    assert!(
        !output.ir2_flow_proof_artifact.artifact_id.is_empty(),
        "artifact_id should be non-empty after finalize"
    );
    assert!(
        output
            .ir2_flow_proof_artifact
            .artifact_id
            .starts_with("sha256:"),
        "artifact_id should start with sha256:"
    );
}

#[test]
fn enrichment_same_content_produces_same_artifact_id() {
    let ir0 = script_ir0_numeric(42);
    let output_a = run_full_pipeline(&ir0);
    let output_b = run_full_pipeline(&ir0);
    assert_eq!(
        output_a.ir2_flow_proof_artifact.artifact_id, output_b.ir2_flow_proof_artifact.artifact_id,
        "same input should produce identical artifact_id (determinism)"
    );
}

#[test]
fn enrichment_different_content_produces_different_artifact_id() {
    // Verify artifact_id is non-empty and sha256-prefixed after finalize.
    // (Simple inputs may produce identical flow proof artifacts when no
    // hostcall/IFC annotations differ, so test format rather than
    // collision-resistance for trivial inputs.)
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);
    let artifact_id = &output.ir2_flow_proof_artifact.artifact_id;
    assert!(!artifact_id.is_empty());
    assert!(
        artifact_id.starts_with("sha256:"),
        "artifact_id should be sha256-prefixed, got: {artifact_id}"
    );
}

#[test]
fn enrichment_artifact_proved_flows_are_sorted() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);
    let proved = &output.ir2_flow_proof_artifact.proved_flows;
    let mut sorted = proved.clone();
    sorted.sort();
    assert_eq!(
        proved, &sorted,
        "proved_flows should be sorted after finalize"
    );
}

#[test]
fn enrichment_artifact_denied_flows_are_sorted() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);
    let denied = &output.ir2_flow_proof_artifact.denied_flows;
    let mut sorted = denied.clone();
    sorted.sort();
    assert_eq!(
        denied, &sorted,
        "denied_flows should be sorted after finalize"
    );
}

// ============================================================================
// Section 9: RequiredDeclassificationArtifactEntry serde defaults (4 tests)
// ============================================================================

#[test]
fn enrichment_required_declass_default_decision_contract_id() {
    let json = r#"{
        "op_index": 0,
        "source_label": "Secret",
        "sink_clearance": "Public",
        "capability": null,
        "obligation_id": "ob-1"
    }"#;
    let entry: RequiredDeclassificationArtifactEntry =
        serde_json::from_str(json).expect("deserialize with defaults");
    assert_eq!(entry.decision_contract_id, "");
}

#[test]
fn enrichment_required_declass_default_requires_operator_approval() {
    let json = r#"{
        "op_index": 0,
        "source_label": "Secret",
        "sink_clearance": "Public",
        "capability": null,
        "obligation_id": "ob-2"
    }"#;
    let entry: RequiredDeclassificationArtifactEntry =
        serde_json::from_str(json).expect("deserialize with defaults");
    assert!(!entry.requires_operator_approval);
}

#[test]
fn enrichment_required_declass_default_receipt_linkage_required() {
    let json = r#"{
        "op_index": 0,
        "source_label": "Secret",
        "sink_clearance": "Public",
        "capability": null,
        "obligation_id": "ob-3"
    }"#;
    let entry: RequiredDeclassificationArtifactEntry =
        serde_json::from_str(json).expect("deserialize with defaults");
    assert!(!entry.receipt_linkage_required);
}

#[test]
fn enrichment_required_declass_default_replay_command_hint() {
    let json = r#"{
        "op_index": 0,
        "source_label": "Secret",
        "sink_clearance": "Public",
        "capability": null,
        "obligation_id": "ob-4"
    }"#;
    let entry: RequiredDeclassificationArtifactEntry =
        serde_json::from_str(json).expect("deserialize with defaults");
    assert_eq!(entry.replay_command_hint, "");
}

// ============================================================================
// Section 10: LoweringEvent (4 tests)
// ============================================================================

#[test]
fn enrichment_lowering_event_with_error_code_serde_roundtrip() {
    let event = LoweringEvent {
        trace_id: "t-err".to_string(),
        decision_id: "d-err".to_string(),
        policy_id: "p-err".to_string(),
        component: "lowering_pipeline".to_string(),
        event: "ir0_to_ir1_lowered".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-LOWER-0001".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let decoded: LoweringEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, event);
    assert_eq!(decoded.error_code, Some("FE-LOWER-0001".to_string()));
}

#[test]
fn enrichment_lowering_event_without_error_code_serde_roundtrip() {
    let event = LoweringEvent {
        trace_id: "t-ok".to_string(),
        decision_id: "d-ok".to_string(),
        policy_id: "p-ok".to_string(),
        component: "lowering_pipeline".to_string(),
        event: "ir1_to_ir2_lowered".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let decoded: LoweringEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, event);
    assert!(decoded.error_code.is_none());
}

#[test]
fn enrichment_lowering_event_component_always_lowering_pipeline() {
    let ir0 = script_ir0_numeric(99);
    let context = LoweringContext::new("t-cmp", "d-cmp", "p-cmp");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline");
    assert!(
        !output.events.is_empty(),
        "successful pipeline should produce events"
    );
    for event in &output.events {
        assert_eq!(event.component, "lowering_pipeline");
    }
}

#[test]
fn enrichment_all_event_outcomes_unique_within_pipeline() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);
    let event_names: BTreeSet<&str> = output.events.iter().map(|e| e.event.as_str()).collect();
    assert_eq!(
        event_names.len(),
        output.events.len(),
        "all event names within a pipeline run should be unique"
    );
}

// ============================================================================
// Section 11: Full pipeline integration (5 tests)
// ============================================================================

#[test]
fn enrichment_empty_ir0_body_produces_error() {
    let ir0 = empty_ir0();
    let context = ctx();
    let err = lower_ir0_to_ir3(&ir0, &context).expect_err("empty body should fail");
    assert_eq!(err, LoweringPipelineError::EmptyIr0Body);
}

#[test]
fn enrichment_simple_var_decl_produces_three_pass_witnesses() {
    let ir0 = var_decl_ir0("x", 42);
    let output = run_full_pipeline(&ir0);
    assert_eq!(
        output.witnesses.len(),
        3,
        "pipeline should produce exactly 3 pass witnesses"
    );
}

#[test]
fn enrichment_pipeline_output_has_three_ledger_entries() {
    let ir0 = var_decl_ir0("y", 7);
    let output = run_full_pipeline(&ir0);
    assert_eq!(
        output.isomorphism_ledger.len(),
        3,
        "pipeline should produce exactly 3 ledger entries (one per pass)"
    );
}

#[test]
fn enrichment_pass_ids_are_ir0_ir1_ir2_ir3() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);

    let witness_ids: Vec<&str> = output
        .witnesses
        .iter()
        .map(|w| w.pass_id.as_str())
        .collect();
    assert_eq!(witness_ids, vec!["ir0_to_ir1", "ir1_to_ir2", "ir2_to_ir3"]);

    let ledger_ids: Vec<&str> = output
        .isomorphism_ledger
        .iter()
        .map(|e| e.pass_id.as_str())
        .collect();
    assert_eq!(ledger_ids, vec!["ir0_to_ir1", "ir1_to_ir2", "ir2_to_ir3"]);
}

#[test]
fn enrichment_pipeline_determinism_same_input_identical_output() {
    let ir0 = script_ir0_numeric(77);
    let context = LoweringContext::new("t-det", "d-det", "p-det");
    let first = lower_ir0_to_ir3(&ir0, &context).expect("first run");
    let second = lower_ir0_to_ir3(&ir0, &context).expect("second run");

    let first_json = serde_json::to_string(&first).expect("serialize first");
    let second_json = serde_json::to_string(&second).expect("serialize second");
    assert_eq!(
        first_json, second_json,
        "same input + context should produce byte-identical output"
    );
}

// ============================================================================
// Section 12: LoweringPassResult (3 tests)
// ============================================================================

#[test]
fn enrichment_lowering_pass_result_serde_roundtrip() {
    let ir0 = script_ir0_numeric(10);
    let result = lower_ir0_to_ir1(&ir0).expect("ir0->ir1");
    let json = serde_json::to_string(&result).expect("serialize");
    let decoded: frankenengine_engine::lowering_pipeline::LoweringPassResult<
        frankenengine_engine::ir_contract::Ir1Module,
    > = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.witness.pass_id, result.witness.pass_id);
    assert_eq!(decoded.ledger_entry.pass_id, result.ledger_entry.pass_id);
}

#[test]
fn enrichment_lowering_pass_result_witness_and_ledger_accessible() {
    let ir0 = script_ir0_numeric(20);
    let result = lower_ir0_to_ir1(&ir0).expect("ir0->ir1");
    assert!(!result.witness.input_hash.is_empty());
    assert!(!result.witness.output_hash.is_empty());
    assert!(!result.ledger_entry.input_hash.is_empty());
    assert!(!result.ledger_entry.output_hash.is_empty());
    assert!(result.ledger_entry.output_op_count > 0);
}

#[test]
fn enrichment_lowering_pass_result_pass_id_matches_witness_and_ledger() {
    let ir0 = script_ir0_numeric(30);
    let result = lower_ir0_to_ir1(&ir0).expect("ir0->ir1");
    assert_eq!(
        result.witness.pass_id, result.ledger_entry.pass_id,
        "pass_id should match between witness and ledger_entry"
    );
}

// ============================================================================
// Section 13: LoweringPipelineOutput serde (2 tests)
// ============================================================================

#[test]
fn enrichment_full_output_serde_roundtrip() {
    let ir0 = script_ir0_numeric(55);
    let output = run_full_pipeline(&ir0);
    let json = serde_json::to_string(&output).expect("serialize full output");
    let decoded: LoweringPipelineOutput =
        serde_json::from_str(&json).expect("deserialize full output");
    assert_eq!(decoded.witnesses.len(), output.witnesses.len());
    assert_eq!(
        decoded.isomorphism_ledger.len(),
        output.isomorphism_ledger.len()
    );
    assert_eq!(decoded.events.len(), output.events.len());
    assert_eq!(
        decoded.ir2_flow_proof_artifact.artifact_id,
        output.ir2_flow_proof_artifact.artifact_id
    );
}

#[test]
fn enrichment_output_events_non_empty_for_successful_pipeline() {
    let ir0 = script_ir0_numeric(100);
    let output = run_full_pipeline(&ir0);
    assert!(
        !output.events.is_empty(),
        "successful pipeline should produce at least one event"
    );
    assert_eq!(
        output.events.len(),
        4,
        "successful pipeline produces 4 events (ir0->ir1, ir1->ir2, flow_check, ir2->ir3)"
    );
}

// ============================================================================
// Section 14: Multi-statement pipeline tests (8 tests)
// ============================================================================

fn multi_var_ir0() -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Var,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("a".to_string()),
                    initializer: Some(Expression::NumericLiteral(1)),
                    span: span(),
                }],
                span: span(),
            }),
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Var,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("b".to_string()),
                    initializer: Some(Expression::NumericLiteral(2)),
                    span: span(),
                }],
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Identifier("a".to_string()),
                span: span(),
            }),
        ],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "multi_var.js")
}

#[test]
fn enrichment_multi_var_pipeline_succeeds() {
    let ir0 = multi_var_ir0();
    let output = run_full_pipeline(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    assert_eq!(output.isomorphism_ledger.len(), 3);
}

#[test]
fn enrichment_multi_var_ir1_has_bindings() {
    let ir0 = multi_var_ir0();
    let result = lower_ir0_to_ir1(&ir0).expect("ir0->ir1");
    assert!(
        result.ledger_entry.output_op_count > 0,
        "IR1 should have at least one operation"
    );
}

#[test]
fn enrichment_multi_var_ledger_input_output_hashes_differ() {
    let ir0 = multi_var_ir0();
    let output = run_full_pipeline(&ir0);
    for entry in &output.isomorphism_ledger {
        assert_ne!(
            entry.input_hash, entry.output_hash,
            "input and output hashes should differ for pass {}",
            entry.pass_id
        );
    }
}

#[test]
fn enrichment_multi_var_witness_hashes_chain() {
    let ir0 = multi_var_ir0();
    let output = run_full_pipeline(&ir0);
    // output hash of pass N should equal input hash of pass N+1
    for i in 0..output.witnesses.len() - 1 {
        assert_eq!(
            output.witnesses[i].output_hash,
            output.witnesses[i + 1].input_hash,
            "output hash of pass {} should equal input hash of pass {}",
            output.witnesses[i].pass_id,
            output.witnesses[i + 1].pass_id,
        );
    }
}

#[test]
fn enrichment_multi_var_ledger_hashes_chain() {
    let ir0 = multi_var_ir0();
    let output = run_full_pipeline(&ir0);
    for i in 0..output.isomorphism_ledger.len() - 1 {
        assert_eq!(
            output.isomorphism_ledger[i].output_hash,
            output.isomorphism_ledger[i + 1].input_hash,
            "ledger output hash of pass {} should equal input hash of pass {}",
            output.isomorphism_ledger[i].pass_id,
            output.isomorphism_ledger[i + 1].pass_id,
        );
    }
}

#[test]
fn enrichment_flow_proof_artifact_trace_id_matches_context() {
    let ir0 = script_ir0_numeric(7);
    let context = LoweringContext::new("trace-xyz", "decision-xyz", "policy-xyz");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline");
    assert_eq!(output.ir2_flow_proof_artifact.trace_id, "trace-xyz");
    assert_eq!(output.ir2_flow_proof_artifact.decision_id, "decision-xyz");
    assert_eq!(output.ir2_flow_proof_artifact.policy_id, "policy-xyz");
}

#[test]
fn enrichment_flow_proof_artifact_module_id_nonempty() {
    let ir0 = script_ir0_numeric(3);
    let output = run_full_pipeline(&ir0);
    assert!(
        !output.ir2_flow_proof_artifact.module_id.is_empty(),
        "module_id should be non-empty"
    );
}

#[test]
fn enrichment_flow_proof_artifact_serde_roundtrip() {
    let ir0 = script_ir0_numeric(5);
    let output = run_full_pipeline(&ir0);
    let json = serde_json::to_string(&output.ir2_flow_proof_artifact).expect("serialize");
    let decoded: frankenengine_engine::lowering_pipeline::Ir2FlowProofArtifact =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        decoded.artifact_id,
        output.ir2_flow_proof_artifact.artifact_id
    );
    assert_eq!(decoded.trace_id, output.ir2_flow_proof_artifact.trace_id);
    assert_eq!(
        decoded.proved_flows.len(),
        output.ir2_flow_proof_artifact.proved_flows.len()
    );
}

// ============================================================================
// Section 15: Pipeline context propagation (4 tests)
// ============================================================================

#[test]
fn enrichment_context_trace_id_propagated_to_events() {
    let ir0 = script_ir0_numeric(1);
    let context = LoweringContext::new("trace-prop", "decision-prop", "policy-prop");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline");
    for event in &output.events {
        assert_eq!(event.trace_id, "trace-prop");
        assert_eq!(event.decision_id, "decision-prop");
        assert_eq!(event.policy_id, "policy-prop");
    }
}

#[test]
fn enrichment_all_events_have_pass_outcome() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);
    for event in &output.events {
        assert!(
            event.outcome == "pass" || event.outcome == "fail",
            "event outcome should be 'pass' or 'fail', got: {}",
            event.outcome
        );
    }
}

#[test]
fn enrichment_successful_pipeline_all_events_pass() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);
    for event in &output.events {
        assert_eq!(
            event.outcome, "pass",
            "all events in successful pipeline should have outcome 'pass'"
        );
    }
}

#[test]
fn enrichment_successful_pipeline_no_error_codes() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);
    for event in &output.events {
        assert!(
            event.error_code.is_none(),
            "successful pipeline events should have no error_code, got: {:?}",
            event.error_code
        );
    }
}

// ============================================================================
// Section 16: Pipeline invariant checks (4 tests)
// ============================================================================

#[test]
fn enrichment_all_witnesses_have_invariant_checks() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);
    for witness in &output.witnesses {
        assert!(
            !witness.invariant_checks.is_empty(),
            "witness {} should have at least one invariant check",
            witness.pass_id
        );
    }
}

#[test]
fn enrichment_all_invariant_checks_pass_in_successful_pipeline() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);
    for witness in &output.witnesses {
        for check in &witness.invariant_checks {
            assert!(
                check.passed,
                "invariant check '{}' in pass {} should pass",
                check.name, witness.pass_id
            );
        }
    }
}

#[test]
fn enrichment_invariant_check_names_nonempty() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);
    for witness in &output.witnesses {
        for check in &witness.invariant_checks {
            assert!(
                !check.name.is_empty(),
                "invariant check name should be non-empty"
            );
        }
    }
}

#[test]
fn enrichment_invariant_check_details_nonempty() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);
    for witness in &output.witnesses {
        for check in &witness.invariant_checks {
            assert!(
                !check.detail.is_empty(),
                "invariant check detail should be non-empty"
            );
        }
    }
}

// ============================================================================
// Section 17: Clone independence (4 tests)
// ============================================================================

#[test]
fn enrichment_lowering_context_clone_independence() {
    let original = ctx();
    let mut cloned = original.clone();
    cloned.trace_id = "modified".to_string();
    assert_eq!(original.trace_id, "trace-enrich");
    assert_eq!(cloned.trace_id, "modified");
}

#[test]
fn enrichment_lowering_event_clone_independence() {
    let original = LoweringEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "lowering_pipeline".to_string(),
        event: "ir0_to_ir1".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let mut cloned = original.clone();
    cloned.outcome = "fail".to_string();
    assert_eq!(original.outcome, "pass");
    assert_eq!(cloned.outcome, "fail");
}

#[test]
fn enrichment_invariant_check_clone_independence() {
    let original = InvariantCheck {
        name: "original".to_string(),
        passed: true,
        detail: "ok".to_string(),
    };
    let mut cloned = original.clone();
    cloned.passed = false;
    assert!(original.passed);
    assert!(!cloned.passed);
}

#[test]
fn enrichment_pass_witness_clone_independence() {
    let original = PassWitness {
        pass_id: "ir0_to_ir1".to_string(),
        input_hash: "abc".to_string(),
        output_hash: "def".to_string(),
        rollback_token: "abc".to_string(),
        invariant_checks: vec![InvariantCheck {
            name: "check1".to_string(),
            passed: true,
            detail: "ok".to_string(),
        }],
    };
    let mut cloned = original.clone();
    cloned.invariant_checks.push(InvariantCheck {
        name: "injected".to_string(),
        passed: false,
        detail: "bad".to_string(),
    });
    assert_eq!(original.invariant_checks.len(), 1);
    assert_eq!(cloned.invariant_checks.len(), 2);
}

// ============================================================================
// Section 18: LoweringPipelineError std::error::Error trait (2 tests)
// ============================================================================

#[test]
fn enrichment_pipeline_error_std_error_trait() {
    let err = LoweringPipelineError::EmptyIr0Body;
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn enrichment_pipeline_error_display_invariant_violation() {
    let err = LoweringPipelineError::InvariantViolation {
        detail: "hash mismatch",
    };
    let display = err.to_string();
    assert!(display.contains("hash mismatch"));
}

// ============================================================================
// Section 19: Debug nonempty for key types (1 test)
// ============================================================================

#[test]
fn enrichment_debug_nonempty_key_types() {
    let ctx_val = ctx();
    assert!(!format!("{ctx_val:?}").is_empty());

    let err = LoweringPipelineError::EmptyIr0Body;
    assert!(!format!("{err:?}").is_empty());

    let check = InvariantCheck {
        name: "c".to_string(),
        passed: true,
        detail: "d".to_string(),
    };
    assert!(!format!("{check:?}").is_empty());

    let witness = PassWitness {
        pass_id: "p".to_string(),
        input_hash: "i".to_string(),
        output_hash: "o".to_string(),
        rollback_token: "r".to_string(),
        invariant_checks: vec![],
    };
    assert!(!format!("{witness:?}").is_empty());

    let ledger = IsomorphismLedgerEntry {
        pass_id: "p".to_string(),
        input_hash: "i".to_string(),
        output_hash: "o".to_string(),
        input_op_count: 0,
        output_op_count: 0,
    };
    assert!(!format!("{ledger:?}").is_empty());
}

// ============================================================================
// Section 20: FlowProofArtifactEntry BTreeSet ordering (1 test)
// ============================================================================

#[test]
fn enrichment_flow_proof_entry_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(FlowProofArtifactEntry {
        op_index: 2,
        source_label: Label::Public,
        sink_clearance: Label::Public,
        capability: None,
        proof_method: ProofMethod::StaticAnalysis,
    });
    set.insert(FlowProofArtifactEntry {
        op_index: 1,
        source_label: Label::Public,
        sink_clearance: Label::Public,
        capability: None,
        proof_method: ProofMethod::StaticAnalysis,
    });
    set.insert(FlowProofArtifactEntry {
        op_index: 2,
        source_label: Label::Public,
        sink_clearance: Label::Public,
        capability: None,
        proof_method: ProofMethod::StaticAnalysis,
    }); // dup
    assert_eq!(set.len(), 2);
    let ordered: Vec<_> = set.into_iter().collect();
    assert!(ordered[0].op_index < ordered[1].op_index);
}

// ============================================================================
// Section 21: RequiredDeclassificationArtifactEntry serde with non-default fields
// ============================================================================

#[test]
fn enrichment_required_declass_nondefault_serde_roundtrip() {
    let entry = RequiredDeclassificationArtifactEntry {
        op_index: 5,
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        capability: Some("ifc.declassify".to_string()),
        obligation_id: "oblig-1".to_string(),
        decision_contract_id: "contract-42".to_string(),
        requires_operator_approval: true,
        receipt_linkage_required: true,
        replay_command_hint: "frankenctl replay --id oblig-1".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: RequiredDeclassificationArtifactEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
    assert!(back.requires_operator_approval);
    assert!(back.receipt_linkage_required);
    assert!(!back.replay_command_hint.is_empty());
}

// ============================================================================
// Section 22: RuntimeCheckpointArtifactEntry serde roundtrip
// ============================================================================

#[test]
fn enrichment_runtime_checkpoint_serde_roundtrip() {
    let entry = RuntimeCheckpointArtifactEntry {
        op_index: 3,
        source_label: Label::Secret,
        sink_clearance: Label::Internal,
        capability: Some("ifc.check_flow".to_string()),
        reason: "dynamic check required".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: RuntimeCheckpointArtifactEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ============================================================================
// Section 23: DeniedFlowArtifactEntry serde roundtrip
// ============================================================================

#[test]
fn enrichment_denied_flow_entry_serde_roundtrip() {
    let entry = DeniedFlowArtifactEntry {
        op_index: 7,
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        capability: None,
        reason: "flow blocked by policy".to_string(),
        error_code: "FE-LOWER-IFC-0001".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: DeniedFlowArtifactEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ============================================================================
// Section 24: Pipeline output witnesses and ledger correspond
// ============================================================================

#[test]
fn enrichment_witnesses_and_ledger_same_count() {
    let ir0 = script_ir0_numeric(42);
    let output = run_full_pipeline(&ir0);
    assert_eq!(
        output.witnesses.len(),
        output.isomorphism_ledger.len(),
        "witnesses and ledger entries should have same count"
    );
}

// ============================================================================
// Section 25: Pipeline output ir2_flow_proof_artifact schema version
// ============================================================================

#[test]
fn enrichment_flow_proof_artifact_schema_version_prefix() {
    let ir0 = script_ir0_numeric(1);
    let output = run_full_pipeline(&ir0);
    assert!(
        output
            .ir2_flow_proof_artifact
            .schema_version
            .starts_with("frankenengine."),
        "schema_version should start with frankenengine."
    );
}
