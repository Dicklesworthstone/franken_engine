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

use frankenengine_engine::ast::{ParseGoal, SourceSpan, SyntaxTree};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    CapabilityTag, EffectBoundary, FlowAnnotation, Ir0Module, Ir1Op, Ir2Module, Ir2Op,
    Ir3Instruction,
};
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, LoweringPipelineError, lower_ir0_to_ir1, lower_ir0_to_ir3, lower_ir1_to_ir2,
    lower_ir2_to_ir3, validate_ir0_static_semantics,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

#[test]
fn module_source_lowers_across_all_passes() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            r#"import foo from "pkg"; export default foo; await foo;"#,
            ParseGoal::Module,
        )
        .expect("module parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "module_fixture.ts");
    let context = LoweringContext::new("trace-lower", "decision-lower", "policy-lower");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

    assert_eq!(output.witnesses.len(), 3);
    assert_eq!(output.isomorphism_ledger.len(), 3);
    assert!(!output.ir1.ops.is_empty());
    assert!(!output.ir2.ops.is_empty());
    assert!(!output.ir3.instructions.is_empty());
}

#[test]
fn hostcall_literal_preserves_capability_intent_into_ir2() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(r#"hostcall<"fs.read">();"#, ParseGoal::Script)
        .expect("script parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "hostcall_fixture.ts");
    let context = LoweringContext::new("trace-hostcall", "decision-hostcall", "policy-hostcall");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

    let capabilities = output
        .ir2
        .required_capabilities
        .iter()
        .map(|cap| cap.0.as_str())
        .collect::<Vec<_>>();
    assert!(capabilities.contains(&"fs.read"));
}

#[test]
fn dynamic_hostcall_path_inserts_runtime_ifc_guard() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("doWork();", ParseGoal::Script)
        .expect("script parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "dynamic_hostcall_fixture.ts");
    let context = LoweringContext::new("trace-dynamic", "decision-dynamic", "policy-dynamic");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

    let hostcall_caps = output
        .ir3
        .instructions
        .iter()
        .filter_map(|instruction| match instruction {
            Ir3Instruction::HostCall { capability, .. } => Some(capability.0.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(hostcall_caps.contains(&"ifc.check_flow"));
    assert!(hostcall_caps.contains(&"hostcall.invoke"));
}

#[test]
fn pipeline_is_deterministic_for_identical_parse_tree() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("42; await 42;", ParseGoal::Script)
        .expect("script parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "deterministic_fixture.js");
    let context = LoweringContext::new("trace-det", "decision-det", "policy-det");

    let first = lower_ir0_to_ir3(&ir0, &context).expect("first pipeline run should pass");
    let second = lower_ir0_to_ir3(&ir0, &context).expect("second pipeline run should pass");

    assert_eq!(first.ir1.content_hash(), second.ir1.content_hash());
    assert_eq!(first.ir2.content_hash(), second.ir2.content_hash());
    assert_eq!(first.ir3.content_hash(), second.ir3.content_hash());
    assert_eq!(first.witnesses, second.witnesses);
}

#[test]
fn events_contain_required_structured_fields() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1;", ParseGoal::Script)
        .expect("script parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "events_fixture.js");
    let context = LoweringContext::new("trace-events", "decision-events", "policy-events");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should pass");

    assert!(output.events.iter().all(|event| {
        !event.trace_id.is_empty()
            && !event.decision_id.is_empty()
            && !event.policy_id.is_empty()
            && !event.component.is_empty()
            && !event.event.is_empty()
            && !event.outcome.is_empty()
    }));
}

#[test]
fn empty_ir0_tree_is_rejected() {
    let empty_tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: Vec::new(),
        span: SourceSpan::new(0, 0, 1, 1, 1, 1),
    };
    let ir0 = Ir0Module::from_syntax_tree(empty_tree, "empty_fixture.js");
    let context = LoweringContext::new("trace-empty", "decision-empty", "policy-empty");
    let error = lower_ir0_to_ir3(&ir0, &context).expect_err("empty tree should fail");

    assert_eq!(error, LoweringPipelineError::EmptyIr0Body);
}

// ────────────────────────────────────────────────────────────
// Enrichment: individual passes, validation, determinism, errors
// ────────────────────────────────────────────────────────────

#[test]
fn individual_passes_succeed_for_simple_source() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("42;", ParseGoal::Script)
        .expect("parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "individual_passes.js");

    let pass1 = lower_ir0_to_ir1(&ir0).expect("ir0 -> ir1 should succeed");
    assert!(!pass1.module.ops.is_empty());
    assert!(!pass1.witness.pass_id.is_empty());

    let pass2 = lower_ir1_to_ir2(&pass1.module).expect("ir1 -> ir2 should succeed");
    assert!(!pass2.module.ops.is_empty());
    assert!(!pass2.witness.pass_id.is_empty());

    let pass3 = lower_ir2_to_ir3(&pass2.module).expect("ir2 -> ir3 should succeed");
    assert!(!pass3.module.instructions.is_empty());
    assert!(!pass3.witness.pass_id.is_empty());
}

#[test]
fn static_semantics_validation_on_simple_source() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let x = 1;", ParseGoal::Script)
        .expect("parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "semantics_fixture.js");
    let result = validate_ir0_static_semantics(&ir0);
    assert!(result.is_valid());
}

#[test]
fn pipeline_produces_flow_proof_artifact() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1;", ParseGoal::Script)
        .expect("parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "flow_proof_fixture.js");
    let context = LoweringContext::new("trace-fp", "decision-fp", "policy-fp");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should pass");

    assert!(!output.ir2_flow_proof_artifact.module_id.is_empty());
    assert!(!output.ir2_flow_proof_artifact.artifact_id.is_empty());
    assert!(!output.ir2_flow_proof_artifact.schema_version.is_empty());
}

#[test]
fn witnesses_are_consistent_with_isomorphism_ledger() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1;", ParseGoal::Script)
        .expect("parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "witness_consistency.js");
    let context = LoweringContext::new("trace-wc", "decision-wc", "policy-wc");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should pass");

    assert_eq!(output.witnesses.len(), output.isomorphism_ledger.len());
    for witness in &output.witnesses {
        assert!(!witness.pass_id.is_empty());
        assert!(!witness.input_hash.is_empty());
        assert!(!witness.output_hash.is_empty());
    }
}

#[test]
fn lowering_context_fields_propagate_to_events() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1;", ParseGoal::Script)
        .expect("parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "context_propagation.js");
    let context = LoweringContext::new("trace-ctx", "decision-ctx", "policy-ctx");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should pass");

    for event in &output.events {
        assert_eq!(event.trace_id, "trace-ctx");
        assert_eq!(event.decision_id, "decision-ctx");
        assert_eq!(event.policy_id, "policy-ctx");
    }
}

#[test]
fn lowering_pipeline_error_display_is_non_empty() {
    let err = LoweringPipelineError::EmptyIr0Body;
    assert!(!err.to_string().is_empty());

    let err2 = LoweringPipelineError::InvariantViolation {
        detail: "test invariant",
    };
    assert!(!err2.to_string().is_empty());
    assert!(err2.to_string().contains("test invariant"));
}

#[test]
fn content_hashes_differ_for_different_sources() {
    let parser = CanonicalEs2020Parser;

    let tree_a = parser.parse("1;", ParseGoal::Script).expect("parse a");
    let ir0_a = Ir0Module::from_syntax_tree(tree_a, "diff_a.js");
    let ctx = LoweringContext::new("trace-diff", "decision-diff", "policy-diff");
    let out_a = lower_ir0_to_ir3(&ir0_a, &ctx).expect("pipeline a");

    let tree_b = parser.parse("999;", ParseGoal::Script).expect("parse b");
    let ir0_b = Ir0Module::from_syntax_tree(tree_b, "diff_b.js");
    let out_b = lower_ir0_to_ir3(&ir0_b, &ctx).expect("pipeline b");

    assert_ne!(out_a.ir1.content_hash(), out_b.ir1.content_hash());
}

#[test]
fn module_parse_goal_produces_different_ir_than_script() {
    let parser = CanonicalEs2020Parser;
    let ctx = LoweringContext::new("trace-goal", "decision-goal", "policy-goal");

    let script_tree = parser.parse("42;", ParseGoal::Script).expect("script");
    let ir0_script = Ir0Module::from_syntax_tree(script_tree, "goal_script.js");
    let script_out = lower_ir0_to_ir3(&ir0_script, &ctx).expect("script pipeline");

    let module_tree = parser
        .parse(r#"import x from "y"; 42;"#, ParseGoal::Module)
        .expect("module");
    let ir0_module = Ir0Module::from_syntax_tree(module_tree, "goal_module.mjs");
    let module_out = lower_ir0_to_ir3(&ir0_module, &ctx).expect("module pipeline");

    // Module parse has import handling, so IR should differ
    assert_ne!(script_out.ir1.content_hash(), module_out.ir1.content_hash());
}

// ────────────────────────────────────────────────────────────
// Enrichment 2: serde, flow proof artifact, semantic validation,
// error variants, individual pass determinism, invariant checks
// ────────────────────────────────────────────────────────────

use frankenengine_engine::lowering_pipeline::{
    InvariantCheck, Ir2FlowProofArtifact, IsomorphismLedgerEntry, LoweringEvent,
    LoweringPipelineOutput, PassWitness,
};

#[test]
fn lowering_pipeline_output_serde_roundtrip() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("1;", ParseGoal::Script).expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "serde_fixture.js");
    let ctx = LoweringContext::new("trace-serde", "decision-serde", "policy-serde");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline");

    let json = serde_json::to_string(&output).expect("serialize");
    let recovered: LoweringPipelineOutput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(output, recovered);
}

#[test]
fn pass_witness_serde_roundtrip() {
    let witness = PassWitness {
        pass_id: "ir0_to_ir1".to_string(),
        input_hash: "abc123".to_string(),
        output_hash: "def456".to_string(),
        rollback_token: "rb-001".to_string(),
        invariant_checks: vec![InvariantCheck {
            name: "non_empty_output".to_string(),
            passed: true,
            detail: "ok".to_string(),
        }],
    };
    let json = serde_json::to_string(&witness).expect("serialize");
    let recovered: PassWitness = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(witness, recovered);
}

#[test]
fn isomorphism_ledger_entry_serde_roundtrip() {
    let entry = IsomorphismLedgerEntry {
        pass_id: "ir1_to_ir2".to_string(),
        input_hash: "hash-in".to_string(),
        output_hash: "hash-out".to_string(),
        input_op_count: 7,
        output_op_count: 9,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: IsomorphismLedgerEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, recovered);
}

#[test]
fn lowering_event_serde_roundtrip() {
    let event = LoweringEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "lowering_pipeline".to_string(),
        event: "ir0_to_ir1_lowered".to_string(),
        outcome: "success".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: LoweringEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn ir2_flow_proof_artifact_serde_roundtrip() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42;", ParseGoal::Script).expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "flow_artifact_serde.js");
    let ctx = LoweringContext::new("trace-fa", "decision-fa", "policy-fa");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline");

    let json = serde_json::to_string(&output.ir2_flow_proof_artifact).expect("serialize");
    let recovered: Ir2FlowProofArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(output.ir2_flow_proof_artifact, recovered);
}

#[test]
fn flow_proof_artifact_context_matches_lowering_context() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42;", ParseGoal::Script).expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "artifact_ctx.js");
    let ctx = LoweringContext::new("trace-artctx", "decision-artctx", "policy-artctx");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline");

    assert_eq!(output.ir2_flow_proof_artifact.trace_id, "trace-artctx");
    assert_eq!(
        output.ir2_flow_proof_artifact.decision_id,
        "decision-artctx"
    );
    assert_eq!(output.ir2_flow_proof_artifact.policy_id, "policy-artctx");
    assert_eq!(output.ir2_flow_proof_artifact.module_id, "artifact_ctx.js");
    assert!(!output.ir2_flow_proof_artifact.schema_version.is_empty());
    assert!(!output.ir2_flow_proof_artifact.artifact_id.is_empty());
}

#[test]
fn individual_pass_determinism() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42;", ParseGoal::Script).expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "pass_det.js");

    let pass1_a = lower_ir0_to_ir1(&ir0).expect("ir0->ir1 first");
    let pass1_b = lower_ir0_to_ir1(&ir0).expect("ir0->ir1 second");
    assert_eq!(pass1_a.witness, pass1_b.witness);
    assert_eq!(pass1_a.ledger_entry, pass1_b.ledger_entry);
    assert_eq!(pass1_a.module.content_hash(), pass1_b.module.content_hash());

    let pass2_a = lower_ir1_to_ir2(&pass1_a.module).expect("ir1->ir2 first");
    let pass2_b = lower_ir1_to_ir2(&pass1_a.module).expect("ir1->ir2 second");
    assert_eq!(pass2_a.witness, pass2_b.witness);
    assert_eq!(pass2_a.module.content_hash(), pass2_b.module.content_hash());

    let pass3_a = lower_ir2_to_ir3(&pass2_a.module).expect("ir2->ir3 first");
    let pass3_b = lower_ir2_to_ir3(&pass2_a.module).expect("ir2->ir3 second");
    assert_eq!(pass3_a.witness, pass3_b.witness);
    assert_eq!(pass3_a.module.content_hash(), pass3_b.module.content_hash());
}

#[test]
fn witnesses_contain_invariant_checks_that_all_pass() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42;", ParseGoal::Script).expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "invariant_fixture.js");
    let ctx = LoweringContext::new("trace-inv", "decision-inv", "policy-inv");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline");

    for witness in &output.witnesses {
        assert!(
            !witness.invariant_checks.is_empty(),
            "each pass should have invariant checks"
        );
        for check in &witness.invariant_checks {
            assert!(check.passed, "invariant check '{}' should pass", check.name);
            assert!(!check.name.is_empty());
        }
    }
}

#[test]
fn pass_witnesses_have_distinct_pass_ids() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42;", ParseGoal::Script).expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "distinct_pass_ids.js");
    let ctx = LoweringContext::new("trace-pid", "decision-pid", "policy-pid");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline");

    let pass_ids: Vec<&str> = output
        .witnesses
        .iter()
        .map(|w| w.pass_id.as_str())
        .collect();
    let unique: std::collections::BTreeSet<&str> = pass_ids.iter().copied().collect();
    assert_eq!(pass_ids.len(), unique.len(), "pass IDs must be unique");
    assert_eq!(pass_ids.len(), 3, "should have 3 pass witnesses");
}

#[test]
fn isomorphism_ledger_hashes_chain_correctly() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42;", ParseGoal::Script).expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "ledger_chain.js");
    let ctx = LoweringContext::new("trace-lc", "decision-lc", "policy-lc");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline");

    // Each pass's output hash should equal the next pass's input hash
    for window in output.isomorphism_ledger.windows(2) {
        assert_eq!(
            window[0].output_hash, window[1].input_hash,
            "ledger entries should chain: {} output -> {} input",
            window[0].pass_id, window[1].pass_id
        );
    }
}

#[test]
fn rollback_tokens_are_non_empty_and_unique() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42;", ParseGoal::Script).expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "rollback_tokens.js");
    let ctx = LoweringContext::new("trace-rb", "decision-rb", "policy-rb");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline");

    let tokens: Vec<&str> = output
        .witnesses
        .iter()
        .map(|w| w.rollback_token.as_str())
        .collect();
    for token in &tokens {
        assert!(!token.is_empty(), "rollback tokens must be non-empty");
    }
    let unique: std::collections::BTreeSet<&str> = tokens.iter().copied().collect();
    assert_eq!(tokens.len(), unique.len(), "rollback tokens must be unique");
}

#[test]
fn static_semantics_detects_duplicate_let_declarations() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let x = 1; let x = 2;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "dup_let.js");
    let result = validate_ir0_static_semantics(&ir0);
    assert!(!result.is_valid(), "duplicate let should be invalid");
    assert!(!result.errors.is_empty());
}

#[test]
fn static_semantics_detects_const_without_initializer() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("const x;", ParseGoal::Script).expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "const_no_init.js");
    let result = validate_ir0_static_semantics(&ir0);
    assert!(
        !result.is_valid(),
        "const without initializer should be invalid"
    );
}

#[test]
fn error_variant_display_includes_detail() {
    let err = LoweringPipelineError::IrContractValidation {
        code: "FE-IR-0001".to_string(),
        level: frankenengine_engine::ir_contract::IrLevel::Ir0,
        message: "missing field".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("FE-IR-0001"));
    assert!(msg.contains("missing field"));

    let err2 = LoweringPipelineError::FlowLatticeFailure {
        detail: "lattice not monotone".to_string(),
    };
    assert!(err2.to_string().contains("lattice not monotone"));
}

#[test]
fn pipeline_events_count_matches_expected() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42;", ParseGoal::Script).expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "event_count.js");
    let ctx = LoweringContext::new("trace-ec", "decision-ec", "policy-ec");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline");

    // Each pass emits a success event: ir0->ir1, ir1->ir2, ir2->ir3
    assert!(output.events.len() >= 3, "at least 3 events for 3 passes");
    assert!(output.events.iter().all(|e| e.outcome == "success"));
    assert!(output.events.iter().all(|e| e.error_code.is_none()));
}

#[test]
fn hostcall_source_generates_ifc_flow_proof_entries() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(r#"hostcall<"net.send">();"#, ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "hostcall_flow_proof.js");
    let ctx = LoweringContext::new("trace-hfp", "decision-hfp", "policy-hfp");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline");

    // Hostcall should generate at least one runtime checkpoint
    assert!(
        !output
            .ir2_flow_proof_artifact
            .runtime_checkpoints
            .is_empty()
            || !output.ir2_flow_proof_artifact.proved_flows.is_empty()
            || !output
                .ir2_flow_proof_artifact
                .required_declassifications
                .is_empty(),
        "hostcall source should produce some flow proof entries"
    );
}

#[test]
fn dynamic_hostcall_flow_proof_artifact_emits_runtime_checkpoint() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("doWork();", ParseGoal::Script).expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "dynamic_hostcall_fixture.ts");
    let ctx = LoweringContext::new(
        "trace-dynamic-artifact",
        "decision-dynamic-artifact",
        "policy-dynamic-artifact",
    );
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline");
    let artifact = &output.ir2_flow_proof_artifact;

    assert!(artifact.denied_flows.is_empty());
    assert!(artifact.proved_flows.is_empty());
    assert!(artifact.required_declassifications.is_empty());
    assert_eq!(artifact.runtime_checkpoints.len(), 1);
    assert_eq!(artifact.runtime_checkpoints[0].reason, "dynamic_capability");
    assert_eq!(
        artifact.runtime_checkpoints[0].capability.as_deref(),
        Some("hostcall.invoke")
    );
}

#[test]
fn declassification_flow_inserts_runtime_ifc_guard_before_hostcall() {
    let mut ir2 = Ir2Module::new(ContentHash::compute(b"declass-ir2"), "declass_fixture.js");
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::Call { arg_count: 1 },
        effect: EffectBoundary::HostcallEffect,
        required_capability: Some(CapabilityTag("declassify.audit".to_string())),
        flow: Some(FlowAnnotation {
            data_label: Label::Secret,
            sink_clearance: Label::Public,
            declassification_required: true,
        }),
    });

    let ir3 = lower_ir2_to_ir3(&ir2)
        .expect("IR2->IR3 should succeed")
        .module;
    let hostcall_caps: Vec<&str> = ir3
        .instructions
        .iter()
        .filter_map(|instruction| match instruction {
            Ir3Instruction::HostCall { capability, .. } => Some(capability.0.as_str()),
            _ => None,
        })
        .collect();

    assert!(hostcall_caps.contains(&"ifc.check_flow"));
    assert!(hostcall_caps.contains(&"declassify.audit"));

    let guard_index = ir3
        .instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                Ir3Instruction::HostCall { capability, .. }
                if capability.0 == "ifc.check_flow"
            )
        })
        .expect("guard hostcall");
    let declass_index = ir3
        .instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                Ir3Instruction::HostCall { capability, .. }
                if capability.0 == "declassify.audit"
            )
        })
        .expect("declassify hostcall");
    assert!(guard_index < declass_index);
}

#[test]
fn module_with_export_default_produces_ir3() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(r#"export default 42;"#, ParseGoal::Module)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "export_default.mjs");
    let ctx = LoweringContext::new("trace-ed", "decision-ed", "policy-ed");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline");

    assert!(!output.ir3.instructions.is_empty());
    assert!(output.ir3.content_hash() != output.ir1.content_hash());
}

// ────────────────────────────────────────────────────────────
// Enrichment 3: ~80 enrichment tests for edge cases, AST node
// types, error paths, determinism, and round-trip properties
// ────────────────────────────────────────────────────────────

use frankenengine_engine::ast::{Expression, ExpressionStatement, Statement};
use frankenengine_engine::ifc_artifacts::ProofMethod;
use frankenengine_engine::lowering_pipeline::{
    FlowProofArtifactEntry, RuntimeCheckpointArtifactEntry,
};
use frankenengine_engine::ir_contract::IrLevel;

fn span() -> SourceSpan {
    SourceSpan::new(0, 0, 1, 1, 1, 1)
}

fn make_expr_stmt(expr: Expression) -> Statement {
    Statement::Expression(ExpressionStatement {
        expression: expr,
        span: span(),
    })
}

fn make_ir0(body: Vec<Statement>, goal: ParseGoal, label: &str) -> Ir0Module {
    Ir0Module::from_syntax_tree(
        SyntaxTree {
            goal,
            body,
            span: span(),
        },
        label,
    )
}

fn default_ctx() -> LoweringContext {
    LoweringContext::new("trace-enr", "decision-enr", "policy-enr")
}

// --- 1. Numeric literal lowering ---

#[test]
fn enrichment_numeric_literal_lowering_produces_ir3() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(42))],
        ParseGoal::Script,
        "enr_num.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 2. String literal lowering ---

#[test]
fn enrichment_string_literal_lowering_produces_ir3() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::StringLiteral("hello".to_string()))],
        ParseGoal::Script,
        "enr_str.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 3. Boolean literal lowering ---

#[test]
fn enrichment_boolean_true_literal_lowering() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::BooleanLiteral(true))],
        ParseGoal::Script,
        "enr_true.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

#[test]
fn enrichment_boolean_false_literal_lowering() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::BooleanLiteral(false))],
        ParseGoal::Script,
        "enr_false.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 5. Null literal lowering ---

#[test]
fn enrichment_null_literal_lowering() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NullLiteral)],
        ParseGoal::Script,
        "enr_null.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 6. Undefined literal lowering ---

#[test]
fn enrichment_undefined_literal_lowering() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::UndefinedLiteral)],
        ParseGoal::Script,
        "enr_undef.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 7. Multiple statements ---

#[test]
fn enrichment_multiple_expression_statements() {
    let ir0 = make_ir0(
        vec![
            make_expr_stmt(Expression::NumericLiteral(1)),
            make_expr_stmt(Expression::NumericLiteral(2)),
            make_expr_stmt(Expression::NumericLiteral(3)),
        ],
        ParseGoal::Script,
        "enr_multi.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(output.ir3.instructions.len() > 3);
}

// --- 8. Variable declaration: let ---

#[test]
fn enrichment_let_declaration_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let x = 10;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_let.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 9. Variable declaration: var ---

#[test]
fn enrichment_var_declaration_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var y = 20;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_var.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 10. Variable declaration: const ---

#[test]
fn enrichment_const_declaration_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const z = 30;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_const.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 11. Binary add operator ---

#[test]
fn enrichment_binary_add_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1 + 2;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_add.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_add = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Add { .. })
    });
    assert!(has_add, "should have Add instruction");
}

// --- 12. Binary subtract operator ---

#[test]
fn enrichment_binary_subtract_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("10 - 3;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_sub.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_sub = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Sub { .. })
    });
    assert!(has_sub, "should have Sub instruction");
}

// --- 13. Binary multiply operator ---

#[test]
fn enrichment_binary_multiply_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("4 * 5;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_mul.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_mul = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Mul { .. })
    });
    assert!(has_mul, "should have Mul instruction");
}

// --- 14. Binary divide operator ---

#[test]
fn enrichment_binary_divide_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("10 / 2;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_div.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_div = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Div { .. })
    });
    assert!(has_div, "should have Div instruction");
}

// --- 15. Binary remainder operator ---

#[test]
fn enrichment_binary_remainder_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("7 % 3;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_mod.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_mod = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Mod { .. })
    });
    assert!(has_mod, "should have Mod instruction");
}

// --- 16. Comparison operators ---

#[test]
fn enrichment_less_than_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1 < 2;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_lt.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_lt = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Lt { .. })
    });
    assert!(has_lt, "should have Lt instruction");
}

#[test]
fn enrichment_greater_than_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("2 > 1;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_gt.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_gt = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Gt { .. })
    });
    assert!(has_gt, "should have Gt instruction");
}

#[test]
fn enrichment_strict_equal_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1 === 1;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_seq.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_seq = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::StrictEq { .. })
    });
    assert!(has_seq, "should have StrictEq instruction");
}

#[test]
fn enrichment_not_equal_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1 != 2;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_neq.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_neq = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::NotEq { .. })
    });
    assert!(has_neq, "should have NotEq instruction");
}

// --- 20. Bitwise operators ---

#[test]
fn enrichment_bitwise_and_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("5 & 3;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_bitand.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_bitand = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::BitAnd { .. })
    });
    assert!(has_bitand, "should have BitAnd instruction");
}

#[test]
fn enrichment_bitwise_or_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("5 | 3;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_bitor.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_bitor = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::BitOr { .. })
    });
    assert!(has_bitor, "should have BitOr instruction");
}

#[test]
fn enrichment_bitwise_xor_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("5 ^ 3;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_bitxor.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_bitxor = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::BitXor { .. })
    });
    assert!(has_bitxor, "should have BitXor instruction");
}

#[test]
fn enrichment_left_shift_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1 << 3;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_shl.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_shl = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Shl { .. })
    });
    assert!(has_shl, "should have Shl instruction");
}

#[test]
fn enrichment_right_shift_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("8 >> 2;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_shr.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_shr = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Shr { .. })
    });
    assert!(has_shr, "should have Shr instruction");
}

// --- 25. Unary operators ---

#[test]
fn enrichment_unary_negate_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("-42;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_neg.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_neg = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::UnaryNeg { .. })
    });
    assert!(has_neg, "should have UnaryNeg instruction");
}

#[test]
fn enrichment_unary_logical_not_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("!true;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_not.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_not = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::LogicalNot { .. })
    });
    assert!(has_not, "should have LogicalNot instruction");
}

#[test]
fn enrichment_unary_typeof_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("typeof x;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_typeof.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_typeof = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::TypeOf { .. })
    });
    assert!(has_typeof, "should have TypeOf instruction");
}

#[test]
fn enrichment_unary_void_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("void 0;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_void.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_void = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Void { .. })
    });
    assert!(has_void, "should have Void instruction");
}

#[test]
fn enrichment_unary_bitwise_not_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("~42;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_bitnot.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_bitnot = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::BitNot { .. })
    });
    assert!(has_bitnot, "should have BitNot instruction");
}

// --- 30. If statement ---

#[test]
fn enrichment_if_statement_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("if (true) { 1; } else { 2; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_if.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_jump = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Jump { .. } | Ir3Instruction::JumpIf { .. })
    });
    assert!(has_jump, "if statement should produce jump instructions");
}

#[test]
fn enrichment_if_without_else_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("if (true) { 1; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_if_no_else.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 32. While loop ---

#[test]
fn enrichment_while_loop_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("while (true) { 1; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_while.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let jump_count = output.ir3.instructions.iter().filter(|i| {
        matches!(i, Ir3Instruction::Jump { .. })
    }).count();
    assert!(jump_count >= 1, "while loop should have at least one back-edge jump");
}

// --- 33. Do-while loop ---

#[test]
fn enrichment_do_while_loop_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("do { 1; } while (false);", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_dowhile.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 34. For loop ---

#[test]
fn enrichment_for_loop_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("for (let i = 0; i < 10; i = i + 1) { 1; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_for.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 35. For-in loop ---

#[test]
fn enrichment_for_in_loop_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("for (let k in obj) { k; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_forin.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_for_in = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::ForInInit { .. } | Ir3Instruction::ForInNext { .. })
    });
    assert!(has_for_in, "for-in should produce ForInInit/ForInNext");
}

// --- 36. For-of loop ---

#[test]
fn enrichment_for_of_loop_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("for (let v of arr) { v; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_forof.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_for_of = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::ForOfInit { .. } | Ir3Instruction::ForOfNext { .. })
    });
    assert!(has_for_of, "for-of should produce ForOfInit/ForOfNext");
}

// --- 37. Try-catch lowering ---

#[test]
fn enrichment_try_catch_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("try { 1; } catch (e) { 2; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_trycatch.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 38. Throw statement ---

#[test]
fn enrichment_throw_statement_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("throw 42;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_throw.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 39. Return statement ---

#[test]
fn enrichment_return_statement_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("function f() { return 1; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_return.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 40. Function declaration ---

#[test]
fn enrichment_function_declaration_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("function foo() { 42; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_func.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 41. Import statement ---

#[test]
fn enrichment_import_statement_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(r#"import foo from "bar";"#, ParseGoal::Module)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_import.mjs");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 42. Export named clause ---

#[test]
fn enrichment_export_named_clause_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(r#"let x = 1; export { x };"#, ParseGoal::Module)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_export_named.mjs");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 43. Call expression ---

#[test]
fn enrichment_call_expression_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("foo(1, 2);", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_call.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_call = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Call { .. })
    });
    assert!(has_call, "call expression should produce Call instruction");
}

// --- 44. Member access ---

#[test]
fn enrichment_member_access_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("obj.prop;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_member.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_get = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::GetProperty { .. })
    });
    assert!(has_get, "member access should produce GetProperty");
}

// --- 45. Computed member access ---

#[test]
fn enrichment_computed_member_access_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("obj[0];", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_computed.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_get = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::GetProperty { .. })
    });
    assert!(has_get, "computed member access should produce GetProperty");
}

// --- 46. Assignment expression ---

#[test]
fn enrichment_assignment_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let x = 0; x = 5;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_assign.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 47. Compound assignment: += ---

#[test]
fn enrichment_add_assign_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let x = 0; x += 5;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_addassign.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_add = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Add { .. })
    });
    assert!(has_add, "+= should produce Add instruction");
}

// --- 48. Compound assignment: -= ---

#[test]
fn enrichment_sub_assign_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let x = 10; x -= 3;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_subassign.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_sub = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Sub { .. })
    });
    assert!(has_sub, "-= should produce Sub instruction");
}

// --- 49. Await expression ---

#[test]
fn enrichment_await_expression_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("await 42;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_await.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 50. This expression ---

#[test]
fn enrichment_this_expression_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("this;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_this.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 51. Array literal ---

#[test]
fn enrichment_array_literal_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("[1, 2, 3];", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_array.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_new_array = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::NewArray { .. })
    });
    assert!(has_new_array, "array literal should produce NewArray");
}

// --- 52. Object literal ---

#[test]
fn enrichment_object_literal_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let obj = { a: 1, b: 2 };", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_object.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_new_obj = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::NewObject { .. })
    });
    assert!(has_new_obj, "object literal should produce NewObject");
}

// --- 53. New expression ---

#[test]
fn enrichment_new_expression_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("new Foo(1);", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_new.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_construct = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::Construct { .. })
    });
    assert!(has_construct, "new expression should produce Construct");
}

// --- 54. Conditional (ternary) expression ---

#[test]
fn enrichment_conditional_expression_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("true ? 1 : 2;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_ternary.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 55. Logical AND short-circuit ---

#[test]
fn enrichment_logical_and_short_circuit() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("true && false;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_logand.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_jump_if = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::JumpIf { .. })
    });
    assert!(has_jump_if, "logical AND should produce JumpIf for short-circuit");
}

// --- 56. Logical OR short-circuit ---

#[test]
fn enrichment_logical_or_short_circuit() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("false || true;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_logor.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 57. Nullish coalescing ---

#[test]
fn enrichment_nullish_coalescing() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("null ?? 42;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_nullish.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_nullish_jump = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::JumpIfNullish { .. })
    });
    assert!(has_nullish_jump, "?? should produce JumpIfNullish");
}

// --- 58. Switch statement ---

#[test]
fn enrichment_switch_statement_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("switch (x) { case 1: 10; break; case 2: 20; break; default: 0; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_switch.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 59. Delete member expression ---

#[test]
fn enrichment_delete_member_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("delete obj.x;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_delete.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_delete = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::DeleteProperty { .. })
    });
    assert!(has_delete, "delete obj.x should produce DeleteProperty");
}

// --- 60. Determinism: same AST yields identical hashes ---

#[test]
fn enrichment_determinism_same_ast_identical_hashes() {
    let body = vec![
        make_expr_stmt(Expression::NumericLiteral(100)),
        make_expr_stmt(Expression::StringLiteral("abc".to_string())),
    ];
    let ir0 = make_ir0(body.clone(), ParseGoal::Script, "enr_det1.js");
    let ctx = default_ctx();
    let out1 = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline 1");
    let out2 = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline 2");
    assert_eq!(out1.ir3.content_hash(), out2.ir3.content_hash());
    assert_eq!(out1.ir2.content_hash(), out2.ir2.content_hash());
    assert_eq!(out1.ir1.content_hash(), out2.ir1.content_hash());
    assert_eq!(out1.witnesses, out2.witnesses);
    assert_eq!(out1.isomorphism_ledger, out2.isomorphism_ledger);
}

// --- 61. Different AST -> different hashes ---

#[test]
fn enrichment_different_ast_different_hashes() {
    let ir0_a = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
        ParseGoal::Script,
        "enr_diff_a.js",
    );
    let ir0_b = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(2))],
        ParseGoal::Script,
        "enr_diff_b.js",
    );
    let ctx = default_ctx();
    let out_a = lower_ir0_to_ir3(&ir0_a, &ctx).expect("pipeline a");
    let out_b = lower_ir0_to_ir3(&ir0_b, &ctx).expect("pipeline b");
    assert_ne!(out_a.ir3.content_hash(), out_b.ir3.content_hash());
}

// --- 62. Empty body error ---

#[test]
fn enrichment_empty_body_returns_error() {
    let ir0 = make_ir0(vec![], ParseGoal::Script, "enr_empty.js");
    let err = lower_ir0_to_ir3(&ir0, &default_ctx()).expect_err("should fail");
    assert_eq!(err, LoweringPipelineError::EmptyIr0Body);
}

// --- 63. Empty body individual pass ---

#[test]
fn enrichment_empty_body_individual_pass_error() {
    let ir0 = make_ir0(vec![], ParseGoal::Script, "enr_empty_p1.js");
    let err = lower_ir0_to_ir1(&ir0).expect_err("should fail");
    assert_eq!(err, LoweringPipelineError::EmptyIr0Body);
}

// --- 64. Duplicate let detected by validation ---

#[test]
fn enrichment_duplicate_let_semantic_validation() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let a = 1; let a = 2;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_dup_let.js");
    let result = validate_ir0_static_semantics(&ir0);
    assert!(!result.is_valid());
}

// --- 65. Duplicate const detected ---

#[test]
fn enrichment_duplicate_const_semantic_validation() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const a = 1; const a = 2;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_dup_const.js");
    let result = validate_ir0_static_semantics(&ir0);
    assert!(!result.is_valid());
}

// --- 66. Var-var is allowed (no conflict) ---

#[test]
fn enrichment_var_var_no_conflict() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("var a = 1; var a = 2;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_var_var.js");
    let result = validate_ir0_static_semantics(&ir0);
    assert!(result.is_valid(), "var + var should not conflict");
}

// --- 67. Const without initializer is invalid ---

#[test]
fn enrichment_const_no_init_validation() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const x;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_const_no_init.js");
    let result = validate_ir0_static_semantics(&ir0);
    assert!(!result.is_valid());
}

// --- 68. Const without init fails in lowering too ---

#[test]
fn enrichment_const_no_init_lowering_error() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const x;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_const_no_init_lower.js");
    let err = lower_ir0_to_ir3(&ir0, &default_ctx()).expect_err("should fail");
    assert!(matches!(err, LoweringPipelineError::SemanticViolation(_)));
}

// --- 69. Duplicate import binding ---

#[test]
fn enrichment_duplicate_import_binding_validation() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            r#"import x from "a"; import x from "b";"#,
            ParseGoal::Module,
        )
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_dup_import.mjs");
    let result = validate_ir0_static_semantics(&ir0);
    assert!(!result.is_valid(), "duplicate import bindings should be invalid");
}

// --- 70. Duplicate default export ---

#[test]
fn enrichment_duplicate_default_export_validation() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("export default 1; export default 2;", ParseGoal::Module)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_dup_default.mjs");
    let result = validate_ir0_static_semantics(&ir0);
    assert!(!result.is_valid(), "duplicate default exports should be invalid");
}

// --- 71. IR3 always ends with Halt ---

#[test]
fn enrichment_ir3_ends_with_halt() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("42;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_halt.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(
        matches!(output.ir3.instructions.last(), Some(Ir3Instruction::Halt)),
        "IR3 should end with Halt"
    );
}

// --- 72. IR3 function table has main entry ---

#[test]
fn enrichment_ir3_function_table_has_main() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("42;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_ftable.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.function_table.is_empty());
    assert_eq!(output.ir3.function_table[0].entry, 0);
    assert_eq!(output.ir3.function_table[0].name, Some("main".to_string()));
}

// --- 73. Serde roundtrip for LoweringContext ---

#[test]
fn enrichment_lowering_context_serde_roundtrip() {
    let ctx = LoweringContext::new("trace-serde", "decision-serde", "policy-serde");
    let json = serde_json::to_string(&ctx).expect("serialize");
    let recovered: LoweringContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ctx, recovered);
}

// --- 74. Serde roundtrip for InvariantCheck ---

#[test]
fn enrichment_invariant_check_serde_roundtrip() {
    let check = InvariantCheck {
        name: "test_check".to_string(),
        passed: true,
        detail: "all good".to_string(),
    };
    let json = serde_json::to_string(&check).expect("serialize");
    let recovered: InvariantCheck = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(check, recovered);
}

// --- 75. FlowProofArtifactEntry serde ---

#[test]
fn enrichment_flow_proof_entry_serde_roundtrip() {
    let entry = FlowProofArtifactEntry {
        op_index: 5,
        source_label: Label::Public,
        sink_clearance: Label::Internal,
        capability: Some("fs.read".to_string()),
        proof_method: ProofMethod::StaticAnalysis,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: FlowProofArtifactEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, recovered);
}

// --- 76. RuntimeCheckpointArtifactEntry serde ---

#[test]
fn enrichment_runtime_checkpoint_entry_serde_roundtrip() {
    let entry = RuntimeCheckpointArtifactEntry {
        op_index: 3,
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        capability: Some("hostcall.invoke".to_string()),
        reason: "dynamic_capability".to_string(),
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: RuntimeCheckpointArtifactEntry =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, recovered);
}

// --- 77. Error display variants ---

#[test]
fn enrichment_error_display_semantic_violation() {
    let err = LoweringPipelineError::SemanticViolation(
        frankenengine_engine::parser::SemanticError::new(
            frankenengine_engine::parser::SemanticErrorCode::DuplicateLetConstDeclaration,
            Some("x".to_string()),
            None,
        ),
    );
    let msg = err.to_string();
    assert!(!msg.is_empty());
}

#[test]
fn enrichment_error_display_unauthorized_flow() {
    let err = LoweringPipelineError::UnauthorizedFlow {
        op_index: 42,
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        detail: "blocked".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("42"));
    assert!(msg.contains("blocked"));
}

// --- 79. Event components are always "lowering_pipeline" ---

#[test]
fn enrichment_events_component_is_lowering_pipeline() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_component.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    for event in &output.events {
        assert_eq!(event.component, "lowering_pipeline");
    }
}

// --- 80. Ledger op counts are consistent ---

#[test]
fn enrichment_ledger_op_counts_consistent() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1 + 2;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_opcounts.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    for entry in &output.isomorphism_ledger {
        assert!(entry.output_op_count > 0, "output op count should be > 0");
    }
    // First pass output count should equal second pass input (by op count reasoning)
    assert_eq!(
        output.isomorphism_ledger[0].output_op_count,
        output.isomorphism_ledger[1].input_op_count,
        "pass 1 output ops == pass 2 input ops"
    );
}

// --- 81. IR1 Return at end ---

#[test]
fn enrichment_ir1_has_return_at_end() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
        ParseGoal::Script,
        "enr_ir1_return.js",
    );
    let pass1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1");
    assert!(
        matches!(pass1.module.ops.last(), Some(Ir1Op::Return)),
        "IR1 should end with Return"
    );
}

// --- 82. IR2 preserves scope from IR1 ---

#[test]
fn enrichment_ir2_preserves_scopes() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
        ParseGoal::Script,
        "enr_ir2_scopes.js",
    );
    let pass1 = lower_ir0_to_ir1(&ir0).expect("ir0->ir1");
    let pass2 = lower_ir1_to_ir2(&pass1.module).expect("ir1->ir2");
    assert_eq!(pass1.module.scopes.len(), pass2.module.scopes.len());
}

// --- 83. Hostcall with multiple capabilities ---

#[test]
fn enrichment_multiple_hostcall_capabilities() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            r#"hostcall<"fs.read">(); hostcall<"net.send">();"#,
            ParseGoal::Script,
        )
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_multi_hostcall.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let caps: Vec<&str> = output
        .ir2
        .required_capabilities
        .iter()
        .map(|c| c.0.as_str())
        .collect();
    assert!(caps.contains(&"fs.read"));
    assert!(caps.contains(&"net.send"));
}

// --- 84. Pipeline with complex nested expression ---

#[test]
fn enrichment_nested_binary_expression() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("(1 + 2) * (3 - 4);", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_nested.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_add = output.ir3.instructions.iter().any(|i| matches!(i, Ir3Instruction::Add { .. }));
    let has_sub = output.ir3.instructions.iter().any(|i| matches!(i, Ir3Instruction::Sub { .. }));
    let has_mul = output.ir3.instructions.iter().any(|i| matches!(i, Ir3Instruction::Mul { .. }));
    assert!(has_add && has_sub && has_mul);
}

// --- 85. Identifier reference lowering ---

#[test]
fn enrichment_identifier_reference_lowering() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::Identifier("foo".to_string()))],
        ParseGoal::Script,
        "enr_ident.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 86. IR3 jump targets are all within bounds ---

#[test]
fn enrichment_ir3_jump_targets_in_bounds() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("if (true) { 1; } else { 2; } while (false) { 3; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_bounds.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let len = output.ir3.instructions.len();
    for instr in &output.ir3.instructions {
        match instr {
            Ir3Instruction::Jump { target } => {
                assert!((*target as usize) < len, "jump target out of bounds");
            }
            Ir3Instruction::JumpIf { target, .. } => {
                assert!((*target as usize) < len, "jumpif target out of bounds");
            }
            _ => {}
        }
    }
}

// --- 87. Flow proof artifact id is stable ---

#[test]
fn enrichment_flow_proof_artifact_id_stable() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("42;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_artifact_stable.js");
    let ctx = default_ctx();
    let out1 = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline 1");
    let out2 = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline 2");
    assert_eq!(
        out1.ir2_flow_proof_artifact.artifact_id,
        out2.ir2_flow_proof_artifact.artifact_id
    );
}

// --- 88. Template literal lowering ---

#[test]
fn enrichment_template_literal_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("`hello ${42} world`;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_template.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_template = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::TemplateLiteral { .. })
    });
    assert!(has_template, "template literal should produce TemplateLiteral");
}

// --- 89. Large numeric literal ---

#[test]
fn enrichment_large_numeric_literal() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(i64::MAX))],
        ParseGoal::Script,
        "enr_large_num.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 90. Negative numeric literal ---

#[test]
fn enrichment_negative_numeric_literal() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(-1))],
        ParseGoal::Script,
        "enr_neg_num.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 91. Zero numeric literal ---

#[test]
fn enrichment_zero_numeric_literal() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(0))],
        ParseGoal::Script,
        "enr_zero.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 92. Empty string literal ---

#[test]
fn enrichment_empty_string_literal() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::StringLiteral(String::new()))],
        ParseGoal::Script,
        "enr_empty_str.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 93. Witnesses have non-empty hashes ---

#[test]
fn enrichment_witness_hashes_non_empty() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(7))],
        ParseGoal::Script,
        "enr_witness_hash.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    for witness in &output.witnesses {
        assert!(!witness.input_hash.is_empty());
        assert!(!witness.output_hash.is_empty());
        assert!(!witness.rollback_token.is_empty());
    }
}

// --- 94. Individual pass witness pass_id matches ledger ---

#[test]
fn enrichment_witness_pass_id_matches_ledger() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(7))],
        ParseGoal::Script,
        "enr_match_ids.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    for (witness, ledger) in output.witnesses.iter().zip(output.isomorphism_ledger.iter()) {
        assert_eq!(witness.pass_id, ledger.pass_id);
    }
}

// --- 95. IR2 flow proof schema version is set ---

#[test]
fn enrichment_flow_proof_schema_version() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
        ParseGoal::Script,
        "enr_schema_ver.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(
        output.ir2_flow_proof_artifact.schema_version.contains("v1"),
        "schema version should contain v1"
    );
}

// --- 96. Error variant equality ---

#[test]
fn enrichment_error_variant_equality() {
    let err1 = LoweringPipelineError::EmptyIr0Body;
    let err2 = LoweringPipelineError::EmptyIr0Body;
    assert_eq!(err1, err2);

    let err3 = LoweringPipelineError::InvariantViolation {
        detail: "test",
    };
    let err4 = LoweringPipelineError::InvariantViolation {
        detail: "test",
    };
    assert_eq!(err3, err4);
}

// --- 97. Full pipeline serde roundtrip with complex source ---

#[test]
fn enrichment_complex_pipeline_serde_roundtrip() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let x = 1 + 2; if (x) { x = x - 1; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_complex_serde.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let json = serde_json::to_string(&output).expect("serialize");
    let recovered: LoweringPipelineOutput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(output, recovered);
}

// --- 98. Arrow function lowering ---

#[test]
fn enrichment_arrow_function_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let f = (x) => x + 1;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_arrow.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 99. Multiple imports in module ---

#[test]
fn enrichment_multiple_imports() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            r#"import a from "a"; import b from "b"; a; b;"#,
            ParseGoal::Module,
        )
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_multi_import.mjs");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 100. Property set lowering ---

#[test]
fn enrichment_property_set_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("obj.x = 42;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_setprop.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_set = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::SetProperty { .. })
    });
    assert!(has_set, "property assignment should produce SetProperty");
}

// --- 101. Chained member access ---

#[test]
fn enrichment_chained_member_access() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("a.b.c;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_chain.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let get_count = output.ir3.instructions.iter().filter(|i| {
        matches!(i, Ir3Instruction::GetProperty { .. })
    }).count();
    assert!(get_count >= 2, "a.b.c should produce at least 2 GetProperty");
}

// --- 102. Empty array literal ---

#[test]
fn enrichment_empty_array_literal() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("[];", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_empty_arr.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_new_array = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::NewArray { .. })
    });
    assert!(has_new_array, "empty array literal should produce NewArray");
}

// --- 103. Try-catch-finally ---

#[test]
fn enrichment_try_catch_finally_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("try { 1; } catch (e) { 2; } finally { 3; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_tcf.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 104. Switch with default only ---

#[test]
fn enrichment_switch_default_only() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("switch (x) { default: 0; }", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_switch_default.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert!(!output.ir3.instructions.is_empty());
}

// --- 105. IrContractValidation error display ---

#[test]
fn enrichment_ir_contract_validation_error_display() {
    let err = LoweringPipelineError::IrContractValidation {
        code: "FE-IR-TEST".to_string(),
        level: IrLevel::Ir2,
        message: "test message".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("FE-IR-TEST"));
    assert!(msg.contains("test message"));
}

// --- 106. Ledger pass IDs are specific strings ---

#[test]
fn enrichment_ledger_pass_ids_are_canonical() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
        ParseGoal::Script,
        "enr_canonical_ids.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let ids: Vec<&str> = output
        .isomorphism_ledger
        .iter()
        .map(|e| e.pass_id.as_str())
        .collect();
    assert_eq!(ids, vec!["ir0_to_ir1", "ir1_to_ir2", "ir2_to_ir3"]);
}

// --- 107. Context trace_id in flow proof artifact ---

#[test]
fn enrichment_context_in_flow_proof_artifact() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
        ParseGoal::Script,
        "enr_ctx_artifact.js",
    );
    let ctx = LoweringContext::new("my-trace", "my-decision", "my-policy");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("pipeline");
    assert_eq!(output.ir2_flow_proof_artifact.trace_id, "my-trace");
    assert_eq!(output.ir2_flow_proof_artifact.decision_id, "my-decision");
    assert_eq!(output.ir2_flow_proof_artifact.policy_id, "my-policy");
}

// --- 108. Module id in flow proof artifact matches source label ---

#[test]
fn enrichment_module_id_in_artifact() {
    let ir0 = make_ir0(
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
        ParseGoal::Script,
        "my_unique_module.js",
    );
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    assert_eq!(
        output.ir2_flow_proof_artifact.module_id,
        "my_unique_module.js"
    );
}

// --- 109. Instanceof operator ---

#[test]
fn enrichment_instanceof_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("x instanceof Array;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_instanceof.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_instanceof = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::InstanceOf { .. })
    });
    assert!(has_instanceof, "instanceof should produce InstanceOf");
}

// --- 110. Unary plus operator ---

#[test]
fn enrichment_unary_plus_lowering() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("+42;", ParseGoal::Script)
        .expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "enr_uplus.js");
    let output = lower_ir0_to_ir3(&ir0, &default_ctx()).expect("pipeline");
    let has_uplus = output.ir3.instructions.iter().any(|i| {
        matches!(i, Ir3Instruction::UnaryPlus { .. })
    });
    assert!(has_uplus, "unary + should produce UnaryPlus");
}
