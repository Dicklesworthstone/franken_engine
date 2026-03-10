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
