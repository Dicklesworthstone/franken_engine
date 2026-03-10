//! Integration tests for ir_contract (bd-1wa).

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

use frankenengine_engine::ast::{
    Expression, ExpressionStatement, ParseGoal, SourceSpan, Statement, SyntaxTree,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    BindingKind, CapabilityTag, EffectBoundary, ExecutionOutcome, FlowAnnotation,
    HostcallDecisionRecord, Ir0Module, Ir1Module, Ir1Op, Ir2Module, Ir2Op, Ir3FunctionDesc,
    Ir3Instruction, Ir3Module, Ir4Module, IrContractEvent, IrError, IrErrorCode, IrLevel,
    IrSchemaVersion, IrVerifier, RegRange, ResolvedBinding, ScopeId, ScopeKind, ScopeNode,
    SpecializationLinkage, WitnessEvent, WitnessEventKind, error_code, verify_ir1_source,
    verify_ir3_specialization, verify_ir4_linkage,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_span() -> SourceSpan {
    SourceSpan::new(0, 10, 1, 1, 1, 11)
}

fn make_syntax_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(42),
            span: make_span(),
        })],
        span: make_span(),
    }
}

fn make_ir0() -> Ir0Module {
    Ir0Module::from_syntax_tree(make_syntax_tree(), "integration.js")
}

fn make_ir1(ir0_hash: ContentHash) -> Ir1Module {
    let mut ir1 = Ir1Module::new(ir0_hash, "integration.js");
    ir1.scopes.push(ScopeNode {
        scope_id: ScopeId { depth: 0, index: 0 },
        parent: None,
        kind: ScopeKind::Global,
        bindings: vec![ResolvedBinding {
            name: "x".to_string(),
            binding_id: 0,
            scope: ScopeId { depth: 0, index: 0 },
            kind: BindingKind::Let,
        }],
    });
    ir1.ops.push(Ir1Op::LoadBinding { binding_id: 0 });
    ir1.ops.push(Ir1Op::Return);
    ir1
}

fn make_ir2(ir1_hash: ContentHash) -> Ir2Module {
    let mut ir2 = Ir2Module::new(ir1_hash, "integration.js");
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::LoadBinding { binding_id: 0 },
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
    });
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::Call { arg_count: 1 },
        effect: EffectBoundary::HostcallEffect,
        required_capability: Some(CapabilityTag("fs:read".to_string())),
        flow: Some(FlowAnnotation {
            data_label: Label::Internal,
            sink_clearance: Label::Internal,
            declassification_required: false,
        }),
    });
    ir2.required_capabilities
        .push(CapabilityTag("fs:read".to_string()));
    ir2
}

fn make_ir3(ir2_hash: ContentHash) -> Ir3Module {
    let mut ir3 = Ir3Module::new(ir2_hash, "integration.js");
    ir3.instructions
        .push(Ir3Instruction::LoadInt { dst: 0, value: 42 });
    ir3.instructions.push(Ir3Instruction::LoadStr {
        dst: 1,
        pool_index: 0,
    });
    ir3.instructions.push(Ir3Instruction::Add {
        dst: 2,
        lhs: 0,
        rhs: 1,
    });
    ir3.instructions.push(Ir3Instruction::HostCall {
        capability: CapabilityTag("fs:read".to_string()),
        args: RegRange { start: 0, count: 1 },
        dst: 3,
    });
    ir3.instructions.push(Ir3Instruction::Return { value: 3 });
    ir3.constant_pool.push("hello".to_string());
    ir3.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 0,
        frame_size: 4,
        name: Some("main".to_string()),
    });
    ir3.required_capabilities
        .push(CapabilityTag("fs:read".to_string()));
    ir3
}

fn make_ir4(ir3_hash: ContentHash) -> Ir4Module {
    let mut ir4 = Ir4Module::new(ir3_hash, "integration.js");
    ir4.events.push(WitnessEvent {
        seq: 0,
        kind: WitnessEventKind::CapabilityChecked,
        instruction_index: 3,
        payload_hash: ContentHash::compute(b"cap:fs:read"),
        timestamp_tick: 10,
    });
    ir4.events.push(WitnessEvent {
        seq: 1,
        kind: WitnessEventKind::HostcallDispatched,
        instruction_index: 3,
        payload_hash: ContentHash::compute(b"hostcall:fs:read"),
        timestamp_tick: 20,
    });
    ir4.events.push(WitnessEvent {
        seq: 2,
        kind: WitnessEventKind::ExecutionCompleted,
        instruction_index: 4,
        payload_hash: ContentHash::compute(b"result"),
        timestamp_tick: 30,
    });
    ir4.hostcall_decisions.push(HostcallDecisionRecord {
        seq: 0,
        capability: CapabilityTag("fs:read".to_string()),
        allowed: true,
        instruction_index: 3,
    });
    ir4.instructions_executed = 5;
    ir4.duration_ticks = 30;
    ir4.outcome = ExecutionOutcome::Completed;
    ir4
}

// ---------------------------------------------------------------------------
// Full pipeline: IR0 -> IR1 -> IR2 -> IR3 -> IR4
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_hash_chain_integration() {
    let ir0 = make_ir0();
    let ir0_hash = ir0.content_hash();

    let ir1 = make_ir1(ir0_hash.clone());
    verify_ir1_source(&ir1, &ir0_hash).unwrap();
    let ir1_hash = ir1.content_hash();

    let ir2 = make_ir2(ir1_hash.clone());
    let ir2_hash = ir2.content_hash();

    let ir3 = make_ir3(ir2_hash.clone());
    verify_ir3_specialization(&ir3).unwrap();
    let ir3_hash = ir3.content_hash();

    let ir4 = make_ir4(ir3_hash.clone());
    verify_ir4_linkage(&ir4, &ir3_hash).unwrap();

    // All hashes distinct.
    let hashes = [ir0_hash, ir1_hash, ir2_hash, ir3_hash, ir4.content_hash()];
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "hash collision at levels {i} and {j}");
        }
    }
}

// ---------------------------------------------------------------------------
// IrVerifier full pipeline with structured events
// ---------------------------------------------------------------------------

#[test]
fn verifier_full_pipeline_events() {
    let ir0 = make_ir0();
    let ir0_hash = ir0.content_hash();
    let ir1 = make_ir1(ir0_hash.clone());
    let ir3 = make_ir3(ContentHash::compute(b"ir2"));
    let ir3_hash = ir3.content_hash();
    let ir4 = make_ir4(ir3_hash.clone());

    let mut verifier = IrVerifier::new();
    verifier.verify_ir0(&ir0, &ir0_hash, "int-trace").unwrap();
    verifier.verify_ir1(&ir1, &ir0_hash, "int-trace").unwrap();
    verifier.verify_ir3(&ir3, "int-trace").unwrap();
    verifier.verify_ir4(&ir4, &ir3_hash, "int-trace").unwrap();

    let events = verifier.drain_events();
    assert_eq!(events.len(), 4);

    // All events have correct trace_id and component.
    for e in &events {
        assert_eq!(e.trace_id, "int-trace");
        assert_eq!(e.component, "ir_contract");
        assert_eq!(e.outcome, "ok");
        assert!(e.content_hash.is_some());
        assert!(e.error_code.is_none());
    }

    // Events cover all verified levels.
    let levels: Vec<IrLevel> = events.iter().map(|e| e.level).collect();
    assert_eq!(
        levels,
        vec![IrLevel::Ir0, IrLevel::Ir1, IrLevel::Ir3, IrLevel::Ir4]
    );
}

#[test]
fn verifier_captures_multiple_failures() {
    let ir0 = make_ir0();
    let wrong_hash = ContentHash::compute(b"wrong");

    let mut verifier = IrVerifier::new();

    // First failure: IR0 hash mismatch.
    let _ = verifier.verify_ir0(&ir0, &wrong_hash, "t-multi");

    // Second failure: IR3 invalid specialization.
    let source_hash = ContentHash::compute(b"test");
    let mut ir3 = Ir3Module::new(source_hash, "bad.js");
    ir3.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec![], // empty — invalid
        optimization_class: "opt".to_string(),
        validity_epoch: 1,
        rollback_token: ContentHash::compute(b"baseline"),
    });
    let _ = verifier.verify_ir3(&ir3, "t-multi");

    let events = verifier.drain_events();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|e| e.outcome == "error"));
    assert_eq!(
        events[0].error_code.as_deref(),
        Some("IR_HASH_VERIFICATION_FAILED")
    );
    assert_eq!(
        events[1].error_code.as_deref(),
        Some("IR_INVALID_SPECIALIZATION_LINKAGE")
    );
}

// ---------------------------------------------------------------------------
// Serde roundtrips (integration)
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_serde_roundtrip() {
    let ir0 = make_ir0();
    let ir0_hash = ir0.content_hash();
    let ir1 = make_ir1(ir0_hash.clone());
    let ir1_hash = ir1.content_hash();
    let ir2 = make_ir2(ir1_hash.clone());
    let ir2_hash = ir2.content_hash();
    let ir3 = make_ir3(ir2_hash.clone());
    let ir3_hash = ir3.content_hash();
    let ir4 = make_ir4(ir3_hash.clone());

    // Round-trip each level through JSON.
    let ir0_json = serde_json::to_string(&ir0).unwrap();
    let ir0_r: Ir0Module = serde_json::from_str(&ir0_json).unwrap();
    assert_eq!(ir0, ir0_r);

    let ir1_json = serde_json::to_string(&ir1).unwrap();
    let ir1_r: Ir1Module = serde_json::from_str(&ir1_json).unwrap();
    assert_eq!(ir1, ir1_r);

    let ir2_json = serde_json::to_string(&ir2).unwrap();
    let ir2_r: Ir2Module = serde_json::from_str(&ir2_json).unwrap();
    assert_eq!(ir2, ir2_r);

    let ir3_json = serde_json::to_string(&ir3).unwrap();
    let ir3_r: Ir3Module = serde_json::from_str(&ir3_json).unwrap();
    assert_eq!(ir3, ir3_r);

    let ir4_json = serde_json::to_string(&ir4).unwrap();
    let ir4_r: Ir4Module = serde_json::from_str(&ir4_json).unwrap();
    assert_eq!(ir4, ir4_r);
}

#[test]
fn verifier_events_serde_roundtrip() {
    let ir0 = make_ir0();
    let ir0_hash = ir0.content_hash();

    let mut verifier = IrVerifier::new();
    verifier.verify_ir0(&ir0, &ir0_hash, "serde-t").unwrap();

    let events = verifier.drain_events();
    let json = serde_json::to_string(&events).unwrap();
    let restored: Vec<IrContractEvent> = serde_json::from_str(&json).unwrap();
    assert_eq!(events, restored);
}

// ---------------------------------------------------------------------------
// Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_replay_produces_identical_hashes() {
    let run = || {
        let ir0 = make_ir0();
        let ir0_hash = ir0.content_hash();
        let ir1 = make_ir1(ir0_hash.clone());
        let ir1_hash = ir1.content_hash();
        let ir2 = make_ir2(ir1_hash.clone());
        let ir2_hash = ir2.content_hash();
        let ir3 = make_ir3(ir2_hash.clone());
        let ir3_hash = ir3.content_hash();
        let ir4 = make_ir4(ir3_hash.clone());
        let ir4_hash = ir4.content_hash();
        (ir0_hash, ir1_hash, ir2_hash, ir3_hash, ir4_hash)
    };
    assert_eq!(run(), run());
}

#[test]
fn deterministic_replay_identical_verifier_events() {
    let run = || {
        let ir0 = make_ir0();
        let ir0_hash = ir0.content_hash();
        let ir1 = make_ir1(ir0_hash.clone());
        let ir3 = make_ir3(ContentHash::compute(b"ir2"));
        let ir3_hash = ir3.content_hash();
        let ir4 = make_ir4(ir3_hash.clone());

        let mut verifier = IrVerifier::new();
        verifier.verify_ir0(&ir0, &ir0_hash, "det").unwrap();
        verifier.verify_ir1(&ir1, &ir0_hash, "det").unwrap();
        verifier.verify_ir3(&ir3, "det").unwrap();
        verifier.verify_ir4(&ir4, &ir3_hash, "det").unwrap();
        serde_json::to_string(&verifier.drain_events()).unwrap()
    };
    assert_eq!(run(), run());
}

// ---------------------------------------------------------------------------
// Canonical bytes stability
// ---------------------------------------------------------------------------

#[test]
fn canonical_bytes_differ_for_different_content() {
    let ir0a = Ir0Module::from_syntax_tree(make_syntax_tree(), "a.js");
    let ir0b = Ir0Module::from_syntax_tree(
        SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![],
            span: make_span(),
        },
        "b.js",
    );
    assert_ne!(ir0a.canonical_bytes(), ir0b.canonical_bytes());
}

// ---------------------------------------------------------------------------
// Specialization linkage
// ---------------------------------------------------------------------------

#[test]
fn ir3_with_specialization_and_full_verification() {
    let ir2_hash = ContentHash::compute(b"ir2");
    let mut ir3 = make_ir3(ir2_hash);
    ir3.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec!["proof-001".to_string(), "proof-002".to_string()],
        optimization_class: "hostcall_dispatch".to_string(),
        validity_epoch: 42,
        rollback_token: ContentHash::compute(b"baseline-v1"),
    });

    verify_ir3_specialization(&ir3).unwrap();

    // Serde roundtrip preserves specialization.
    let json = serde_json::to_string(&ir3).unwrap();
    let restored: Ir3Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir3, restored);

    // Content hash changes with specialization.
    let plain = make_ir3(ContentHash::compute(b"ir2"));
    assert_ne!(ir3.content_hash(), plain.content_hash());
}

// ---------------------------------------------------------------------------
// Error codes stability
// ---------------------------------------------------------------------------

#[test]
fn error_codes_are_stable() {
    let cases = [
        (
            IrErrorCode::SchemaVersionMismatch,
            "IR_SCHEMA_VERSION_MISMATCH",
        ),
        (IrErrorCode::LevelMismatch, "IR_LEVEL_MISMATCH"),
        (IrErrorCode::SourceHashMismatch, "IR_SOURCE_HASH_MISMATCH"),
        (
            IrErrorCode::HashVerificationFailed,
            "IR_HASH_VERIFICATION_FAILED",
        ),
        (
            IrErrorCode::MissingCapabilityAnnotation,
            "IR_MISSING_CAPABILITY_ANNOTATION",
        ),
        (
            IrErrorCode::InvalidSpecializationLinkage,
            "IR_INVALID_SPECIALIZATION_LINKAGE",
        ),
        (
            IrErrorCode::WitnessIntegrityViolation,
            "IR_WITNESS_INTEGRITY_VIOLATION",
        ),
    ];
    for (code, expected) in &cases {
        let err = IrError::new(*code, "test", IrLevel::Ir0);
        assert_eq!(
            error_code(&err),
            *expected,
            "error_code mismatch for {code:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

#[test]
fn schema_version_propagates_through_all_levels() {
    let ir0 = make_ir0();
    let ir0_hash = ir0.content_hash();
    let ir1 = make_ir1(ir0_hash);
    let ir1_hash = ir1.content_hash();
    let ir2 = make_ir2(ir1_hash);
    let ir2_hash = ir2.content_hash();
    let ir3 = make_ir3(ir2_hash);
    let ir3_hash = ir3.content_hash();
    let ir4 = make_ir4(ir3_hash);

    let current = IrSchemaVersion::CURRENT;
    assert_eq!(ir0.header.schema_version, current);
    assert_eq!(ir1.header.schema_version, current);
    assert_eq!(ir2.header.schema_version, current);
    assert_eq!(ir3.header.schema_version, current);
    assert_eq!(ir4.header.schema_version, current);
}

// ---------------------------------------------------------------------------
// Verification failure scenarios
// ---------------------------------------------------------------------------

#[test]
fn verify_ir4_non_monotonic_events_rejected() {
    let ir3_hash = ContentHash::compute(b"ir3");
    let mut ir4 = Ir4Module::new(ir3_hash.clone(), "bad.js");
    ir4.events.push(WitnessEvent {
        seq: 5,
        kind: WitnessEventKind::HostcallDispatched,
        instruction_index: 0,
        payload_hash: ContentHash::compute(b"a"),
        timestamp_tick: 100,
    });
    ir4.events.push(WitnessEvent {
        seq: 3, // backwards
        kind: WitnessEventKind::CapabilityChecked,
        instruction_index: 1,
        payload_hash: ContentHash::compute(b"b"),
        timestamp_tick: 200,
    });
    let err = verify_ir4_linkage(&ir4, &ir3_hash).unwrap_err();
    assert_eq!(err.code, IrErrorCode::WitnessIntegrityViolation);
}

#[test]
fn verify_ir1_source_missing_hash_rejected() {
    // Create an IR1 module with a known source hash, but verify against a different one.
    let ir0_hash = ContentHash::compute(b"correct");
    let ir1 = Ir1Module::new(ir0_hash, "test.js");
    let wrong = ContentHash::compute(b"wrong");
    let err = verify_ir1_source(&ir1, &wrong).unwrap_err();
    assert_eq!(err.code, IrErrorCode::SourceHashMismatch);
}

// ---------------------------------------------------------------------------
// IR2 IFC annotation preservation
// ---------------------------------------------------------------------------

#[test]
fn ir2_ifc_annotations_preserved_through_roundtrip() {
    let ir1_hash = ContentHash::compute(b"ir1");
    let mut ir2 = Ir2Module::new(ir1_hash, "ifc.js");
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::Call { arg_count: 0 },
        effect: EffectBoundary::NetworkEffect,
        required_capability: Some(CapabilityTag("net:connect".to_string())),
        flow: Some(FlowAnnotation {
            data_label: Label::Internal,
            sink_clearance: Label::Public,
            declassification_required: true,
        }),
    });

    let json = serde_json::to_string(&ir2).unwrap();
    let restored: Ir2Module = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.ops[0].effect, EffectBoundary::NetworkEffect);
    assert!(
        restored.ops[0]
            .flow
            .as_ref()
            .unwrap()
            .declassification_required
    );
    assert_eq!(
        restored.ops[0].required_capability.as_ref().unwrap().0,
        "net:connect"
    );
}

// ---------------------------------------------------------------------------
// IR4 active specializations
// ---------------------------------------------------------------------------

#[test]
fn ir4_tracks_active_specialization_ids() {
    let ir3_hash = ContentHash::compute(b"ir3");
    let mut ir4 = Ir4Module::new(ir3_hash, "spec.js");
    ir4.active_specialization_ids.push("spec-001".to_string());
    ir4.active_specialization_ids.push("spec-002".to_string());

    let json = serde_json::to_string(&ir4).unwrap();
    let restored: Ir4Module = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.active_specialization_ids.len(), 2);
    assert_eq!(restored.active_specialization_ids[0], "spec-001");
    assert_eq!(restored.active_specialization_ids[1], "spec-002");
}

// ---------------------------------------------------------------------------
// IR level ordering contract
// ---------------------------------------------------------------------------

#[test]
fn ir_level_ordering_is_pipeline_order() {
    let levels = [
        IrLevel::Ir0,
        IrLevel::Ir1,
        IrLevel::Ir2,
        IrLevel::Ir3,
        IrLevel::Ir4,
    ];
    for i in 0..levels.len() - 1 {
        assert!(levels[i] < levels[i + 1]);
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment batch 8: enum serde, Display, error variants,
// canonical value stability, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn ir_level_serde_round_trip() {
    for level in [
        IrLevel::Ir0,
        IrLevel::Ir1,
        IrLevel::Ir2,
        IrLevel::Ir3,
        IrLevel::Ir4,
    ] {
        let json = serde_json::to_string(&level).expect("serialize");
        let recovered: IrLevel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(level, recovered);
    }
}

#[test]
fn ir_level_as_str_all_unique() {
    let strs: std::collections::BTreeSet<&str> = [
        IrLevel::Ir0,
        IrLevel::Ir1,
        IrLevel::Ir2,
        IrLevel::Ir3,
        IrLevel::Ir4,
    ]
    .iter()
    .map(|l| l.as_str())
    .collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn ir_error_code_serde_round_trip() {
    let codes = [
        IrErrorCode::SchemaVersionMismatch,
        IrErrorCode::LevelMismatch,
        IrErrorCode::SourceHashMismatch,
        IrErrorCode::HashVerificationFailed,
        IrErrorCode::MissingCapabilityAnnotation,
        IrErrorCode::InvalidSpecializationLinkage,
        IrErrorCode::WitnessIntegrityViolation,
    ];
    for code in codes {
        let json = serde_json::to_string(&code).expect("serialize");
        let recovered: IrErrorCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(code, recovered);
    }
}

#[test]
fn ir_error_code_as_str_all_unique() {
    let codes = [
        IrErrorCode::SchemaVersionMismatch,
        IrErrorCode::LevelMismatch,
        IrErrorCode::SourceHashMismatch,
        IrErrorCode::HashVerificationFailed,
        IrErrorCode::MissingCapabilityAnnotation,
        IrErrorCode::InvalidSpecializationLinkage,
        IrErrorCode::WitnessIntegrityViolation,
    ];
    let strs: std::collections::BTreeSet<&str> = codes.iter().map(|c| c.as_str()).collect();
    assert_eq!(strs.len(), codes.len());
}

#[test]
fn ir_error_display_is_non_empty() {
    let err = IrError::new(IrErrorCode::SourceHashMismatch, "test detail", IrLevel::Ir1);
    let msg = err.to_string();
    assert!(!msg.is_empty());
    assert!(msg.contains("test detail") || msg.contains("SOURCE_HASH_MISMATCH"));
}

#[test]
fn ir_error_serde_round_trip() {
    let err = IrError::new(IrErrorCode::LevelMismatch, "wrong level", IrLevel::Ir2);
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: IrError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err.code, recovered.code);
    assert_eq!(err.level, recovered.level);
}

#[test]
fn witness_event_kind_serde_round_trip() {
    let kinds = [
        WitnessEventKind::CapabilityChecked,
        WitnessEventKind::HostcallDispatched,
        WitnessEventKind::ExecutionCompleted,
    ];
    for kind in kinds {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: WitnessEventKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, recovered);
    }
}

#[test]
fn execution_outcome_serde_round_trip() {
    let outcomes = [
        ExecutionOutcome::Completed,
        ExecutionOutcome::Exception,
        ExecutionOutcome::Timeout,
        ExecutionOutcome::Halted,
    ];
    for outcome in outcomes {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let recovered: ExecutionOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, recovered);
    }
}

#[test]
fn execution_outcome_as_str_all_unique() {
    let outcomes = [
        ExecutionOutcome::Completed,
        ExecutionOutcome::Exception,
        ExecutionOutcome::Timeout,
        ExecutionOutcome::Halted,
    ];
    let strs: std::collections::BTreeSet<&str> = outcomes.iter().map(|o| o.as_str()).collect();
    assert_eq!(strs.len(), outcomes.len());
}

#[test]
fn effect_boundary_serde_round_trip() {
    let effects = [
        EffectBoundary::Pure,
        EffectBoundary::HostcallEffect,
        EffectBoundary::NetworkEffect,
    ];
    for effect in effects {
        let json = serde_json::to_string(&effect).expect("serialize");
        let recovered: EffectBoundary = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(effect, recovered);
    }
}

#[test]
fn binding_kind_serde_round_trip() {
    let kinds = [
        BindingKind::Var,
        BindingKind::Let,
        BindingKind::Const,
        BindingKind::FunctionDecl,
        BindingKind::Parameter,
        BindingKind::Import,
    ];
    for kind in kinds {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: BindingKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, recovered);
    }
}

#[test]
fn scope_kind_serde_round_trip() {
    let kinds = [ScopeKind::Global, ScopeKind::Function, ScopeKind::Block];
    for kind in kinds {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: ScopeKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, recovered);
    }
}

#[test]
fn ir_schema_version_current_is_stable() {
    let v = IrSchemaVersion::CURRENT;
    assert_eq!(v.major, 0);
    assert_eq!(v.minor, 1);
}

#[test]
fn ir0_empty_body_has_valid_hash() {
    let empty_tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![],
        span: make_span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(empty_tree, "empty.js");
    let hash = ir0.content_hash();
    assert!(!hash.as_bytes().is_empty());
}

#[test]
fn ir3_instruction_serde_round_trip_all_variants() {
    let instructions = [
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 0,
        },
        Ir3Instruction::Add {
            dst: 2,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("test".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 3,
        },
        Ir3Instruction::Return { value: 0 },
    ];
    for instr in &instructions {
        let json = serde_json::to_string(instr).expect("serialize");
        let recovered: Ir3Instruction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*instr, recovered);
    }
}
