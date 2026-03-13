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
    Ir3Instruction, Ir3Module, Ir4Module, IrContractEvent, IrError, IrErrorCode, IrHeader, IrLevel,
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

    let ir1 = make_ir1(ir0_hash);
    verify_ir1_source(&ir1, &ir0_hash).unwrap();
    let ir1_hash = ir1.content_hash();

    let ir2 = make_ir2(ir1_hash);
    let ir2_hash = ir2.content_hash();

    let ir3 = make_ir3(ir2_hash);
    verify_ir3_specialization(&ir3).unwrap();
    let ir3_hash = ir3.content_hash();

    let ir4 = make_ir4(ir3_hash);
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
    let ir1 = make_ir1(ir0_hash);
    let ir3 = make_ir3(ContentHash::compute(b"ir2"));
    let ir3_hash = ir3.content_hash();
    let ir4 = make_ir4(ir3_hash);

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
    let ir1 = make_ir1(ir0_hash);
    let ir1_hash = ir1.content_hash();
    let ir2 = make_ir2(ir1_hash);
    let ir2_hash = ir2.content_hash();
    let ir3 = make_ir3(ir2_hash);
    let ir3_hash = ir3.content_hash();
    let ir4 = make_ir4(ir3_hash);

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
        let ir1 = make_ir1(ir0_hash);
        let ir1_hash = ir1.content_hash();
        let ir2 = make_ir2(ir1_hash);
        let ir2_hash = ir2.content_hash();
        let ir3 = make_ir3(ir2_hash);
        let ir3_hash = ir3.content_hash();
        let ir4 = make_ir4(ir3_hash);
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
        let ir1 = make_ir1(ir0_hash);
        let ir3 = make_ir3(ContentHash::compute(b"ir2"));
        let ir3_hash = ir3.content_hash();
        let ir4 = make_ir4(ir3_hash);

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
    let mut ir4 = Ir4Module::new(ir3_hash, "bad.js");
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

// ────────────────────────────────────────────────────────────
// Enrichment batch: IR instruction encoding/decoding,
// opcode validation, contract invariants, serde round-trips,
// edge cases in instruction operands
// ────────────────────────────────────────────────────────────

use frankenengine_engine::ir_contract::{
    HostcallDecisionRecord as HdrAlias, Ir1Literal, Ir1PropertyKey, Ir3FunctionDesc as FnDesc,
    IteratorCloseReason,
};

// --- IR3 instruction serde round-trips (all remaining variants) ---

#[test]
fn enrichment_ir3_sub_serde_roundtrip() {
    let instr = Ir3Instruction::Sub {
        dst: 5,
        lhs: 2,
        rhs: 3,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_mul_serde_roundtrip() {
    let instr = Ir3Instruction::Mul {
        dst: 6,
        lhs: 0,
        rhs: 1,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_div_serde_roundtrip() {
    let instr = Ir3Instruction::Div {
        dst: 7,
        lhs: 4,
        rhs: 5,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_mod_serde_roundtrip() {
    let instr = Ir3Instruction::Mod {
        dst: 8,
        lhs: 3,
        rhs: 2,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_exp_serde_roundtrip() {
    let instr = Ir3Instruction::Exp {
        dst: 9,
        lhs: 1,
        rhs: 2,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_unary_neg_serde_roundtrip() {
    let instr = Ir3Instruction::UnaryNeg { dst: 10, src: 5 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_unary_plus_serde_roundtrip() {
    let instr = Ir3Instruction::UnaryPlus { dst: 11, src: 6 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_logical_not_serde_roundtrip() {
    let instr = Ir3Instruction::LogicalNot { dst: 12, src: 7 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_bit_not_serde_roundtrip() {
    let instr = Ir3Instruction::BitNot { dst: 13, src: 8 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_typeof_serde_roundtrip() {
    let instr = Ir3Instruction::TypeOf { dst: 14, src: 9 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_void_serde_roundtrip() {
    let instr = Ir3Instruction::Void { dst: 15, src: 10 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_comparison_ops_serde_roundtrip() {
    let ops = [
        Ir3Instruction::Lt {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Lte {
            dst: 3,
            lhs: 4,
            rhs: 5,
        },
        Ir3Instruction::Gt {
            dst: 6,
            lhs: 7,
            rhs: 8,
        },
        Ir3Instruction::Gte {
            dst: 9,
            lhs: 10,
            rhs: 11,
        },
    ];
    for op in &ops {
        let json = serde_json::to_string(op).unwrap();
        let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
        assert_eq!(*op, recovered);
    }
}

#[test]
fn enrichment_ir3_equality_ops_serde_roundtrip() {
    let ops = [
        Ir3Instruction::Eq {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::StrictEq {
            dst: 3,
            lhs: 4,
            rhs: 5,
        },
        Ir3Instruction::NotEq {
            dst: 6,
            lhs: 7,
            rhs: 8,
        },
        Ir3Instruction::StrictNotEq {
            dst: 9,
            lhs: 10,
            rhs: 11,
        },
    ];
    for op in &ops {
        let json = serde_json::to_string(op).unwrap();
        let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
        assert_eq!(*op, recovered);
    }
}

#[test]
fn enrichment_ir3_bitwise_ops_serde_roundtrip() {
    let ops = [
        Ir3Instruction::BitAnd {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::BitOr {
            dst: 3,
            lhs: 4,
            rhs: 5,
        },
        Ir3Instruction::BitXor {
            dst: 6,
            lhs: 7,
            rhs: 8,
        },
    ];
    for op in &ops {
        let json = serde_json::to_string(op).unwrap();
        let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
        assert_eq!(*op, recovered);
    }
}

#[test]
fn enrichment_ir3_shift_ops_serde_roundtrip() {
    let ops = [
        Ir3Instruction::Shl {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Shr {
            dst: 3,
            lhs: 4,
            rhs: 5,
        },
        Ir3Instruction::Ushr {
            dst: 6,
            lhs: 7,
            rhs: 8,
        },
    ];
    for op in &ops {
        let json = serde_json::to_string(op).unwrap();
        let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
        assert_eq!(*op, recovered);
    }
}

#[test]
fn enrichment_ir3_instanceof_serde_roundtrip() {
    let instr = Ir3Instruction::InstanceOf {
        dst: 0,
        lhs: 1,
        rhs: 2,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_in_op_serde_roundtrip() {
    let instr = Ir3Instruction::InOp {
        dst: 0,
        lhs: 1,
        rhs: 2,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_construct_serde_roundtrip() {
    let instr = Ir3Instruction::Construct {
        callee: 0,
        args: RegRange { start: 1, count: 3 },
        dst: 4,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_load_bool_serde_roundtrip() {
    for value in [true, false] {
        let instr = Ir3Instruction::LoadBool { dst: 0, value };
        let json = serde_json::to_string(&instr).unwrap();
        let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
        assert_eq!(instr, recovered);
    }
}

#[test]
fn enrichment_ir3_load_null_serde_roundtrip() {
    let instr = Ir3Instruction::LoadNull { dst: 0 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_load_undefined_serde_roundtrip() {
    let instr = Ir3Instruction::LoadUndefined { dst: 0 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_move_serde_roundtrip() {
    let instr = Ir3Instruction::Move { dst: 5, src: 3 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_jump_serde_roundtrip() {
    let instr = Ir3Instruction::Jump { target: 42 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_jump_if_serde_roundtrip() {
    let instr = Ir3Instruction::JumpIf {
        cond: 0,
        target: 10,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_jump_if_nullish_serde_roundtrip() {
    let instr = Ir3Instruction::JumpIfNullish {
        cond: 1,
        target: 20,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_call_serde_roundtrip() {
    let instr = Ir3Instruction::Call {
        callee: 0,
        args: RegRange { start: 1, count: 2 },
        dst: 3,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_get_property_serde_roundtrip() {
    let instr = Ir3Instruction::GetProperty {
        obj: 0,
        key: 1,
        dst: 2,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_set_property_serde_roundtrip() {
    let instr = Ir3Instruction::SetProperty {
        obj: 0,
        key: 1,
        val: 2,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_delete_property_serde_roundtrip() {
    let instr = Ir3Instruction::DeleteProperty {
        obj: 0,
        key: 1,
        dst: 2,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_new_object_serde_roundtrip() {
    let instr = Ir3Instruction::NewObject { dst: 0 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_new_array_serde_roundtrip() {
    let instr = Ir3Instruction::NewArray { dst: 0 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_template_literal_serde_roundtrip() {
    let instr = Ir3Instruction::TemplateLiteral {
        parts: RegRange { start: 0, count: 5 },
        dst: 6,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_halt_serde_roundtrip() {
    let instr = Ir3Instruction::Halt;
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_for_in_init_serde_roundtrip() {
    let instr = Ir3Instruction::ForInInit { src: 0, dst: 1 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_for_in_next_serde_roundtrip() {
    let instr = Ir3Instruction::ForInNext {
        iterator: 0,
        value_dst: 1,
        done_target: 10,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_for_of_init_serde_roundtrip() {
    let instr = Ir3Instruction::ForOfInit { src: 2, dst: 3 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_for_of_next_serde_roundtrip() {
    let instr = Ir3Instruction::ForOfNext {
        iterator: 3,
        value_dst: 4,
        done_target: 20,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_iterator_close_all_reasons_serde_roundtrip() {
    for reason in [
        IteratorCloseReason::Break,
        IteratorCloseReason::Return,
        IteratorCloseReason::Throw,
    ] {
        let instr = Ir3Instruction::IteratorClose {
            iterator: 5,
            reason,
        };
        let json = serde_json::to_string(&instr).unwrap();
        let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
        assert_eq!(instr, recovered);
    }
}

// --- IR1 op serde round-trips ---

#[test]
fn enrichment_ir1_all_ops_serde_roundtrip() {
    let ops = vec![
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(99),
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("hello".to_string()),
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Boolean(true),
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Null,
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::LoadBinding { binding_id: 0 },
        Ir1Op::StoreBinding { binding_id: 1 },
        Ir1Op::Call { arg_count: 3 },
        Ir1Op::Return,
        Ir1Op::ImportModule {
            specifier: "mod".to_string(),
        },
        Ir1Op::ExportBinding {
            name: "x".to_string(),
            binding_id: 2,
        },
        Ir1Op::Await,
        Ir1Op::Nop,
        Ir1Op::Label { id: 0 },
        Ir1Op::Jump { label_id: 1 },
        Ir1Op::JumpIfFalsy { label_id: 2 },
        Ir1Op::JumpIfFalsyConsume { label_id: 3 },
        Ir1Op::JumpIfTruthy { label_id: 4 },
        Ir1Op::JumpIfNullish { label_id: 5 },
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Static("prop".to_string()),
        },
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Dynamic,
        },
        Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static("val".to_string()),
        },
        Ir1Op::DeleteProperty {
            key: Ir1PropertyKey::Dynamic,
        },
        Ir1Op::NewArray { count: 5 },
        Ir1Op::NewObject { count: 3 },
        Ir1Op::Throw,
        Ir1Op::LoadThis,
        Ir1Op::DeclareFunction {
            name: "f".to_string(),
            binding_id: 10,
        },
        Ir1Op::BeginTry { catch_label: 100 },
        Ir1Op::EndTry,
        Ir1Op::Pop,
        Ir1Op::ForInInit,
        Ir1Op::ForInNext { done_label: 50 },
        Ir1Op::ForOfInit,
        Ir1Op::ForOfNext { done_label: 60 },
        Ir1Op::IteratorClose {
            reason: IteratorCloseReason::Break,
        },
        Ir1Op::Construct { arg_count: 2 },
        Ir1Op::TemplateLiteral { quasi_count: 3 },
    ];
    for op in &ops {
        let json = serde_json::to_string(op).unwrap();
        let recovered: Ir1Op = serde_json::from_str(&json).unwrap();
        assert_eq!(*op, recovered);
    }
}

// --- Edge cases in instruction operands ---

#[test]
fn enrichment_ir3_load_int_max_value() {
    let instr = Ir3Instruction::LoadInt {
        dst: 0,
        value: i64::MAX,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_load_int_min_value() {
    let instr = Ir3Instruction::LoadInt {
        dst: 0,
        value: i64::MIN,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_load_int_zero() {
    let instr = Ir3Instruction::LoadInt { dst: 0, value: 0 };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_ir3_load_int_negative() {
    let instr = Ir3Instruction::LoadInt {
        dst: 0,
        value: -1_000_000,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

#[test]
fn enrichment_reg_range_zero_count() {
    let rr = RegRange { start: 0, count: 0 };
    let json = serde_json::to_string(&rr).unwrap();
    let recovered: RegRange = serde_json::from_str(&json).unwrap();
    assert_eq!(rr, recovered);
}

#[test]
fn enrichment_reg_range_max_start() {
    let rr = RegRange {
        start: u32::MAX,
        count: 1,
    };
    let json = serde_json::to_string(&rr).unwrap();
    let recovered: RegRange = serde_json::from_str(&json).unwrap();
    assert_eq!(rr, recovered);
}

#[test]
fn enrichment_ir3_load_str_max_pool_index() {
    let instr = Ir3Instruction::LoadStr {
        dst: 0,
        pool_index: u32::MAX,
    };
    let json = serde_json::to_string(&instr).unwrap();
    let recovered: Ir3Instruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr, recovered);
}

// --- Canonical bytes determinism ---

#[test]
fn enrichment_ir3_canonical_bytes_deterministic_across_runs() {
    let h = ContentHash::compute(b"ir2");
    let a = make_ir3(h).canonical_bytes();
    let b = make_ir3(h).canonical_bytes();
    assert_eq!(a, b);
}

#[test]
fn enrichment_ir1_canonical_bytes_deterministic() {
    let h = ContentHash::compute(b"ir0");
    let a = make_ir1(h).canonical_bytes();
    let b = make_ir1(h).canonical_bytes();
    assert_eq!(a, b);
}

#[test]
fn enrichment_ir2_canonical_bytes_deterministic() {
    let h = ContentHash::compute(b"ir1");
    let a = make_ir2(h).canonical_bytes();
    let b = make_ir2(h).canonical_bytes();
    assert_eq!(a, b);
}

// --- Content hash sensitivity ---

#[test]
fn enrichment_ir3_hash_changes_with_instruction_order() {
    let h = ContentHash::compute(b"ir2");
    let mut m1 = Ir3Module::new(h, "test.js");
    m1.instructions
        .push(Ir3Instruction::LoadInt { dst: 0, value: 1 });
    m1.instructions
        .push(Ir3Instruction::LoadInt { dst: 1, value: 2 });

    let mut m2 = Ir3Module::new(h, "test.js");
    m2.instructions
        .push(Ir3Instruction::LoadInt { dst: 1, value: 2 });
    m2.instructions
        .push(Ir3Instruction::LoadInt { dst: 0, value: 1 });

    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_ir3_hash_changes_with_constant_pool() {
    let h = ContentHash::compute(b"ir2");
    let mut m1 = Ir3Module::new(h, "test.js");
    m1.constant_pool.push("alpha".to_string());

    let mut m2 = Ir3Module::new(h, "test.js");
    m2.constant_pool.push("beta".to_string());

    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_ir3_hash_changes_with_function_table() {
    let h = ContentHash::compute(b"ir2");
    let mut m1 = Ir3Module::new(h, "test.js");
    m1.function_table.push(FnDesc {
        entry: 0,
        arity: 1,
        frame_size: 4,
        name: Some("fn1".to_string()),
    });

    let mut m2 = Ir3Module::new(h, "test.js");
    m2.function_table.push(FnDesc {
        entry: 0,
        arity: 2,
        frame_size: 4,
        name: Some("fn1".to_string()),
    });

    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_ir3_hash_changes_with_capabilities() {
    let h = ContentHash::compute(b"ir2");
    let mut m1 = Ir3Module::new(h, "test.js");
    m1.required_capabilities
        .push(CapabilityTag("fs:read".to_string()));

    let mut m2 = Ir3Module::new(h, "test.js");
    m2.required_capabilities
        .push(CapabilityTag("net:connect".to_string()));

    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_ir1_hash_changes_with_scope_bindings() {
    let h = ContentHash::compute(b"ir0");
    let m1 = make_ir1(h);
    let mut m2 = make_ir1(h);
    m2.scopes[0].bindings[0].name = "y".to_string();
    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_ir4_hash_changes_with_outcome() {
    let h = ContentHash::compute(b"ir3");
    let mut m1 = Ir4Module::new(h, "test.js");
    m1.outcome = ExecutionOutcome::Completed;

    let mut m2 = Ir4Module::new(h, "test.js");
    m2.outcome = ExecutionOutcome::Exception;

    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_ir4_hash_changes_with_duration_ticks() {
    let h = ContentHash::compute(b"ir3");
    let mut m1 = Ir4Module::new(h, "test.js");
    m1.duration_ticks = 100;

    let mut m2 = Ir4Module::new(h, "test.js");
    m2.duration_ticks = 200;

    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_ir4_hash_changes_with_instructions_executed() {
    let h = ContentHash::compute(b"ir3");
    let mut m1 = Ir4Module::new(h, "test.js");
    m1.instructions_executed = 50;

    let mut m2 = Ir4Module::new(h, "test.js");
    m2.instructions_executed = 51;

    assert_ne!(m1.content_hash(), m2.content_hash());
}

// --- Verification edge cases ---

#[test]
fn enrichment_verify_ir4_empty_events_passes() {
    let h = ContentHash::compute(b"ir3");
    let ir4 = Ir4Module::new(h, "test.js");
    assert!(verify_ir4_linkage(&ir4, &h).is_ok());
}

#[test]
fn enrichment_verify_ir4_single_event_passes() {
    let h = ContentHash::compute(b"ir3");
    let mut ir4 = Ir4Module::new(h, "test.js");
    ir4.events.push(WitnessEvent {
        seq: 0,
        kind: WitnessEventKind::ExecutionCompleted,
        instruction_index: 0,
        payload_hash: ContentHash::compute(b"done"),
        timestamp_tick: 1,
    });
    assert!(verify_ir4_linkage(&ir4, &h).is_ok());
}

#[test]
fn enrichment_verify_ir4_duplicate_seq_rejected() {
    let h = ContentHash::compute(b"ir3");
    let mut ir4 = Ir4Module::new(h, "test.js");
    ir4.events.push(WitnessEvent {
        seq: 1,
        kind: WitnessEventKind::CapabilityChecked,
        instruction_index: 0,
        payload_hash: ContentHash::compute(b"a"),
        timestamp_tick: 10,
    });
    ir4.events.push(WitnessEvent {
        seq: 1, // duplicate
        kind: WitnessEventKind::HostcallDispatched,
        instruction_index: 1,
        payload_hash: ContentHash::compute(b"b"),
        timestamp_tick: 20,
    });
    let err = verify_ir4_linkage(&ir4, &h).unwrap_err();
    assert_eq!(err.code, IrErrorCode::WitnessIntegrityViolation);
}

#[test]
fn enrichment_verify_ir4_three_events_monotonic_passes() {
    let h = ContentHash::compute(b"ir3");
    let mut ir4 = Ir4Module::new(h, "test.js");
    for seq in 0..3 {
        ir4.events.push(WitnessEvent {
            seq,
            kind: WitnessEventKind::CapabilityChecked,
            instruction_index: seq as u32,
            payload_hash: ContentHash::compute(format!("evt{seq}").as_bytes()),
            timestamp_tick: seq * 10,
        });
    }
    assert!(verify_ir4_linkage(&ir4, &h).is_ok());
}

#[test]
fn enrichment_verify_ir3_no_specialization_passes() {
    let h = ContentHash::compute(b"ir2");
    let ir3 = Ir3Module::new(h, "test.js");
    assert!(verify_ir3_specialization(&ir3).is_ok());
}

#[test]
fn enrichment_verify_ir3_empty_optimization_class_rejected() {
    let h = ContentHash::compute(b"ir2");
    let mut ir3 = Ir3Module::new(h, "test.js");
    ir3.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec!["p1".to_string()],
        optimization_class: String::new(),
        validity_epoch: 1,
        rollback_token: ContentHash::compute(b"rollback"),
    });
    let err = verify_ir3_specialization(&ir3).unwrap_err();
    assert_eq!(err.code, IrErrorCode::InvalidSpecializationLinkage);
}

#[test]
fn enrichment_verify_ir1_source_none_hash_rejected() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"x"), "test.js");
    ir1.header.source_hash = None;
    let err = verify_ir1_source(&ir1, &ContentHash::compute(b"x")).unwrap_err();
    assert_eq!(err.code, IrErrorCode::SourceHashMismatch);
}

// --- IrError construction and properties ---

#[test]
fn enrichment_ir_error_preserves_level() {
    for level in [
        IrLevel::Ir0,
        IrLevel::Ir1,
        IrLevel::Ir2,
        IrLevel::Ir3,
        IrLevel::Ir4,
    ] {
        let err = IrError::new(IrErrorCode::LevelMismatch, "test", level);
        assert_eq!(err.level, level);
    }
}

#[test]
fn enrichment_ir_error_preserves_message() {
    let err = IrError::new(
        IrErrorCode::SchemaVersionMismatch,
        "custom detail here",
        IrLevel::Ir0,
    );
    assert_eq!(err.message, "custom detail here");
}

#[test]
fn enrichment_ir_error_display_contains_level_and_code() {
    let err = IrError::new(
        IrErrorCode::HashVerificationFailed,
        "bad hash",
        IrLevel::Ir3,
    );
    let display = err.to_string();
    assert!(display.contains("ir3"));
    assert!(display.contains("IR_HASH_VERIFICATION_FAILED"));
    assert!(display.contains("bad hash"));
}

// --- IrVerifier event tracking ---

#[test]
fn enrichment_verifier_drain_empties_events() {
    let ir0 = make_ir0();
    let h = ir0.content_hash();
    let mut verifier = IrVerifier::new();
    verifier.verify_ir0(&ir0, &h, "t").unwrap();
    let first = verifier.drain_events();
    assert_eq!(first.len(), 1);
    let second = verifier.drain_events();
    assert!(second.is_empty());
}

#[test]
fn enrichment_verifier_default_identical_to_new() {
    let mut v1 = IrVerifier::new();
    let mut v2 = IrVerifier::default();
    assert!(v1.drain_events().is_empty());
    assert!(v2.drain_events().is_empty());
}

#[test]
fn enrichment_verifier_error_event_has_no_content_hash() {
    let ir0 = make_ir0();
    let wrong = ContentHash::compute(b"wrong");
    let mut verifier = IrVerifier::new();
    let _ = verifier.verify_ir0(&ir0, &wrong, "t");
    let events = verifier.drain_events();
    assert_eq!(events.len(), 1);
    assert!(events[0].content_hash.is_none());
    assert!(events[0].error_code.is_some());
}

#[test]
fn enrichment_verifier_success_event_has_content_hash() {
    let ir0 = make_ir0();
    let h = ir0.content_hash();
    let mut verifier = IrVerifier::new();
    verifier.verify_ir0(&ir0, &h, "t").unwrap();
    let events = verifier.drain_events();
    assert_eq!(events.len(), 1);
    assert!(events[0].content_hash.is_some());
    assert!(events[0].error_code.is_none());
}

// --- IrContractEvent serde ---

#[test]
fn enrichment_ir_contract_event_serde_roundtrip_error() {
    let ir0 = make_ir0();
    let wrong = ContentHash::compute(b"wrong");
    let mut verifier = IrVerifier::new();
    let _ = verifier.verify_ir0(&ir0, &wrong, "err-trace");
    let events = verifier.drain_events();
    let json = serde_json::to_string(&events).unwrap();
    let recovered: Vec<IrContractEvent> = serde_json::from_str(&json).unwrap();
    assert_eq!(events, recovered);
}

// --- Ir1Literal serde ---

#[test]
fn enrichment_ir1_literal_all_variants_serde() {
    let literals = [
        Ir1Literal::String("test".to_string()),
        Ir1Literal::Integer(42),
        Ir1Literal::Integer(-1),
        Ir1Literal::Integer(0),
        Ir1Literal::Boolean(true),
        Ir1Literal::Boolean(false),
        Ir1Literal::Null,
        Ir1Literal::Undefined,
    ];
    for lit in &literals {
        let json = serde_json::to_string(lit).unwrap();
        let recovered: Ir1Literal = serde_json::from_str(&json).unwrap();
        assert_eq!(*lit, recovered);
    }
}

// --- Ir1PropertyKey serde ---

#[test]
fn enrichment_ir1_property_key_static_serde() {
    let key = Ir1PropertyKey::Static("myProp".to_string());
    let json = serde_json::to_string(&key).unwrap();
    let recovered: Ir1PropertyKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, recovered);
}

#[test]
fn enrichment_ir1_property_key_dynamic_serde() {
    let key = Ir1PropertyKey::Dynamic;
    let json = serde_json::to_string(&key).unwrap();
    let recovered: Ir1PropertyKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, recovered);
}

// --- IteratorCloseReason ---

#[test]
fn enrichment_iterator_close_reason_as_str_stable() {
    assert_eq!(IteratorCloseReason::Break.as_str(), "break");
    assert_eq!(IteratorCloseReason::Return.as_str(), "return");
    assert_eq!(IteratorCloseReason::Throw.as_str(), "throw");
}

#[test]
fn enrichment_iterator_close_reason_all_unique() {
    let strs: std::collections::BTreeSet<&str> = [
        IteratorCloseReason::Break,
        IteratorCloseReason::Return,
        IteratorCloseReason::Throw,
    ]
    .iter()
    .map(|r| r.as_str())
    .collect();
    assert_eq!(strs.len(), 3);
}

// --- ScopeKind additional coverage ---

#[test]
fn enrichment_scope_kind_module_and_catch_serde() {
    let kinds = [ScopeKind::Module, ScopeKind::Catch];
    for kind in kinds {
        let json = serde_json::to_string(&kind).unwrap();
        let recovered: ScopeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, recovered);
    }
}

#[test]
fn enrichment_scope_kind_as_str_all_variants() {
    assert_eq!(ScopeKind::Global.as_str(), "global");
    assert_eq!(ScopeKind::Module.as_str(), "module");
    assert_eq!(ScopeKind::Function.as_str(), "function");
    assert_eq!(ScopeKind::Block.as_str(), "block");
    assert_eq!(ScopeKind::Catch.as_str(), "catch");
}

// --- EffectBoundary additional variants ---

#[test]
fn enrichment_effect_boundary_all_variants_serde() {
    let effects = [
        EffectBoundary::Pure,
        EffectBoundary::ReadEffect,
        EffectBoundary::WriteEffect,
        EffectBoundary::NetworkEffect,
        EffectBoundary::FsEffect,
        EffectBoundary::HostcallEffect,
    ];
    for effect in effects {
        let json = serde_json::to_string(&effect).unwrap();
        let recovered: EffectBoundary = serde_json::from_str(&json).unwrap();
        assert_eq!(effect, recovered);
    }
}

#[test]
fn enrichment_effect_boundary_as_str_all_unique() {
    let effects = [
        EffectBoundary::Pure,
        EffectBoundary::ReadEffect,
        EffectBoundary::WriteEffect,
        EffectBoundary::NetworkEffect,
        EffectBoundary::FsEffect,
        EffectBoundary::HostcallEffect,
    ];
    let strs: std::collections::BTreeSet<&str> = effects.iter().map(|e| e.as_str()).collect();
    assert_eq!(strs.len(), effects.len());
}

// --- WitnessEventKind additional variants ---

#[test]
fn enrichment_witness_event_kind_all_variants_serde() {
    let kinds = [
        WitnessEventKind::HostcallDispatched,
        WitnessEventKind::CapabilityChecked,
        WitnessEventKind::ExceptionRaised,
        WitnessEventKind::GcTriggered,
        WitnessEventKind::ExecutionCompleted,
        WitnessEventKind::FlowLabelChecked,
        WitnessEventKind::DeclassificationRequested,
    ];
    for kind in kinds {
        let json = serde_json::to_string(&kind).unwrap();
        let recovered: WitnessEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, recovered);
    }
}

#[test]
fn enrichment_witness_event_kind_as_str_all_unique() {
    let kinds = [
        WitnessEventKind::HostcallDispatched,
        WitnessEventKind::CapabilityChecked,
        WitnessEventKind::ExceptionRaised,
        WitnessEventKind::GcTriggered,
        WitnessEventKind::ExecutionCompleted,
        WitnessEventKind::FlowLabelChecked,
        WitnessEventKind::DeclassificationRequested,
    ];
    let strs: std::collections::BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), kinds.len());
}

// --- HostcallDecisionRecord serde ---

#[test]
fn enrichment_hostcall_decision_record_serde_roundtrip() {
    let rec = HdrAlias {
        seq: 42,
        capability: CapabilityTag("fs:write".to_string()),
        allowed: false,
        instruction_index: 7,
    };
    let json = serde_json::to_string(&rec).unwrap();
    let recovered: HdrAlias = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, recovered);
}

#[test]
fn enrichment_hostcall_decision_record_allowed_vs_denied() {
    let allowed = HdrAlias {
        seq: 0,
        capability: CapabilityTag("net:connect".to_string()),
        allowed: true,
        instruction_index: 0,
    };
    let denied = HdrAlias {
        seq: 0,
        capability: CapabilityTag("net:connect".to_string()),
        allowed: false,
        instruction_index: 0,
    };
    assert_ne!(allowed, denied);
}

// --- Ir3FunctionDesc serde ---

#[test]
fn enrichment_ir3_function_desc_serde_roundtrip() {
    let desc = FnDesc {
        entry: 10,
        arity: 3,
        frame_size: 8,
        name: Some("myFunc".to_string()),
    };
    let json = serde_json::to_string(&desc).unwrap();
    let recovered: FnDesc = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, recovered);
}

#[test]
fn enrichment_ir3_function_desc_anonymous_serde() {
    let desc = FnDesc {
        entry: 0,
        arity: 0,
        frame_size: 2,
        name: None,
    };
    let json = serde_json::to_string(&desc).unwrap();
    let recovered: FnDesc = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, recovered);
}

// --- SpecializationLinkage serde ---

#[test]
fn enrichment_specialization_linkage_serde_roundtrip() {
    let sl = SpecializationLinkage {
        proof_input_ids: vec!["p1".to_string(), "p2".to_string(), "p3".to_string()],
        optimization_class: "inline_dispatch".to_string(),
        validity_epoch: 9999,
        rollback_token: ContentHash::compute(b"baseline"),
    };
    let json = serde_json::to_string(&sl).unwrap();
    let recovered: SpecializationLinkage = serde_json::from_str(&json).unwrap();
    assert_eq!(sl, recovered);
}

// --- WitnessEvent serde ---

#[test]
fn enrichment_witness_event_serde_roundtrip() {
    let evt = WitnessEvent {
        seq: 100,
        kind: WitnessEventKind::GcTriggered,
        instruction_index: 42,
        payload_hash: ContentHash::compute(b"gc-payload"),
        timestamp_tick: 5000,
    };
    let json = serde_json::to_string(&evt).unwrap();
    let recovered: WitnessEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, recovered);
}

// --- IrHeader serde ---

#[test]
fn enrichment_ir_header_serde_roundtrip_with_source_hash() {
    let header = IrHeader {
        schema_version: IrSchemaVersion::CURRENT,
        level: IrLevel::Ir2,
        source_hash: Some(ContentHash::compute(b"src")),
        source_label: "header_test.js".to_string(),
    };
    let json = serde_json::to_string(&header).unwrap();
    let recovered: IrHeader = serde_json::from_str(&json).unwrap();
    assert_eq!(header, recovered);
}

#[test]
fn enrichment_ir_header_serde_roundtrip_without_source_hash() {
    let header = IrHeader {
        schema_version: IrSchemaVersion::CURRENT,
        level: IrLevel::Ir0,
        source_hash: None,
        source_label: "no_source.js".to_string(),
    };
    let json = serde_json::to_string(&header).unwrap();
    let recovered: IrHeader = serde_json::from_str(&json).unwrap();
    assert_eq!(header, recovered);
}

// --- ScopeId serde ---

#[test]
fn enrichment_scope_id_serde_roundtrip() {
    let sid = ScopeId { depth: 3, index: 7 };
    let json = serde_json::to_string(&sid).unwrap();
    let recovered: ScopeId = serde_json::from_str(&json).unwrap();
    assert_eq!(sid, recovered);
}

#[test]
fn enrichment_scope_id_ordering() {
    let a = ScopeId { depth: 0, index: 0 };
    let b = ScopeId { depth: 0, index: 1 };
    let c = ScopeId { depth: 1, index: 0 };
    assert!(a < b);
    assert!(b < c);
}

// --- ResolvedBinding serde ---

#[test]
fn enrichment_resolved_binding_serde_roundtrip() {
    let rb = ResolvedBinding {
        name: "myVar".to_string(),
        binding_id: 42,
        scope: ScopeId { depth: 1, index: 2 },
        kind: BindingKind::Const,
    };
    let json = serde_json::to_string(&rb).unwrap();
    let recovered: ResolvedBinding = serde_json::from_str(&json).unwrap();
    assert_eq!(rb, recovered);
}

// --- ScopeNode serde ---

#[test]
fn enrichment_scope_node_serde_roundtrip() {
    let node = ScopeNode {
        scope_id: ScopeId { depth: 0, index: 0 },
        parent: None,
        kind: ScopeKind::Global,
        bindings: vec![
            ResolvedBinding {
                name: "a".to_string(),
                binding_id: 0,
                scope: ScopeId { depth: 0, index: 0 },
                kind: BindingKind::Let,
            },
            ResolvedBinding {
                name: "b".to_string(),
                binding_id: 1,
                scope: ScopeId { depth: 0, index: 0 },
                kind: BindingKind::Var,
            },
        ],
    };
    let json = serde_json::to_string(&node).unwrap();
    let recovered: ScopeNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, recovered);
}

#[test]
fn enrichment_scope_node_with_parent_serde_roundtrip() {
    let node = ScopeNode {
        scope_id: ScopeId { depth: 1, index: 0 },
        parent: Some(ScopeId { depth: 0, index: 0 }),
        kind: ScopeKind::Function,
        bindings: vec![],
    };
    let json = serde_json::to_string(&node).unwrap();
    let recovered: ScopeNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, recovered);
}

// --- FlowAnnotation serde ---

#[test]
fn enrichment_flow_annotation_serde_roundtrip() {
    let fa = FlowAnnotation {
        data_label: Label::Public,
        sink_clearance: Label::Internal,
        declassification_required: true,
    };
    let json = serde_json::to_string(&fa).unwrap();
    let recovered: FlowAnnotation = serde_json::from_str(&json).unwrap();
    assert_eq!(fa, recovered);
}

// --- CapabilityTag serde ---

#[test]
fn enrichment_capability_tag_serde_roundtrip() {
    let tag = CapabilityTag("custom:capability".to_string());
    let json = serde_json::to_string(&tag).unwrap();
    let recovered: CapabilityTag = serde_json::from_str(&json).unwrap();
    assert_eq!(tag, recovered);
}

#[test]
fn enrichment_capability_tag_empty_string() {
    let tag = CapabilityTag(String::new());
    let json = serde_json::to_string(&tag).unwrap();
    let recovered: CapabilityTag = serde_json::from_str(&json).unwrap();
    assert_eq!(tag, recovered);
}

// --- Ir2Op serde ---

#[test]
fn enrichment_ir2_op_pure_no_capability_serde() {
    let op = Ir2Op {
        inner: Ir1Op::LoadBinding { binding_id: 0 },
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
    };
    let json = serde_json::to_string(&op).unwrap();
    let recovered: Ir2Op = serde_json::from_str(&json).unwrap();
    assert_eq!(op, recovered);
}

#[test]
fn enrichment_ir2_op_with_all_fields_serde() {
    let op = Ir2Op {
        inner: Ir1Op::Call { arg_count: 2 },
        effect: EffectBoundary::FsEffect,
        required_capability: Some(CapabilityTag("fs:write".to_string())),
        flow: Some(FlowAnnotation {
            data_label: Label::Internal,
            sink_clearance: Label::Public,
            declassification_required: false,
        }),
    };
    let json = serde_json::to_string(&op).unwrap();
    let recovered: Ir2Op = serde_json::from_str(&json).unwrap();
    assert_eq!(op, recovered);
}

// --- Full module serde with empty content ---

#[test]
fn enrichment_ir3_empty_module_serde_roundtrip() {
    let h = ContentHash::compute(b"ir2");
    let ir3 = Ir3Module::new(h, "empty.js");
    let json = serde_json::to_string(&ir3).unwrap();
    let recovered: Ir3Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir3, recovered);
}

#[test]
fn enrichment_ir4_empty_module_serde_roundtrip() {
    let h = ContentHash::compute(b"ir3");
    let ir4 = Ir4Module::new(h, "empty.js");
    let json = serde_json::to_string(&ir4).unwrap();
    let recovered: Ir4Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir4, recovered);
}

#[test]
fn enrichment_ir1_empty_module_serde_roundtrip() {
    let h = ContentHash::compute(b"ir0");
    let ir1 = Ir1Module::new(h, "empty.js");
    let json = serde_json::to_string(&ir1).unwrap();
    let recovered: Ir1Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir1, recovered);
}

#[test]
fn enrichment_ir2_empty_module_serde_roundtrip() {
    let h = ContentHash::compute(b"ir1");
    let ir2 = Ir2Module::new(h, "empty.js");
    let json = serde_json::to_string(&ir2).unwrap();
    let recovered: Ir2Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir2, recovered);
}

// --- IrSchemaVersion edge cases ---

#[test]
fn enrichment_schema_version_ordering() {
    let v010 = IrSchemaVersion {
        major: 0,
        minor: 1,
        patch: 0,
    };
    let v011 = IrSchemaVersion {
        major: 0,
        minor: 1,
        patch: 1,
    };
    let v100 = IrSchemaVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };
    assert!(v010 < v011);
    assert!(v011 < v100);
}

#[test]
fn enrichment_schema_version_display_custom() {
    let v = IrSchemaVersion {
        major: 2,
        minor: 3,
        patch: 4,
    };
    assert_eq!(v.to_string(), "2.3.4");
}

// --- BindingKind as_str stability ---

#[test]
fn enrichment_binding_kind_as_str_all_stable() {
    assert_eq!(BindingKind::Let.as_str(), "let");
    assert_eq!(BindingKind::Const.as_str(), "const");
    assert_eq!(BindingKind::Var.as_str(), "var");
    assert_eq!(BindingKind::Parameter.as_str(), "parameter");
    assert_eq!(BindingKind::Import.as_str(), "import");
    assert_eq!(BindingKind::FunctionDecl.as_str(), "function_decl");
}

// --- Cross-level hash chain invariant ---

#[test]
fn enrichment_hash_chain_source_hash_links_levels() {
    let ir0 = make_ir0();
    let ir0_hash = ir0.content_hash();
    let ir1 = make_ir1(ir0_hash);
    assert_eq!(ir1.header.source_hash, Some(ir0_hash));

    let ir1_hash = ir1.content_hash();
    let ir2 = make_ir2(ir1_hash);
    assert_eq!(ir2.header.source_hash, Some(ir1_hash));

    let ir2_hash = ir2.content_hash();
    let ir3 = make_ir3(ir2_hash);
    assert_eq!(ir3.header.source_hash, Some(ir2_hash));

    let ir3_hash = ir3.content_hash();
    let ir4 = make_ir4(ir3_hash);
    assert_eq!(ir4.header.source_hash, Some(ir3_hash));
    assert_eq!(ir4.executed_ir3_hash, ir3_hash);
}

// --- Module level header correctness ---

#[test]
fn enrichment_module_headers_have_correct_levels() {
    let ir0 = make_ir0();
    assert_eq!(ir0.header.level, IrLevel::Ir0);
    assert!(ir0.header.source_hash.is_none());

    let h = ContentHash::compute(b"x");
    let ir1 = Ir1Module::new(h, "t.js");
    assert_eq!(ir1.header.level, IrLevel::Ir1);
    assert!(ir1.header.source_hash.is_some());

    let ir2 = Ir2Module::new(h, "t.js");
    assert_eq!(ir2.header.level, IrLevel::Ir2);

    let ir3 = Ir3Module::new(h, "t.js");
    assert_eq!(ir3.header.level, IrLevel::Ir3);

    let ir4 = Ir4Module::new(h, "t.js");
    assert_eq!(ir4.header.level, IrLevel::Ir4);
}
