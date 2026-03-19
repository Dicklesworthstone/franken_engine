#![forbid(unsafe_code)]

//! Enrichment integration tests for the `ir_contract` module.
//!
//! Focuses on cross-level IR pipeline integrity: IR0->IR1->IR2->IR3->IR4 chain,
//! verification functions, hash linkage, specialization, witness monotonicity,
//! and structured event emission.

use std::collections::BTreeSet;

use frankenengine_engine::ast::{
    Expression, ExpressionStatement, ParseGoal, SourceSpan, Statement, SyntaxTree,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::*;

// =========================================================================
// Helpers
// =========================================================================

fn span() -> SourceSpan {
    SourceSpan::new(0, 10, 1, 1, 1, 11)
}

fn syntax_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(42),
            span: span(),
        })],
        span: span(),
    }
}

fn ir0() -> Ir0Module {
    Ir0Module::from_syntax_tree(syntax_tree(), "test.js")
}

fn ir1(source_hash: ContentHash) -> Ir1Module {
    let mut m = Ir1Module::new(source_hash, "test.js");
    m.scopes.push(ScopeNode {
        scope_id: ScopeId { depth: 0, index: 0 },
        parent: None,
        kind: ScopeKind::Global,
        bindings: vec![ResolvedBinding {
            name: "x".to_string(),
            binding_id: 0,
            scope: ScopeId { depth: 0, index: 0 },
            kind: BindingKind::Var,
        }],
    });
    m.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::Integer(42),
    });
    m.ops.push(Ir1Op::StoreBinding { binding_id: 0 });
    m
}

fn ir2(source_hash: ContentHash) -> Ir2Module {
    let mut m = Ir2Module::new(source_hash, "test.js");
    m.ops.push(Ir2Op {
        inner: Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(42),
        },
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
    });
    m
}

fn ir3(source_hash: ContentHash) -> Ir3Module {
    let mut m = Ir3Module::new(source_hash, "test.js");
    m.instructions
        .push(Ir3Instruction::LoadInt { dst: 0, value: 42 });
    m.instructions.push(Ir3Instruction::Halt);
    m.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 0,
        frame_size: 1,
        name: Some("main".to_string()),
    });
    m
}

fn ir4(ir3_hash: ContentHash) -> Ir4Module {
    let mut m = Ir4Module::new(ir3_hash, "test.js");
    m.events.push(WitnessEvent {
        seq: 0,
        kind: WitnessEventKind::ExecutionCompleted,
        instruction_index: 1,
        payload_hash: ContentHash::compute(b"done"),
        timestamp_tick: 100,
    });
    m.instructions_executed = 2;
    m.duration_ticks = 100;
    m
}

// =========================================================================
// Full IR pipeline: IR0 -> IR1 -> IR2 -> IR3 -> IR4
// =========================================================================

#[test]
fn enrichment_full_ir_pipeline_hash_chain() {
    let m0 = ir0();
    let h0 = m0.content_hash();

    let m1 = ir1(h0);
    assert_eq!(m1.header.source_hash.as_ref(), Some(&h0));
    let h1 = m1.content_hash();

    let m2 = ir2(h1);
    assert_eq!(m2.header.source_hash.as_ref(), Some(&h1));
    let h2 = m2.content_hash();

    let m3 = ir3(h2);
    assert_eq!(m3.header.source_hash.as_ref(), Some(&h2));
    let h3 = m3.content_hash();

    let m4 = ir4(h3);
    assert_eq!(m4.executed_ir3_hash, h3);
    assert_eq!(m4.header.source_hash.as_ref(), Some(&h3));
}

#[test]
fn enrichment_full_pipeline_verification_passes() {
    let m0 = ir0();
    let h0 = m0.content_hash();

    let m1 = ir1(h0);
    let h1 = m1.content_hash();

    let m3 = ir3(h1);
    let h3 = m3.content_hash();

    let m4 = ir4(h3);

    assert!(verify_ir0_hash(&m0, &h0).is_ok());
    assert!(verify_ir1_source(&m1, &h0).is_ok());
    assert!(verify_ir3_specialization(&m3).is_ok());
    assert!(verify_ir4_linkage(&m4, &h3).is_ok());
}

#[test]
fn enrichment_verifier_emits_events_on_success() {
    let m0 = ir0();
    let h0 = m0.content_hash();
    let m1 = ir1(h0);
    let m3 = ir3(m1.content_hash());
    let h3 = m3.content_hash();
    let m4 = ir4(h3);

    let mut v = IrVerifier::new();
    v.verify_ir0(&m0, &h0, "t1").unwrap();
    v.verify_ir1(&m1, &h0, "t1").unwrap();
    v.verify_ir3(&m3, "t1").unwrap();
    v.verify_ir4(&m4, &h3, "t1").unwrap();

    let events = v.drain_events();
    assert_eq!(events.len(), 4);
    for ev in &events {
        assert_eq!(ev.outcome, "ok");
        assert_eq!(ev.component, "ir_contract");
        assert!(ev.content_hash.is_some());
    }
}

#[test]
fn enrichment_verifier_emits_error_events_on_failure() {
    let m0 = ir0();
    let wrong_hash = ContentHash::compute(b"wrong");

    let mut v = IrVerifier::new();
    assert!(v.verify_ir0(&m0, &wrong_hash, "t2").is_err());

    let events = v.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(
        events[0].error_code.as_deref(),
        Some("IR_HASH_VERIFICATION_FAILED")
    );
}

// =========================================================================
// IrSchemaVersion
// =========================================================================

#[test]
fn enrichment_schema_version_current() {
    let v = IrSchemaVersion::CURRENT;
    assert_eq!(v.major, 0);
    assert_eq!(v.minor, 1);
    assert_eq!(v.patch, 0);
}

#[test]
fn enrichment_schema_version_display() {
    assert_eq!(IrSchemaVersion::CURRENT.to_string(), "0.1.0");
    let custom = IrSchemaVersion {
        major: 2,
        minor: 3,
        patch: 4,
    };
    assert_eq!(custom.to_string(), "2.3.4");
}

#[test]
fn enrichment_schema_version_serde_roundtrip() {
    let v = IrSchemaVersion {
        major: 1,
        minor: 2,
        patch: 3,
    };
    let json = serde_json::to_string(&v).unwrap();
    let restored: IrSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

#[test]
fn enrichment_schema_version_ordering() {
    let v1 = IrSchemaVersion {
        major: 0,
        minor: 1,
        patch: 0,
    };
    let v2 = IrSchemaVersion {
        major: 0,
        minor: 2,
        patch: 0,
    };
    let v3 = IrSchemaVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };
    assert!(v1 < v2);
    assert!(v2 < v3);
}

// =========================================================================
// IrLevel
// =========================================================================

#[test]
fn enrichment_ir_level_as_str_all() {
    let levels = [
        (IrLevel::Ir0, "ir0"),
        (IrLevel::Ir1, "ir1"),
        (IrLevel::Ir2, "ir2"),
        (IrLevel::Ir3, "ir3"),
        (IrLevel::Ir4, "ir4"),
    ];
    let mut seen = BTreeSet::new();
    for (level, expected) in &levels {
        assert_eq!(level.as_str(), *expected);
        assert_eq!(level.to_string(), *expected);
        assert!(seen.insert(level.as_str()));
    }
    assert_eq!(seen.len(), 5);
}

#[test]
fn enrichment_ir_level_serde_roundtrip() {
    for level in [
        IrLevel::Ir0,
        IrLevel::Ir1,
        IrLevel::Ir2,
        IrLevel::Ir3,
        IrLevel::Ir4,
    ] {
        let json = serde_json::to_string(&level).unwrap();
        let restored: IrLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, restored);
    }
}

#[test]
fn enrichment_ir_level_ordering() {
    assert!(IrLevel::Ir0 < IrLevel::Ir1);
    assert!(IrLevel::Ir1 < IrLevel::Ir2);
    assert!(IrLevel::Ir2 < IrLevel::Ir3);
    assert!(IrLevel::Ir3 < IrLevel::Ir4);
}

// =========================================================================
// IrHeader
// =========================================================================

#[test]
fn enrichment_ir_header_serde_roundtrip() {
    let header = IrHeader {
        schema_version: IrSchemaVersion::CURRENT,
        level: IrLevel::Ir1,
        source_hash: Some(ContentHash::compute(b"source")),
        source_label: "my_file.js".to_string(),
    };
    let json = serde_json::to_string(&header).unwrap();
    let restored: IrHeader = serde_json::from_str(&json).unwrap();
    assert_eq!(header, restored);
}

#[test]
fn enrichment_ir_header_without_source_hash() {
    let header = IrHeader {
        schema_version: IrSchemaVersion::CURRENT,
        level: IrLevel::Ir0,
        source_hash: None,
        source_label: "root.js".to_string(),
    };
    let json = serde_json::to_string(&header).unwrap();
    let restored: IrHeader = serde_json::from_str(&json).unwrap();
    assert_eq!(header, restored);
    assert!(header.source_hash.is_none());
}

// =========================================================================
// IR0
// =========================================================================

#[test]
fn enrichment_ir0_from_syntax_tree_sets_header() {
    let m = ir0();
    assert_eq!(m.header.level, IrLevel::Ir0);
    assert!(m.header.source_hash.is_none());
    assert_eq!(m.header.source_label, "test.js");
    assert_eq!(m.header.schema_version, IrSchemaVersion::CURRENT);
}

#[test]
fn enrichment_ir0_content_hash_deterministic() {
    let m1 = ir0();
    let m2 = ir0();
    assert_eq!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_ir0_different_trees_different_hashes() {
    let m1 = ir0();
    let m2 = Ir0Module::from_syntax_tree(
        SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![],
            span: span(),
        },
        "empty.mjs",
    );
    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_ir0_serde_roundtrip() {
    let m = ir0();
    let json = serde_json::to_string(&m).unwrap();
    let restored: Ir0Module = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

// =========================================================================
// Verification: verify_ir0_hash
// =========================================================================

#[test]
fn enrichment_verify_ir0_hash_ok() {
    let m = ir0();
    let h = m.content_hash();
    assert!(verify_ir0_hash(&m, &h).is_ok());
}

#[test]
fn enrichment_verify_ir0_hash_mismatch() {
    let m = ir0();
    let wrong = ContentHash::compute(b"not_the_hash");
    let err = verify_ir0_hash(&m, &wrong).unwrap_err();
    assert_eq!(err.code, IrErrorCode::HashVerificationFailed);
    assert_eq!(err.level, IrLevel::Ir0);
}

// =========================================================================
// BindingKind
// =========================================================================

#[test]
fn enrichment_binding_kind_as_str_all_unique() {
    let kinds = [
        BindingKind::Let,
        BindingKind::Const,
        BindingKind::Var,
        BindingKind::Parameter,
        BindingKind::Import,
        BindingKind::FunctionDecl,
    ];
    let mut seen = BTreeSet::new();
    for k in &kinds {
        assert!(seen.insert(k.as_str()), "duplicate: {}", k.as_str());
    }
    assert_eq!(seen.len(), 6);
}

#[test]
fn enrichment_binding_kind_serde_roundtrip() {
    for kind in [
        BindingKind::Let,
        BindingKind::Const,
        BindingKind::Var,
        BindingKind::Parameter,
        BindingKind::Import,
        BindingKind::FunctionDecl,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let restored: BindingKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, restored);
    }
}

// =========================================================================
// ScopeKind
// =========================================================================

#[test]
fn enrichment_scope_kind_as_str_all_unique() {
    let kinds = [
        ScopeKind::Global,
        ScopeKind::Module,
        ScopeKind::Function,
        ScopeKind::Block,
        ScopeKind::Catch,
    ];
    let mut seen = BTreeSet::new();
    for k in &kinds {
        assert!(seen.insert(k.as_str()), "duplicate: {}", k.as_str());
    }
    assert_eq!(seen.len(), 5);
}

// =========================================================================
// Ir1PropertyKey
// =========================================================================

#[test]
fn enrichment_ir1_property_key_serde() {
    let static_key = Ir1PropertyKey::Static("name".to_string());
    let dynamic_key = Ir1PropertyKey::Dynamic;
    for key in &[static_key, dynamic_key] {
        let json = serde_json::to_string(key).unwrap();
        let restored: Ir1PropertyKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, &restored);
    }
}

// =========================================================================
// IteratorCloseReason
// =========================================================================

#[test]
fn enrichment_iterator_close_reason_as_str_all() {
    let reasons = [
        (IteratorCloseReason::Break, "break"),
        (IteratorCloseReason::Return, "return"),
        (IteratorCloseReason::Throw, "throw"),
    ];
    let mut seen = BTreeSet::new();
    for (reason, expected) in &reasons {
        assert_eq!(reason.as_str(), *expected);
        assert!(seen.insert(reason.as_str()));
    }
    assert_eq!(seen.len(), 3);
}

// =========================================================================
// Ir1Literal
// =========================================================================

#[test]
fn enrichment_ir1_literal_all_variants_serde() {
    let literals = vec![
        Ir1Literal::String("hello".to_string()),
        Ir1Literal::Integer(42),
        Ir1Literal::Integer(-1),
        Ir1Literal::Boolean(true),
        Ir1Literal::Boolean(false),
        Ir1Literal::Null,
        Ir1Literal::Undefined,
    ];
    for lit in literals {
        let json = serde_json::to_string(&lit).unwrap();
        let restored: Ir1Literal = serde_json::from_str(&json).unwrap();
        assert_eq!(lit, restored);
    }
}

// =========================================================================
// Ir1Op — representative variants
// =========================================================================

#[test]
fn enrichment_ir1_op_all_variants_serde_sample() {
    use frankenengine_engine::ast::{AssignmentOperator, BinaryOperator, UnaryOperator};

    let ops = vec![
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(1),
        },
        Ir1Op::LoadBinding { binding_id: 5 },
        Ir1Op::StoreBinding { binding_id: 3 },
        Ir1Op::Call { arg_count: 2 },
        Ir1Op::Return,
        Ir1Op::ImportModule {
            specifier: "react".to_string(),
        },
        Ir1Op::ExportBinding {
            name: "default".to_string(),
            binding_id: 0,
        },
        Ir1Op::Await,
        Ir1Op::Nop,
        Ir1Op::BinaryOp {
            operator: BinaryOperator::Add,
        },
        Ir1Op::UnaryOp {
            operator: UnaryOperator::Typeof,
        },
        Ir1Op::AssignOp {
            binding_id: 1,
            operator: AssignmentOperator::AddAssign,
        },
        Ir1Op::Label { id: 0 },
        Ir1Op::Jump { label_id: 0 },
        Ir1Op::JumpIfFalsy { label_id: 1 },
        Ir1Op::JumpIfFalsyConsume { label_id: 2 },
        Ir1Op::JumpIfTruthy { label_id: 3 },
        Ir1Op::JumpIfNullish { label_id: 4 },
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Static("x".to_string()),
        },
        Ir1Op::SetProperty {
            key: Ir1PropertyKey::Dynamic,
        },
        Ir1Op::DeleteProperty {
            key: Ir1PropertyKey::Static("y".to_string()),
        },
        Ir1Op::NewArray { count: 3 },
        Ir1Op::NewObject { count: 2 },
        Ir1Op::Throw,
        Ir1Op::LoadThis,
        Ir1Op::DeclareFunction {
            name: "foo".to_string(),
            binding_id: 10,
        },
        Ir1Op::BeginTry {
            catch_label: 5,
            finally_label: None,
        },
        Ir1Op::EndTry,
        Ir1Op::Pop,
        Ir1Op::ForInInit,
        Ir1Op::ForInNext { done_label: 6 },
        Ir1Op::ForOfInit,
        Ir1Op::ForOfNext { done_label: 7 },
        Ir1Op::IteratorClose {
            reason: IteratorCloseReason::Break,
        },
        Ir1Op::Construct { arg_count: 1 },
        Ir1Op::TemplateLiteral { quasi_count: 2 },
    ];
    for op in ops {
        let json = serde_json::to_string(&op).unwrap();
        let restored: Ir1Op = serde_json::from_str(&json).unwrap();
        assert_eq!(op, restored);
    }
}

// =========================================================================
// IR1 Module
// =========================================================================

#[test]
fn enrichment_ir1_module_new_sets_header() {
    let h = ContentHash::compute(b"ir0");
    let m = Ir1Module::new(h, "src.js");
    assert_eq!(m.header.level, IrLevel::Ir1);
    assert_eq!(m.header.source_hash, Some(h));
    assert!(m.scopes.is_empty());
    assert!(m.ops.is_empty());
}

#[test]
fn enrichment_ir1_module_content_hash_deterministic() {
    let h = ContentHash::compute(b"ir0");
    let m1 = ir1(h);
    let m2 = ir1(h);
    assert_eq!(m1.content_hash(), m2.content_hash());
}

// =========================================================================
// Verification: verify_ir1_source
// =========================================================================

#[test]
fn enrichment_verify_ir1_source_ok() {
    let h0 = ContentHash::compute(b"ir0_content");
    let m = Ir1Module::new(h0, "test.js");
    assert!(verify_ir1_source(&m, &h0).is_ok());
}

#[test]
fn enrichment_verify_ir1_source_mismatch() {
    let h0 = ContentHash::compute(b"ir0");
    let wrong = ContentHash::compute(b"different");
    let m = Ir1Module::new(h0, "test.js");
    let err = verify_ir1_source(&m, &wrong).unwrap_err();
    assert_eq!(err.code, IrErrorCode::SourceHashMismatch);
}

// =========================================================================
// EffectBoundary
// =========================================================================

#[test]
fn enrichment_effect_boundary_as_str_all() {
    let effects = [
        (EffectBoundary::Pure, "pure"),
        (EffectBoundary::ReadEffect, "read"),
        (EffectBoundary::WriteEffect, "write"),
        (EffectBoundary::NetworkEffect, "network"),
        (EffectBoundary::FsEffect, "fs"),
        (EffectBoundary::HostcallEffect, "hostcall"),
    ];
    let mut seen = BTreeSet::new();
    for (eff, expected) in &effects {
        assert_eq!(eff.as_str(), *expected);
        assert!(seen.insert(eff.as_str()));
    }
    assert_eq!(seen.len(), 6);
}

// =========================================================================
// IR2
// =========================================================================

#[test]
fn enrichment_ir2_module_with_capability_and_flow() {
    let h = ContentHash::compute(b"ir1");
    let mut m = Ir2Module::new(h, "test.js");
    m.ops.push(Ir2Op {
        inner: Ir1Op::Call { arg_count: 1 },
        effect: EffectBoundary::HostcallEffect,
        required_capability: Some(CapabilityTag("fs:read".to_string())),
        flow: Some(FlowAnnotation {
            data_label: Label::Public,
            sink_clearance: Label::Secret,
            declassification_required: true,
        }),
    });
    m.required_capabilities
        .push(CapabilityTag("fs:read".to_string()));
    let json = serde_json::to_string(&m).unwrap();
    let restored: Ir2Module = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

// =========================================================================
// IR3
// =========================================================================

#[test]
fn enrichment_ir3_module_new_sets_header() {
    let h = ContentHash::compute(b"ir2");
    let m = Ir3Module::new(h, "test.js");
    assert_eq!(m.header.level, IrLevel::Ir3);
    assert_eq!(m.header.source_hash, Some(h));
    assert!(m.instructions.is_empty());
    assert!(m.specialization.is_none());
}

#[test]
fn enrichment_ir3_with_specialization_serde() {
    let h = ContentHash::compute(b"ir2");
    let mut m = Ir3Module::new(h, "test.js");
    m.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec!["proof-1".to_string(), "proof-2".to_string()],
        optimization_class: "inline_cache".to_string(),
        validity_epoch: 100,
        rollback_token: ContentHash::compute(b"rollback"),
    });
    let json = serde_json::to_string(&m).unwrap();
    let restored: Ir3Module = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

// =========================================================================
// Verification: verify_ir3_specialization
// =========================================================================

#[test]
fn enrichment_verify_ir3_no_specialization_ok() {
    let h = ContentHash::compute(b"ir2");
    let m = Ir3Module::new(h, "test.js");
    assert!(verify_ir3_specialization(&m).is_ok());
}

#[test]
fn enrichment_verify_ir3_valid_specialization_ok() {
    let h = ContentHash::compute(b"ir2");
    let mut m = Ir3Module::new(h, "test.js");
    m.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec!["proof-1".to_string()],
        optimization_class: "deopt_guard".to_string(),
        validity_epoch: 50,
        rollback_token: ContentHash::compute(b"rb"),
    });
    assert!(verify_ir3_specialization(&m).is_ok());
}

#[test]
fn enrichment_verify_ir3_empty_proof_ids_fails() {
    let h = ContentHash::compute(b"ir2");
    let mut m = Ir3Module::new(h, "test.js");
    m.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec![],
        optimization_class: "inline_cache".to_string(),
        validity_epoch: 10,
        rollback_token: ContentHash::compute(b"rb"),
    });
    let err = verify_ir3_specialization(&m).unwrap_err();
    assert_eq!(err.code, IrErrorCode::InvalidSpecializationLinkage);
}

#[test]
fn enrichment_verify_ir3_empty_optimization_class_fails() {
    let h = ContentHash::compute(b"ir2");
    let mut m = Ir3Module::new(h, "test.js");
    m.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec!["p1".to_string()],
        optimization_class: "".to_string(),
        validity_epoch: 10,
        rollback_token: ContentHash::compute(b"rb"),
    });
    let err = verify_ir3_specialization(&m).unwrap_err();
    assert_eq!(err.code, IrErrorCode::InvalidSpecializationLinkage);
}

// =========================================================================
// WitnessEventKind
// =========================================================================

#[test]
fn enrichment_witness_event_kind_as_str_all() {
    let kinds = [
        (WitnessEventKind::HostcallDispatched, "hostcall_dispatched"),
        (WitnessEventKind::CapabilityChecked, "capability_checked"),
        (WitnessEventKind::ExceptionRaised, "exception_raised"),
        (WitnessEventKind::GcTriggered, "gc_triggered"),
        (WitnessEventKind::ExecutionCompleted, "execution_completed"),
        (WitnessEventKind::FlowLabelChecked, "flow_label_checked"),
        (
            WitnessEventKind::DeclassificationRequested,
            "declassification_requested",
        ),
    ];
    let mut seen = BTreeSet::new();
    for (kind, expected) in &kinds {
        assert_eq!(kind.as_str(), *expected);
        assert!(seen.insert(kind.as_str()));
    }
    assert_eq!(seen.len(), 7);
}

// =========================================================================
// ExecutionOutcome
// =========================================================================

#[test]
fn enrichment_execution_outcome_as_str_all() {
    let outcomes = [
        (ExecutionOutcome::Completed, "completed"),
        (ExecutionOutcome::Exception, "exception"),
        (ExecutionOutcome::Timeout, "timeout"),
        (ExecutionOutcome::Halted, "halted"),
    ];
    let mut seen = BTreeSet::new();
    for (outcome, expected) in &outcomes {
        assert_eq!(outcome.as_str(), *expected);
        assert!(seen.insert(outcome.as_str()));
    }
    assert_eq!(seen.len(), 4);
}

// =========================================================================
// IR4 Module
// =========================================================================

#[test]
fn enrichment_ir4_module_new_sets_defaults() {
    let h = ContentHash::compute(b"ir3");
    let m = Ir4Module::new(h, "test.js");
    assert_eq!(m.header.level, IrLevel::Ir4);
    assert_eq!(m.executed_ir3_hash, h);
    assert_eq!(m.outcome, ExecutionOutcome::Completed);
    assert!(m.events.is_empty());
    assert!(m.hostcall_decisions.is_empty());
    assert_eq!(m.instructions_executed, 0);
    assert_eq!(m.duration_ticks, 0);
}

#[test]
fn enrichment_ir4_with_events_serde() {
    let h = ContentHash::compute(b"ir3");
    let mut m = Ir4Module::new(h, "test.js");
    m.events.push(WitnessEvent {
        seq: 0,
        kind: WitnessEventKind::CapabilityChecked,
        instruction_index: 5,
        payload_hash: ContentHash::compute(b"cap_check"),
        timestamp_tick: 10,
    });
    m.events.push(WitnessEvent {
        seq: 1,
        kind: WitnessEventKind::HostcallDispatched,
        instruction_index: 6,
        payload_hash: ContentHash::compute(b"hostcall"),
        timestamp_tick: 20,
    });
    m.hostcall_decisions.push(HostcallDecisionRecord {
        seq: 0,
        capability: CapabilityTag("net:fetch".to_string()),
        allowed: true,
        instruction_index: 6,
    });
    m.outcome = ExecutionOutcome::Completed;
    m.instructions_executed = 100;
    m.duration_ticks = 500;

    let json = serde_json::to_string(&m).unwrap();
    let restored: Ir4Module = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

// =========================================================================
// Verification: verify_ir4_linkage
// =========================================================================

#[test]
fn enrichment_verify_ir4_linkage_ok() {
    let h3 = ContentHash::compute(b"ir3");
    let m = ir4(h3);
    assert!(verify_ir4_linkage(&m, &h3).is_ok());
}

#[test]
fn enrichment_verify_ir4_hash_mismatch() {
    let h3 = ContentHash::compute(b"ir3");
    let wrong = ContentHash::compute(b"wrong_ir3");
    let m = ir4(h3);
    let err = verify_ir4_linkage(&m, &wrong).unwrap_err();
    assert_eq!(err.code, IrErrorCode::WitnessIntegrityViolation);
}

#[test]
fn enrichment_verify_ir4_non_monotonic_events() {
    let h3 = ContentHash::compute(b"ir3");
    let mut m = Ir4Module::new(h3, "test.js");
    m.events.push(WitnessEvent {
        seq: 5,
        kind: WitnessEventKind::ExecutionCompleted,
        instruction_index: 0,
        payload_hash: ContentHash::compute(b"a"),
        timestamp_tick: 10,
    });
    m.events.push(WitnessEvent {
        seq: 3, // non-monotonic!
        kind: WitnessEventKind::ExceptionRaised,
        instruction_index: 1,
        payload_hash: ContentHash::compute(b"b"),
        timestamp_tick: 20,
    });
    let err = verify_ir4_linkage(&m, &h3).unwrap_err();
    assert_eq!(err.code, IrErrorCode::WitnessIntegrityViolation);
    assert!(err.message.contains("not monotonic"));
}

// =========================================================================
// IrError
// =========================================================================

#[test]
fn enrichment_ir_error_display_format() {
    let err = IrError::new(
        IrErrorCode::SourceHashMismatch,
        "hash mismatch",
        IrLevel::Ir1,
    );
    let display = err.to_string();
    assert!(display.contains("ir1"));
    assert!(display.contains("IR_SOURCE_HASH_MISMATCH"));
    assert!(display.contains("hash mismatch"));
}

#[test]
fn enrichment_ir_error_is_std_error() {
    let err = IrError::new(IrErrorCode::LevelMismatch, "wrong level", IrLevel::Ir2);
    let _: &dyn std::error::Error = &err;
}

#[test]
fn enrichment_ir_error_code_as_str_all_unique() {
    let codes = [
        IrErrorCode::SchemaVersionMismatch,
        IrErrorCode::LevelMismatch,
        IrErrorCode::SourceHashMismatch,
        IrErrorCode::HashVerificationFailed,
        IrErrorCode::MissingCapabilityAnnotation,
        IrErrorCode::InvalidSpecializationLinkage,
        IrErrorCode::WitnessIntegrityViolation,
    ];
    let mut seen = BTreeSet::new();
    for code in &codes {
        assert!(seen.insert(code.as_str()), "duplicate: {}", code.as_str());
    }
    assert_eq!(seen.len(), 7);
}

#[test]
fn enrichment_error_code_helper() {
    let err = IrError::new(
        IrErrorCode::HashVerificationFailed,
        "bad hash",
        IrLevel::Ir0,
    );
    assert_eq!(error_code(&err), "IR_HASH_VERIFICATION_FAILED");
}

// =========================================================================
// IrContractEvent serde
// =========================================================================

#[test]
fn enrichment_ir_contract_event_serde() {
    let event = IrContractEvent {
        trace_id: "trace-1".to_string(),
        component: "ir_contract".to_string(),
        event: "ir0_hash_verified".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        level: IrLevel::Ir0,
        content_hash: Some("abc123".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: IrContractEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// =========================================================================
// IrVerifier drain_events
// =========================================================================

#[test]
fn enrichment_ir_verifier_drain_clears() {
    let m0 = ir0();
    let h0 = m0.content_hash();
    let mut v = IrVerifier::new();
    v.verify_ir0(&m0, &h0, "t1").unwrap();
    assert_eq!(v.drain_events().len(), 1);
    assert_eq!(v.drain_events().len(), 0); // drained
}

#[test]
fn enrichment_ir_verifier_default() {
    let v = IrVerifier::default();
    let mut v = v;
    assert!(v.drain_events().is_empty());
}

// =========================================================================
// Ir3Instruction representative variants serde
// =========================================================================

#[test]
fn enrichment_ir3_instruction_sample_variants_serde() {
    let instrs = vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 0,
        },
        Ir3Instruction::LoadBool {
            dst: 2,
            value: true,
        },
        Ir3Instruction::LoadNull { dst: 3 },
        Ir3Instruction::LoadUndefined { dst: 4 },
        Ir3Instruction::Add {
            dst: 5,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Sub {
            dst: 6,
            lhs: 2,
            rhs: 3,
        },
        Ir3Instruction::Mul {
            dst: 7,
            lhs: 4,
            rhs: 5,
        },
        Ir3Instruction::Halt,
        Ir3Instruction::Return { value: 0 },
    ];
    for instr in instrs {
        let json = serde_json::to_string(&instr).unwrap();
        let restored: Ir3Instruction = serde_json::from_str(&json).unwrap();
        assert_eq!(instr, restored);
    }
}

// =========================================================================
// Ir3FunctionDesc
// =========================================================================

#[test]
fn enrichment_ir3_function_desc_serde() {
    let desc = Ir3FunctionDesc {
        entry: 0,
        arity: 3,
        frame_size: 10,
        name: Some("compute".to_string()),
    };
    let json = serde_json::to_string(&desc).unwrap();
    let restored: Ir3FunctionDesc = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, restored);
}

#[test]
fn enrichment_ir3_function_desc_anonymous() {
    let desc = Ir3FunctionDesc {
        entry: 50,
        arity: 0,
        frame_size: 2,
        name: None,
    };
    let json = serde_json::to_string(&desc).unwrap();
    let restored: Ir3FunctionDesc = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, restored);
}

// =========================================================================
// CapabilityTag
// =========================================================================

#[test]
fn enrichment_capability_tag_serde() {
    let tag = CapabilityTag("net:fetch".to_string());
    let json = serde_json::to_string(&tag).unwrap();
    let restored: CapabilityTag = serde_json::from_str(&json).unwrap();
    assert_eq!(tag, restored);
}

// =========================================================================
// HostcallDecisionRecord
// =========================================================================

#[test]
fn enrichment_hostcall_decision_record_serde() {
    let record = HostcallDecisionRecord {
        seq: 7,
        capability: CapabilityTag("fs:write".to_string()),
        allowed: false,
        instruction_index: 42,
    };
    let json = serde_json::to_string(&record).unwrap();
    let restored: HostcallDecisionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

// =========================================================================
// RegRange
// =========================================================================

#[test]
fn enrichment_reg_range_serde() {
    let rr = RegRange {
        start: 5,
        count: 10,
    };
    let json = serde_json::to_string(&rr).unwrap();
    let restored: RegRange = serde_json::from_str(&json).unwrap();
    assert_eq!(rr, restored);
}

// =========================================================================
// FlowAnnotation
// =========================================================================

#[test]
fn enrichment_flow_annotation_serde() {
    let flow = FlowAnnotation {
        data_label: Label::Public,
        sink_clearance: Label::Secret,
        declassification_required: true,
    };
    let json = serde_json::to_string(&flow).unwrap();
    let restored: FlowAnnotation = serde_json::from_str(&json).unwrap();
    assert_eq!(flow, restored);
}

// =========================================================================
// Content hash determinism across all module types
// =========================================================================

#[test]
fn enrichment_all_module_canonical_bytes_deterministic() {
    let m0 = ir0();
    assert_eq!(m0.canonical_bytes(), m0.canonical_bytes());

    let h0 = m0.content_hash();
    let m1 = ir1(h0);
    assert_eq!(m1.canonical_bytes(), m1.canonical_bytes());

    let m2 = ir2(m1.content_hash());
    assert_eq!(m2.canonical_bytes(), m2.canonical_bytes());

    let m3 = ir3(m2.content_hash());
    assert_eq!(m3.canonical_bytes(), m3.canonical_bytes());

    let m4 = ir4(m3.content_hash());
    assert_eq!(m4.canonical_bytes(), m4.canonical_bytes());
}
