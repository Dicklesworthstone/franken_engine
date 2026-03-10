#![forbid(unsafe_code)]
//! Integration tests for `ir_contract` — multi-level IR (IR0–IR4) with
//! canonical hash chain, serde round-trips, verification helpers,
//! structured events, and cross-concern integration scenarios.

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
    HostcallDecisionRecord, Ir0Module, Ir1Literal, Ir1Module, Ir1Op, Ir2Module, Ir2Op,
    Ir3FunctionDesc, Ir3Instruction, Ir3Module, Ir4Module, IrContractEvent, IrError, IrErrorCode,
    IrLevel, IrSchemaVersion, IrVerifier, RegRange, ResolvedBinding, ScopeId, ScopeKind, ScopeNode,
    SpecializationLinkage, WitnessEvent, WitnessEventKind, error_code, verify_ir0_hash,
    verify_ir1_source, verify_ir3_specialization, verify_ir4_linkage,
};

// ============================================================================
// Helpers
// ============================================================================

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

fn make_module_syntax_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![],
        span: make_span(),
    }
}

fn make_ir0() -> Ir0Module {
    Ir0Module::from_syntax_tree(make_syntax_tree(), "test.js")
}

fn make_ir1(source_hash: ContentHash) -> Ir1Module {
    let mut ir1 = Ir1Module::new(source_hash, "test.js");
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

fn make_ir2(source_hash: ContentHash) -> Ir2Module {
    let mut ir2 = Ir2Module::new(source_hash, "test.js");
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(42),
        },
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

fn make_ir3(source_hash: ContentHash) -> Ir3Module {
    let mut ir3 = Ir3Module::new(source_hash, "test.js");
    ir3.instructions
        .push(Ir3Instruction::LoadInt { dst: 0, value: 42 });
    ir3.instructions
        .push(Ir3Instruction::LoadInt { dst: 1, value: 10 });
    ir3.instructions.push(Ir3Instruction::Add {
        dst: 2,
        lhs: 0,
        rhs: 1,
    });
    ir3.instructions.push(Ir3Instruction::Return { value: 2 });
    ir3.instructions.push(Ir3Instruction::Halt);
    ir3.constant_pool.push("hello".to_string());
    ir3.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 0,
        frame_size: 3,
        name: Some("main".to_string()),
    });
    ir3
}

fn make_ir4(ir3_hash: ContentHash) -> Ir4Module {
    let mut ir4 = Ir4Module::new(ir3_hash, "test.js");
    ir4.events.push(WitnessEvent {
        seq: 0,
        kind: WitnessEventKind::HostcallDispatched,
        instruction_index: 0,
        payload_hash: ContentHash::compute(b"payload-0"),
        timestamp_tick: 100,
    });
    ir4.events.push(WitnessEvent {
        seq: 1,
        kind: WitnessEventKind::ExecutionCompleted,
        instruction_index: 4,
        payload_hash: ContentHash::compute(b"payload-1"),
        timestamp_tick: 200,
    });
    ir4.hostcall_decisions.push(HostcallDecisionRecord {
        seq: 0,
        capability: CapabilityTag("fs:read".to_string()),
        allowed: true,
        instruction_index: 0,
    });
    ir4.instructions_executed = 5;
    ir4.duration_ticks = 200;
    ir4.active_specialization_ids.push("spec-alpha".to_string());
    ir4
}

/// Build a full IR0 -> IR1 -> IR2 -> IR3 -> IR4 pipeline, returning all modules.
fn build_full_pipeline() -> (Ir0Module, Ir1Module, Ir2Module, Ir3Module, Ir4Module) {
    let ir0 = make_ir0();
    let ir0_hash = ir0.content_hash();
    let ir1 = make_ir1(ir0_hash.clone());
    let ir1_hash = ir1.content_hash();
    let ir2 = make_ir2(ir1_hash.clone());
    let ir2_hash = ir2.content_hash();
    let ir3 = make_ir3(ir2_hash.clone());
    let ir3_hash = ir3.content_hash();
    let ir4 = make_ir4(ir3_hash.clone());
    (ir0, ir1, ir2, ir3, ir4)
}

// ============================================================================
// 1. IrSchemaVersion
// ============================================================================

#[test]
fn schema_version_current_values() {
    let v = IrSchemaVersion::CURRENT;
    assert_eq!(v.major, 0);
    assert_eq!(v.minor, 1);
    assert_eq!(v.patch, 0);
}

#[test]
fn schema_version_display() {
    assert_eq!(IrSchemaVersion::CURRENT.to_string(), "0.1.0");
    let custom = IrSchemaVersion {
        major: 2,
        minor: 3,
        patch: 99,
    };
    assert_eq!(custom.to_string(), "2.3.99");
}

#[test]
fn schema_version_serde_roundtrip() {
    let v = IrSchemaVersion::CURRENT;
    let json = serde_json::to_string(&v).unwrap();
    let restored: IrSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

#[test]
fn schema_version_custom_serde_roundtrip() {
    let v = IrSchemaVersion {
        major: 10,
        minor: 20,
        patch: 30,
    };
    let json = serde_json::to_string(&v).unwrap();
    let restored: IrSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

#[test]
fn schema_version_canonical_deterministic() {
    let a = IrSchemaVersion::CURRENT.canonical_value();
    let b = IrSchemaVersion::CURRENT.canonical_value();
    assert_eq!(a, b);
}

#[test]
fn schema_version_ordering() {
    let v010 = IrSchemaVersion {
        major: 0,
        minor: 1,
        patch: 0,
    };
    let v020 = IrSchemaVersion {
        major: 0,
        minor: 2,
        patch: 0,
    };
    let v100 = IrSchemaVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };
    assert!(v010 < v020);
    assert!(v020 < v100);
}

// ============================================================================
// 2. IrLevel
// ============================================================================

#[test]
fn ir_level_as_str_all_variants() {
    assert_eq!(IrLevel::Ir0.as_str(), "ir0");
    assert_eq!(IrLevel::Ir1.as_str(), "ir1");
    assert_eq!(IrLevel::Ir2.as_str(), "ir2");
    assert_eq!(IrLevel::Ir3.as_str(), "ir3");
    assert_eq!(IrLevel::Ir4.as_str(), "ir4");
}

#[test]
fn ir_level_display_all_variants() {
    assert_eq!(format!("{}", IrLevel::Ir0), "ir0");
    assert_eq!(format!("{}", IrLevel::Ir1), "ir1");
    assert_eq!(format!("{}", IrLevel::Ir2), "ir2");
    assert_eq!(format!("{}", IrLevel::Ir3), "ir3");
    assert_eq!(format!("{}", IrLevel::Ir4), "ir4");
}

#[test]
fn ir_level_ordering() {
    assert!(IrLevel::Ir0 < IrLevel::Ir1);
    assert!(IrLevel::Ir1 < IrLevel::Ir2);
    assert!(IrLevel::Ir2 < IrLevel::Ir3);
    assert!(IrLevel::Ir3 < IrLevel::Ir4);
}

#[test]
fn ir_level_serde_roundtrip_all_variants() {
    for level in [
        IrLevel::Ir0,
        IrLevel::Ir1,
        IrLevel::Ir2,
        IrLevel::Ir3,
        IrLevel::Ir4,
    ] {
        let json = serde_json::to_string(&level).unwrap();
        let restored: IrLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, restored, "level={level}");
    }
}

#[test]
fn ir_level_equality_and_clone() {
    let a = IrLevel::Ir2;
    let b = a;
    assert_eq!(a, b);
    let c = a;
    assert_eq!(a, c);
}

// ============================================================================
// 3. BindingKind
// ============================================================================

#[test]
fn binding_kind_as_str_all_variants() {
    assert_eq!(BindingKind::Let.as_str(), "let");
    assert_eq!(BindingKind::Const.as_str(), "const");
    assert_eq!(BindingKind::Var.as_str(), "var");
    assert_eq!(BindingKind::Parameter.as_str(), "parameter");
    assert_eq!(BindingKind::Import.as_str(), "import");
    assert_eq!(BindingKind::FunctionDecl.as_str(), "function_decl");
}

#[test]
fn binding_kind_serde_roundtrip() {
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

// ============================================================================
// 4. ScopeKind
// ============================================================================

#[test]
fn scope_kind_as_str_all_variants() {
    assert_eq!(ScopeKind::Global.as_str(), "global");
    assert_eq!(ScopeKind::Module.as_str(), "module");
    assert_eq!(ScopeKind::Function.as_str(), "function");
    assert_eq!(ScopeKind::Block.as_str(), "block");
    assert_eq!(ScopeKind::Catch.as_str(), "catch");
}

#[test]
fn scope_kind_serde_roundtrip() {
    for kind in [
        ScopeKind::Global,
        ScopeKind::Module,
        ScopeKind::Function,
        ScopeKind::Block,
        ScopeKind::Catch,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let restored: ScopeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, restored);
    }
}

// ============================================================================
// 5. ScopeId
// ============================================================================

#[test]
fn scope_id_construction_and_canonical() {
    let sid = ScopeId { depth: 3, index: 7 };
    assert_eq!(sid.depth, 3);
    assert_eq!(sid.index, 7);
    // canonical_value is deterministic
    let a = sid.canonical_value();
    let b = sid.canonical_value();
    assert_eq!(a, b);
}

#[test]
fn scope_id_serde_roundtrip() {
    let sid = ScopeId {
        depth: 10,
        index: 99,
    };
    let json = serde_json::to_string(&sid).unwrap();
    let restored: ScopeId = serde_json::from_str(&json).unwrap();
    assert_eq!(sid, restored);
}

// ============================================================================
// 6. ResolvedBinding
// ============================================================================

#[test]
fn resolved_binding_construction_and_canonical() {
    let rb = ResolvedBinding {
        name: "myVar".to_string(),
        binding_id: 42,
        scope: ScopeId { depth: 1, index: 2 },
        kind: BindingKind::Const,
    };
    assert_eq!(rb.name, "myVar");
    assert_eq!(rb.binding_id, 42);
    let cv = rb.canonical_value();
    let cv2 = rb.canonical_value();
    assert_eq!(cv, cv2);
}

#[test]
fn resolved_binding_serde_roundtrip() {
    let rb = ResolvedBinding {
        name: "foo".to_string(),
        binding_id: 7,
        scope: ScopeId { depth: 0, index: 0 },
        kind: BindingKind::Import,
    };
    let json = serde_json::to_string(&rb).unwrap();
    let restored: ResolvedBinding = serde_json::from_str(&json).unwrap();
    assert_eq!(rb, restored);
}

// ============================================================================
// 7. ScopeNode
// ============================================================================

#[test]
fn scope_node_with_parent_canonical() {
    let node = ScopeNode {
        scope_id: ScopeId { depth: 1, index: 0 },
        parent: Some(ScopeId { depth: 0, index: 0 }),
        kind: ScopeKind::Function,
        bindings: vec![ResolvedBinding {
            name: "param".to_string(),
            binding_id: 0,
            scope: ScopeId { depth: 1, index: 0 },
            kind: BindingKind::Parameter,
        }],
    };
    let cv1 = node.canonical_value();
    let cv2 = node.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn scope_node_without_parent_canonical() {
    let node = ScopeNode {
        scope_id: ScopeId { depth: 0, index: 0 },
        parent: None,
        kind: ScopeKind::Global,
        bindings: vec![],
    };
    let cv = node.canonical_value();
    let cv2 = node.canonical_value();
    assert_eq!(cv, cv2);
}

#[test]
fn scope_node_serde_roundtrip() {
    let node = ScopeNode {
        scope_id: ScopeId { depth: 2, index: 1 },
        parent: Some(ScopeId { depth: 1, index: 0 }),
        kind: ScopeKind::Catch,
        bindings: vec![ResolvedBinding {
            name: "err".to_string(),
            binding_id: 5,
            scope: ScopeId { depth: 2, index: 1 },
            kind: BindingKind::Let,
        }],
    };
    let json = serde_json::to_string(&node).unwrap();
    let restored: ScopeNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, restored);
}

// ============================================================================
// 8. Ir1Literal
// ============================================================================

#[test]
fn ir1_literal_all_variants_canonical_and_serde() {
    let literals = vec![
        Ir1Literal::String("hello world".to_string()),
        Ir1Literal::Integer(i64::MAX),
        Ir1Literal::Integer(i64::MIN),
        Ir1Literal::Integer(0),
        Ir1Literal::Boolean(true),
        Ir1Literal::Boolean(false),
        Ir1Literal::Null,
        Ir1Literal::Undefined,
    ];
    for lit in &literals {
        // canonical is deterministic
        let cv1 = lit.canonical_value();
        let cv2 = lit.canonical_value();
        assert_eq!(cv1, cv2);
        // serde round-trip
        let json = serde_json::to_string(lit).unwrap();
        let restored: Ir1Literal = serde_json::from_str(&json).unwrap();
        assert_eq!(*lit, restored);
    }
}

// ============================================================================
// 9. Ir1Op
// ============================================================================

#[test]
fn ir1_op_all_variants_canonical() {
    let ops = vec![
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("test".to_string()),
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(99),
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Boolean(false),
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Null,
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::LoadBinding { binding_id: 0 },
        Ir1Op::StoreBinding { binding_id: 99 },
        Ir1Op::Call { arg_count: 5 },
        Ir1Op::Return,
        Ir1Op::ImportModule {
            specifier: "./module.js".to_string(),
        },
        Ir1Op::ExportBinding {
            name: "default".to_string(),
            binding_id: 0,
        },
        Ir1Op::Await,
        Ir1Op::Nop,
    ];
    for op in &ops {
        let cv1 = op.canonical_value();
        let cv2 = op.canonical_value();
        assert_eq!(cv1, cv2);
    }
}

#[test]
fn ir1_op_serde_roundtrip_all_variants() {
    let ops = vec![
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("x".to_string()),
        },
        Ir1Op::LoadBinding { binding_id: 42 },
        Ir1Op::StoreBinding { binding_id: 7 },
        Ir1Op::Call { arg_count: 0 },
        Ir1Op::Return,
        Ir1Op::ImportModule {
            specifier: "mod".to_string(),
        },
        Ir1Op::ExportBinding {
            name: "y".to_string(),
            binding_id: 3,
        },
        Ir1Op::Await,
        Ir1Op::Nop,
    ];
    for op in &ops {
        let json = serde_json::to_string(op).unwrap();
        let restored: Ir1Op = serde_json::from_str(&json).unwrap();
        assert_eq!(*op, restored);
    }
}

// ============================================================================
// 10. EffectBoundary
// ============================================================================

#[test]
fn effect_boundary_as_str_all_variants() {
    assert_eq!(EffectBoundary::Pure.as_str(), "pure");
    assert_eq!(EffectBoundary::ReadEffect.as_str(), "read");
    assert_eq!(EffectBoundary::WriteEffect.as_str(), "write");
    assert_eq!(EffectBoundary::NetworkEffect.as_str(), "network");
    assert_eq!(EffectBoundary::FsEffect.as_str(), "fs");
    assert_eq!(EffectBoundary::HostcallEffect.as_str(), "hostcall");
}

#[test]
fn effect_boundary_serde_roundtrip() {
    for eb in [
        EffectBoundary::Pure,
        EffectBoundary::ReadEffect,
        EffectBoundary::WriteEffect,
        EffectBoundary::NetworkEffect,
        EffectBoundary::FsEffect,
        EffectBoundary::HostcallEffect,
    ] {
        let json = serde_json::to_string(&eb).unwrap();
        let restored: EffectBoundary = serde_json::from_str(&json).unwrap();
        assert_eq!(eb, restored);
    }
}

// ============================================================================
// 11. CapabilityTag
// ============================================================================

#[test]
fn capability_tag_construction_and_canonical() {
    let tag = CapabilityTag("net:connect".to_string());
    assert_eq!(tag.0, "net:connect");
    let cv1 = tag.canonical_value();
    let cv2 = tag.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn capability_tag_serde_roundtrip() {
    let tag = CapabilityTag("fs:write".to_string());
    let json = serde_json::to_string(&tag).unwrap();
    let restored: CapabilityTag = serde_json::from_str(&json).unwrap();
    assert_eq!(tag, restored);
}

// ============================================================================
// 12. FlowAnnotation
// ============================================================================

#[test]
fn flow_annotation_canonical_deterministic() {
    let fa = FlowAnnotation {
        data_label: Label::Secret,
        sink_clearance: Label::Confidential,
        declassification_required: true,
    };
    let cv1 = fa.canonical_value();
    let cv2 = fa.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn flow_annotation_serde_roundtrip() {
    let fa = FlowAnnotation {
        data_label: Label::Public,
        sink_clearance: Label::Internal,
        declassification_required: false,
    };
    let json = serde_json::to_string(&fa).unwrap();
    let restored: FlowAnnotation = serde_json::from_str(&json).unwrap();
    assert_eq!(fa, restored);
}

#[test]
fn flow_annotation_with_declassification_required() {
    let fa = FlowAnnotation {
        data_label: Label::TopSecret,
        sink_clearance: Label::Public,
        declassification_required: true,
    };
    assert!(fa.declassification_required);
    let json = serde_json::to_string(&fa).unwrap();
    let restored: FlowAnnotation = serde_json::from_str(&json).unwrap();
    assert!(restored.declassification_required);
}

// ============================================================================
// 13. Ir2Op
// ============================================================================

#[test]
fn ir2_op_pure_no_capability_no_flow() {
    let op = Ir2Op {
        inner: Ir1Op::Nop,
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
    };
    let cv1 = op.canonical_value();
    let cv2 = op.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn ir2_op_with_capability_and_flow() {
    let op = Ir2Op {
        inner: Ir1Op::Call { arg_count: 2 },
        effect: EffectBoundary::NetworkEffect,
        required_capability: Some(CapabilityTag("net:http".to_string())),
        flow: Some(FlowAnnotation {
            data_label: Label::Confidential,
            sink_clearance: Label::Secret,
            declassification_required: false,
        }),
    };
    let cv1 = op.canonical_value();
    let cv2 = op.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn ir2_op_serde_roundtrip() {
    let op = Ir2Op {
        inner: Ir1Op::LoadLiteral {
            value: Ir1Literal::Boolean(true),
        },
        effect: EffectBoundary::ReadEffect,
        required_capability: Some(CapabilityTag("db:read".to_string())),
        flow: None,
    };
    let json = serde_json::to_string(&op).unwrap();
    let restored: Ir2Op = serde_json::from_str(&json).unwrap();
    assert_eq!(op, restored);
}

// ============================================================================
// 14. RegRange
// ============================================================================

#[test]
fn reg_range_construction_and_canonical() {
    let rr = RegRange { start: 5, count: 3 };
    assert_eq!(rr.start, 5);
    assert_eq!(rr.count, 3);
    let cv1 = rr.canonical_value();
    let cv2 = rr.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn reg_range_serde_roundtrip() {
    let rr = RegRange {
        start: 0,
        count: 10,
    };
    let json = serde_json::to_string(&rr).unwrap();
    let restored: RegRange = serde_json::from_str(&json).unwrap();
    assert_eq!(rr, restored);
}

// ============================================================================
// 15. Ir3Instruction — all variants
// ============================================================================

#[test]
fn ir3_instruction_all_variants_canonical_deterministic() {
    let instructions = vec![
        Ir3Instruction::LoadInt {
            dst: 0,
            value: i64::MAX,
        },
        Ir3Instruction::LoadInt {
            dst: 0,
            value: i64::MIN,
        },
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 0,
        },
        Ir3Instruction::LoadBool {
            dst: 2,
            value: true,
        },
        Ir3Instruction::LoadBool {
            dst: 2,
            value: false,
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
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Mul {
            dst: 7,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Div {
            dst: 8,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Move { dst: 9, src: 0 },
        Ir3Instruction::Jump { target: 42 },
        Ir3Instruction::JumpIf {
            cond: 0,
            target: 99,
        },
        Ir3Instruction::Call {
            callee: 0,
            args: RegRange { start: 1, count: 3 },
            dst: 10,
        },
        Ir3Instruction::Return { value: 0 },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("sys:exec".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 11,
        },
        Ir3Instruction::GetProperty {
            obj: 0,
            key: 1,
            dst: 2,
        },
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 1,
            val: 2,
        },
        Ir3Instruction::Halt,
    ];
    for instr in &instructions {
        let cv1 = instr.canonical_value();
        let cv2 = instr.canonical_value();
        assert_eq!(cv1, cv2);
    }
}

#[test]
fn ir3_instruction_serde_roundtrip_all_variants() {
    let instructions = vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::LoadStr {
            dst: 0,
            pool_index: 5,
        },
        Ir3Instruction::LoadBool {
            dst: 0,
            value: false,
        },
        Ir3Instruction::LoadNull { dst: 0 },
        Ir3Instruction::LoadUndefined { dst: 0 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Sub {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Mul {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Move { dst: 0, src: 1 },
        Ir3Instruction::Jump { target: 7 },
        Ir3Instruction::JumpIf { cond: 0, target: 3 },
        Ir3Instruction::Call {
            callee: 0,
            args: RegRange { start: 1, count: 2 },
            dst: 3,
        },
        Ir3Instruction::Return { value: 0 },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("test".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 4,
        },
        Ir3Instruction::GetProperty {
            obj: 0,
            key: 1,
            dst: 2,
        },
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 1,
            val: 2,
        },
        Ir3Instruction::Halt,
    ];
    for instr in &instructions {
        let json = serde_json::to_string(instr).unwrap();
        let restored: Ir3Instruction = serde_json::from_str(&json).unwrap();
        assert_eq!(*instr, restored);
    }
}

// ============================================================================
// 16. Ir3FunctionDesc
// ============================================================================

#[test]
fn ir3_function_desc_with_name() {
    let desc = Ir3FunctionDesc {
        entry: 10,
        arity: 3,
        frame_size: 8,
        name: Some("factorial".to_string()),
    };
    assert_eq!(desc.entry, 10);
    assert_eq!(desc.arity, 3);
    assert_eq!(desc.frame_size, 8);
    assert_eq!(desc.name.as_deref(), Some("factorial"));
    let cv1 = desc.canonical_value();
    let cv2 = desc.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn ir3_function_desc_anonymous() {
    let desc = Ir3FunctionDesc {
        entry: 0,
        arity: 0,
        frame_size: 1,
        name: None,
    };
    assert!(desc.name.is_none());
    let cv = desc.canonical_value();
    let cv2 = desc.canonical_value();
    assert_eq!(cv, cv2);
}

#[test]
fn ir3_function_desc_serde_roundtrip() {
    for desc in [
        Ir3FunctionDesc {
            entry: 0,
            arity: 2,
            frame_size: 5,
            name: Some("add".to_string()),
        },
        Ir3FunctionDesc {
            entry: 100,
            arity: 0,
            frame_size: 0,
            name: None,
        },
    ] {
        let json = serde_json::to_string(&desc).unwrap();
        let restored: Ir3FunctionDesc = serde_json::from_str(&json).unwrap();
        assert_eq!(desc, restored);
    }
}

// ============================================================================
// 17. SpecializationLinkage
// ============================================================================

#[test]
fn specialization_linkage_construction_and_canonical() {
    let linkage = SpecializationLinkage {
        proof_input_ids: vec!["proof-alpha".to_string(), "proof-beta".to_string()],
        optimization_class: "constant_folding".to_string(),
        validity_epoch: 1000,
        rollback_token: ContentHash::compute(b"baseline-ir3"),
    };
    assert_eq!(linkage.proof_input_ids.len(), 2);
    assert_eq!(linkage.validity_epoch, 1000);
    let cv1 = linkage.canonical_value();
    let cv2 = linkage.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn specialization_linkage_serde_roundtrip() {
    let linkage = SpecializationLinkage {
        proof_input_ids: vec!["p1".to_string()],
        optimization_class: "dead_code_elimination".to_string(),
        validity_epoch: 42,
        rollback_token: ContentHash::compute(b"rollback"),
    };
    let json = serde_json::to_string(&linkage).unwrap();
    let restored: SpecializationLinkage = serde_json::from_str(&json).unwrap();
    assert_eq!(linkage, restored);
}

// ============================================================================
// 18. WitnessEventKind
// ============================================================================

#[test]
fn witness_event_kind_as_str_all_variants() {
    assert_eq!(
        WitnessEventKind::HostcallDispatched.as_str(),
        "hostcall_dispatched"
    );
    assert_eq!(
        WitnessEventKind::CapabilityChecked.as_str(),
        "capability_checked"
    );
    assert_eq!(
        WitnessEventKind::ExceptionRaised.as_str(),
        "exception_raised"
    );
    assert_eq!(WitnessEventKind::GcTriggered.as_str(), "gc_triggered");
    assert_eq!(
        WitnessEventKind::ExecutionCompleted.as_str(),
        "execution_completed"
    );
    assert_eq!(
        WitnessEventKind::FlowLabelChecked.as_str(),
        "flow_label_checked"
    );
    assert_eq!(
        WitnessEventKind::DeclassificationRequested.as_str(),
        "declassification_requested"
    );
}

#[test]
fn witness_event_kind_serde_roundtrip() {
    for kind in [
        WitnessEventKind::HostcallDispatched,
        WitnessEventKind::CapabilityChecked,
        WitnessEventKind::ExceptionRaised,
        WitnessEventKind::GcTriggered,
        WitnessEventKind::ExecutionCompleted,
        WitnessEventKind::FlowLabelChecked,
        WitnessEventKind::DeclassificationRequested,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let restored: WitnessEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, restored);
    }
}

// ============================================================================
// 19. ExecutionOutcome
// ============================================================================

#[test]
fn execution_outcome_as_str_all_variants() {
    assert_eq!(ExecutionOutcome::Completed.as_str(), "completed");
    assert_eq!(ExecutionOutcome::Exception.as_str(), "exception");
    assert_eq!(ExecutionOutcome::Timeout.as_str(), "timeout");
    assert_eq!(ExecutionOutcome::Halted.as_str(), "halted");
}

#[test]
fn execution_outcome_serde_roundtrip() {
    for outcome in [
        ExecutionOutcome::Completed,
        ExecutionOutcome::Exception,
        ExecutionOutcome::Timeout,
        ExecutionOutcome::Halted,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let restored: ExecutionOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, restored);
    }
}

// ============================================================================
// 20. WitnessEvent
// ============================================================================

#[test]
fn witness_event_canonical_deterministic() {
    let we = WitnessEvent {
        seq: 99,
        kind: WitnessEventKind::GcTriggered,
        instruction_index: 50,
        payload_hash: ContentHash::compute(b"gc-payload"),
        timestamp_tick: 999,
    };
    let cv1 = we.canonical_value();
    let cv2 = we.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn witness_event_serde_roundtrip() {
    let we = WitnessEvent {
        seq: 0,
        kind: WitnessEventKind::FlowLabelChecked,
        instruction_index: 10,
        payload_hash: ContentHash::compute(b"flow"),
        timestamp_tick: 500,
    };
    let json = serde_json::to_string(&we).unwrap();
    let restored: WitnessEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(we, restored);
}

// ============================================================================
// 21. HostcallDecisionRecord
// ============================================================================

#[test]
fn hostcall_decision_record_canonical_deterministic() {
    let hdr = HostcallDecisionRecord {
        seq: 5,
        capability: CapabilityTag("crypto:sign".to_string()),
        allowed: false,
        instruction_index: 20,
    };
    let cv1 = hdr.canonical_value();
    let cv2 = hdr.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn hostcall_decision_record_serde_roundtrip() {
    for allowed in [true, false] {
        let hdr = HostcallDecisionRecord {
            seq: 0,
            capability: CapabilityTag("test".to_string()),
            allowed,
            instruction_index: 0,
        };
        let json = serde_json::to_string(&hdr).unwrap();
        let restored: HostcallDecisionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(hdr, restored);
    }
}

// ============================================================================
// 22. IR0 Module
// ============================================================================

#[test]
fn ir0_from_syntax_tree_sets_correct_header() {
    let ir0 = make_ir0();
    assert_eq!(ir0.header.level, IrLevel::Ir0);
    assert_eq!(ir0.header.schema_version, IrSchemaVersion::CURRENT);
    assert!(ir0.header.source_hash.is_none());
    assert_eq!(ir0.header.source_label, "test.js");
}

#[test]
fn ir0_canonical_bytes_deterministic() {
    let a = make_ir0();
    let b = make_ir0();
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
}

#[test]
fn ir0_content_hash_deterministic() {
    let a = make_ir0();
    let b = make_ir0();
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn ir0_content_hash_changes_with_different_tree() {
    let ir0a = Ir0Module::from_syntax_tree(make_syntax_tree(), "a.js");
    let ir0b = Ir0Module::from_syntax_tree(make_module_syntax_tree(), "b.js");
    assert_ne!(ir0a.content_hash(), ir0b.content_hash());
}

#[test]
fn ir0_content_hash_changes_with_different_label() {
    let ir0a = Ir0Module::from_syntax_tree(make_syntax_tree(), "a.js");
    let ir0b = Ir0Module::from_syntax_tree(make_syntax_tree(), "b.js");
    assert_ne!(ir0a.content_hash(), ir0b.content_hash());
}

#[test]
fn ir0_serde_roundtrip() {
    let ir0 = make_ir0();
    let json = serde_json::to_string(&ir0).unwrap();
    let restored: Ir0Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir0, restored);
    // hash preserved after serde
    assert_eq!(ir0.content_hash(), restored.content_hash());
}

// ============================================================================
// 23. IR1 Module
// ============================================================================

#[test]
fn ir1_construction_sets_header() {
    let source_hash = ContentHash::compute(b"ir0-data");
    let ir1 = Ir1Module::new(source_hash.clone(), "mod.js");
    assert_eq!(ir1.header.level, IrLevel::Ir1);
    assert_eq!(ir1.header.source_hash, Some(source_hash));
    assert_eq!(ir1.header.source_label, "mod.js");
    assert!(ir1.scopes.is_empty());
    assert!(ir1.ops.is_empty());
}

#[test]
fn ir1_canonical_deterministic_with_content() {
    let src = ContentHash::compute(b"test");
    let a = make_ir1(src.clone());
    let b = make_ir1(src);
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn ir1_serde_roundtrip_with_scopes_and_ops() {
    let src = ContentHash::compute(b"test");
    let ir1 = make_ir1(src);
    let json = serde_json::to_string(&ir1).unwrap();
    let restored: Ir1Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir1, restored);
}

#[test]
fn ir1_different_ops_produce_different_hashes() {
    let src = ContentHash::compute(b"test");
    let mut a = Ir1Module::new(src.clone(), "test.js");
    a.ops.push(Ir1Op::Nop);
    let mut b = Ir1Module::new(src, "test.js");
    b.ops.push(Ir1Op::Return);
    assert_ne!(a.content_hash(), b.content_hash());
}

// ============================================================================
// 24. IR2 Module
// ============================================================================

#[test]
fn ir2_construction_sets_header() {
    let src = ContentHash::compute(b"ir1-data");
    let ir2 = Ir2Module::new(src.clone(), "cap.js");
    assert_eq!(ir2.header.level, IrLevel::Ir2);
    assert_eq!(ir2.header.source_hash, Some(src));
    assert!(ir2.ops.is_empty());
    assert!(ir2.required_capabilities.is_empty());
}

#[test]
fn ir2_canonical_deterministic() {
    let src = ContentHash::compute(b"test");
    let a = make_ir2(src.clone());
    let b = make_ir2(src);
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn ir2_serde_roundtrip() {
    let src = ContentHash::compute(b"test");
    let ir2 = make_ir2(src);
    let json = serde_json::to_string(&ir2).unwrap();
    let restored: Ir2Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir2, restored);
}

#[test]
fn ir2_different_effects_produce_different_hashes() {
    let src = ContentHash::compute(b"test");
    let mut a = Ir2Module::new(src.clone(), "test.js");
    a.ops.push(Ir2Op {
        inner: Ir1Op::Nop,
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
    });
    let mut b = Ir2Module::new(src, "test.js");
    b.ops.push(Ir2Op {
        inner: Ir1Op::Nop,
        effect: EffectBoundary::WriteEffect,
        required_capability: None,
        flow: None,
    });
    assert_ne!(a.content_hash(), b.content_hash());
}

// ============================================================================
// 25. IR3 Module
// ============================================================================

#[test]
fn ir3_construction_sets_header() {
    let src = ContentHash::compute(b"ir2-data");
    let ir3 = Ir3Module::new(src.clone(), "exec.js");
    assert_eq!(ir3.header.level, IrLevel::Ir3);
    assert_eq!(ir3.header.source_hash, Some(src));
    assert!(ir3.instructions.is_empty());
    assert!(ir3.constant_pool.is_empty());
    assert!(ir3.function_table.is_empty());
    assert!(ir3.specialization.is_none());
    assert!(ir3.required_capabilities.is_empty());
}

#[test]
fn ir3_canonical_deterministic() {
    let src = ContentHash::compute(b"test");
    let a = make_ir3(src.clone());
    let b = make_ir3(src);
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn ir3_serde_roundtrip() {
    let src = ContentHash::compute(b"test");
    let ir3 = make_ir3(src);
    let json = serde_json::to_string(&ir3).unwrap();
    let restored: Ir3Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir3, restored);
}

#[test]
fn ir3_with_specialization_serde_roundtrip() {
    let src = ContentHash::compute(b"test");
    let mut ir3 = make_ir3(src);
    ir3.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec!["p1".to_string(), "p2".to_string()],
        optimization_class: "inlining".to_string(),
        validity_epoch: 100,
        rollback_token: ContentHash::compute(b"base"),
    });
    let json = serde_json::to_string(&ir3).unwrap();
    let restored: Ir3Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir3, restored);
}

#[test]
fn ir3_with_capabilities_serde_roundtrip() {
    let src = ContentHash::compute(b"test");
    let mut ir3 = Ir3Module::new(src, "test.js");
    ir3.instructions.push(Ir3Instruction::HostCall {
        capability: CapabilityTag("fs:read".to_string()),
        args: RegRange { start: 0, count: 1 },
        dst: 2,
    });
    ir3.required_capabilities
        .push(CapabilityTag("fs:read".to_string()));
    let json = serde_json::to_string(&ir3).unwrap();
    let restored: Ir3Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir3, restored);
}

// ============================================================================
// 26. IR4 Module
// ============================================================================

#[test]
fn ir4_construction_sets_header() {
    let ir3h = ContentHash::compute(b"ir3-hash");
    let ir4 = Ir4Module::new(ir3h.clone(), "witness.js");
    assert_eq!(ir4.header.level, IrLevel::Ir4);
    assert_eq!(ir4.header.source_hash, Some(ir3h.clone()));
    assert_eq!(ir4.executed_ir3_hash, ir3h);
    assert_eq!(ir4.outcome, ExecutionOutcome::Completed);
    assert!(ir4.events.is_empty());
    assert!(ir4.hostcall_decisions.is_empty());
    assert_eq!(ir4.instructions_executed, 0);
    assert_eq!(ir4.duration_ticks, 0);
    assert!(ir4.active_specialization_ids.is_empty());
}

#[test]
fn ir4_canonical_deterministic() {
    let ir3h = ContentHash::compute(b"ir3");
    let a = make_ir4(ir3h.clone());
    let b = make_ir4(ir3h);
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn ir4_serde_roundtrip() {
    let ir3h = ContentHash::compute(b"ir3");
    let ir4 = make_ir4(ir3h);
    let json = serde_json::to_string(&ir4).unwrap();
    let restored: Ir4Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir4, restored);
}

#[test]
fn ir4_different_outcomes_produce_different_hashes() {
    let ir3h = ContentHash::compute(b"ir3");
    let mut a = Ir4Module::new(ir3h.clone(), "test.js");
    a.outcome = ExecutionOutcome::Completed;
    let mut b = Ir4Module::new(ir3h, "test.js");
    b.outcome = ExecutionOutcome::Exception;
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn ir4_all_outcome_variants_serde() {
    let ir3h = ContentHash::compute(b"ir3");
    for outcome in [
        ExecutionOutcome::Completed,
        ExecutionOutcome::Exception,
        ExecutionOutcome::Timeout,
        ExecutionOutcome::Halted,
    ] {
        let mut ir4 = Ir4Module::new(ir3h.clone(), "test.js");
        ir4.outcome = outcome;
        let json = serde_json::to_string(&ir4).unwrap();
        let restored: Ir4Module = serde_json::from_str(&json).unwrap();
        assert_eq!(ir4, restored);
    }
}

// ============================================================================
// 27. IrErrorCode
// ============================================================================

#[test]
fn ir_error_code_as_str_all_variants() {
    assert_eq!(
        IrErrorCode::SchemaVersionMismatch.as_str(),
        "IR_SCHEMA_VERSION_MISMATCH"
    );
    assert_eq!(IrErrorCode::LevelMismatch.as_str(), "IR_LEVEL_MISMATCH");
    assert_eq!(
        IrErrorCode::SourceHashMismatch.as_str(),
        "IR_SOURCE_HASH_MISMATCH"
    );
    assert_eq!(
        IrErrorCode::HashVerificationFailed.as_str(),
        "IR_HASH_VERIFICATION_FAILED"
    );
    assert_eq!(
        IrErrorCode::MissingCapabilityAnnotation.as_str(),
        "IR_MISSING_CAPABILITY_ANNOTATION"
    );
    assert_eq!(
        IrErrorCode::InvalidSpecializationLinkage.as_str(),
        "IR_INVALID_SPECIALIZATION_LINKAGE"
    );
    assert_eq!(
        IrErrorCode::WitnessIntegrityViolation.as_str(),
        "IR_WITNESS_INTEGRITY_VIOLATION"
    );
}

#[test]
fn ir_error_code_display_all_variants() {
    for code in [
        IrErrorCode::SchemaVersionMismatch,
        IrErrorCode::LevelMismatch,
        IrErrorCode::SourceHashMismatch,
        IrErrorCode::HashVerificationFailed,
        IrErrorCode::MissingCapabilityAnnotation,
        IrErrorCode::InvalidSpecializationLinkage,
        IrErrorCode::WitnessIntegrityViolation,
    ] {
        let display = format!("{}", code);
        assert_eq!(display, code.as_str());
    }
}

#[test]
fn ir_error_code_serde_roundtrip() {
    for code in [
        IrErrorCode::SchemaVersionMismatch,
        IrErrorCode::LevelMismatch,
        IrErrorCode::SourceHashMismatch,
        IrErrorCode::HashVerificationFailed,
        IrErrorCode::MissingCapabilityAnnotation,
        IrErrorCode::InvalidSpecializationLinkage,
        IrErrorCode::WitnessIntegrityViolation,
    ] {
        let json = serde_json::to_string(&code).unwrap();
        let restored: IrErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, restored);
    }
}

// ============================================================================
// 28. IrError
// ============================================================================

#[test]
fn ir_error_construction() {
    let err = IrError::new(
        IrErrorCode::LevelMismatch,
        "expected ir2, got ir3",
        IrLevel::Ir2,
    );
    assert_eq!(err.code, IrErrorCode::LevelMismatch);
    assert_eq!(err.message, "expected ir2, got ir3");
    assert_eq!(err.level, IrLevel::Ir2);
}

#[test]
fn ir_error_display_format() {
    let err = IrError::new(
        IrErrorCode::SchemaVersionMismatch,
        "expected 0.1.0",
        IrLevel::Ir1,
    );
    let display = err.to_string();
    assert!(display.contains("[ir1]"), "display={display}");
    assert!(
        display.contains("IR_SCHEMA_VERSION_MISMATCH"),
        "display={display}"
    );
    assert!(display.contains("expected 0.1.0"), "display={display}");
}

#[test]
fn ir_error_display_format_all_levels() {
    for level in [
        IrLevel::Ir0,
        IrLevel::Ir1,
        IrLevel::Ir2,
        IrLevel::Ir3,
        IrLevel::Ir4,
    ] {
        let err = IrError::new(IrErrorCode::LevelMismatch, "test", level);
        let display = err.to_string();
        assert!(
            display.contains(&format!("[{}]", level)),
            "display={display}"
        );
    }
}

#[test]
fn ir_error_is_std_error() {
    let err = IrError::new(
        IrErrorCode::HashVerificationFailed,
        "bad hash",
        IrLevel::Ir0,
    );
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
}

#[test]
fn ir_error_serde_roundtrip() {
    let err = IrError::new(
        IrErrorCode::WitnessIntegrityViolation,
        "non-monotonic seq",
        IrLevel::Ir4,
    );
    let json = serde_json::to_string(&err).unwrap();
    let restored: IrError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

// ============================================================================
// 29. error_code function
// ============================================================================

#[test]
fn error_code_function_returns_stable_strings() {
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
        assert_eq!(error_code(&err), *expected);
    }
}

// ============================================================================
// 30. Verification helpers — verify_ir0_hash
// ============================================================================

#[test]
fn verify_ir0_hash_passes_for_correct_hash() {
    let ir0 = make_ir0();
    let hash = ir0.content_hash();
    assert!(verify_ir0_hash(&ir0, &hash).is_ok());
}

#[test]
fn verify_ir0_hash_fails_for_wrong_hash() {
    let ir0 = make_ir0();
    let wrong = ContentHash::compute(b"wrong");
    let err = verify_ir0_hash(&ir0, &wrong).unwrap_err();
    assert_eq!(err.code, IrErrorCode::HashVerificationFailed);
    assert_eq!(err.level, IrLevel::Ir0);
    assert!(err.message.contains("mismatch"));
}

#[test]
fn verify_ir0_hash_different_trees_fail() {
    let ir0 = Ir0Module::from_syntax_tree(make_syntax_tree(), "a.js");
    let other = Ir0Module::from_syntax_tree(make_module_syntax_tree(), "b.js");
    let other_hash = other.content_hash();
    assert!(verify_ir0_hash(&ir0, &other_hash).is_err());
}

// ============================================================================
// 31. Verification helpers — verify_ir1_source
// ============================================================================

#[test]
fn verify_ir1_source_passes_for_matching_hash() {
    let ir0_hash = ContentHash::compute(b"ir0");
    let ir1 = Ir1Module::new(ir0_hash.clone(), "test.js");
    assert!(verify_ir1_source(&ir1, &ir0_hash).is_ok());
}

#[test]
fn verify_ir1_source_fails_for_wrong_hash() {
    let ir0_hash = ContentHash::compute(b"ir0");
    let ir1 = Ir1Module::new(ir0_hash, "test.js");
    let wrong = ContentHash::compute(b"wrong");
    let err = verify_ir1_source(&ir1, &wrong).unwrap_err();
    assert_eq!(err.code, IrErrorCode::SourceHashMismatch);
    assert_eq!(err.level, IrLevel::Ir1);
    assert!(err.message.contains("mismatch"));
}

#[test]
fn verify_ir1_source_fails_for_missing_source_hash() {
    // Construct an IR1 with source_hash = None manually
    let ir1 = Ir1Module {
        header: frankenengine_engine::ir_contract::IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir1,
            source_hash: None,
            source_label: "no-source.js".to_string(),
        },
        scopes: vec![],
        ops: vec![],
    };
    let expected = ContentHash::compute(b"something");
    let err = verify_ir1_source(&ir1, &expected).unwrap_err();
    assert_eq!(err.code, IrErrorCode::SourceHashMismatch);
    assert!(err.message.contains("missing"));
}

// ============================================================================
// 32. Verification helpers — verify_ir3_specialization
// ============================================================================

#[test]
fn verify_ir3_specialization_passes_when_none() {
    let src = ContentHash::compute(b"test");
    let ir3 = Ir3Module::new(src, "test.js");
    assert!(verify_ir3_specialization(&ir3).is_ok());
}

#[test]
fn verify_ir3_specialization_passes_for_valid_linkage() {
    let src = ContentHash::compute(b"test");
    let mut ir3 = Ir3Module::new(src, "test.js");
    ir3.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec!["proof-1".to_string()],
        optimization_class: "type_guard".to_string(),
        validity_epoch: 50,
        rollback_token: ContentHash::compute(b"baseline"),
    });
    assert!(verify_ir3_specialization(&ir3).is_ok());
}

#[test]
fn verify_ir3_specialization_fails_empty_proofs() {
    let src = ContentHash::compute(b"test");
    let mut ir3 = Ir3Module::new(src, "test.js");
    ir3.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec![],
        optimization_class: "type_guard".to_string(),
        validity_epoch: 1,
        rollback_token: ContentHash::compute(b"baseline"),
    });
    let err = verify_ir3_specialization(&ir3).unwrap_err();
    assert_eq!(err.code, IrErrorCode::InvalidSpecializationLinkage);
    assert_eq!(err.level, IrLevel::Ir3);
    assert!(err.message.contains("no proof inputs"));
}

#[test]
fn verify_ir3_specialization_fails_empty_optimization_class() {
    let src = ContentHash::compute(b"test");
    let mut ir3 = Ir3Module::new(src, "test.js");
    ir3.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec!["p1".to_string()],
        optimization_class: String::new(),
        validity_epoch: 1,
        rollback_token: ContentHash::compute(b"baseline"),
    });
    let err = verify_ir3_specialization(&ir3).unwrap_err();
    assert_eq!(err.code, IrErrorCode::InvalidSpecializationLinkage);
    assert!(err.message.contains("empty optimization_class"));
}

// ============================================================================
// 33. Verification helpers — verify_ir4_linkage
// ============================================================================

#[test]
fn verify_ir4_linkage_passes_correct_hash_monotonic_events() {
    let ir3h = ContentHash::compute(b"ir3");
    let ir4 = make_ir4(ir3h.clone());
    assert!(verify_ir4_linkage(&ir4, &ir3h).is_ok());
}

#[test]
fn verify_ir4_linkage_passes_empty_events() {
    let ir3h = ContentHash::compute(b"ir3");
    let ir4 = Ir4Module::new(ir3h.clone(), "test.js");
    assert!(verify_ir4_linkage(&ir4, &ir3h).is_ok());
}

#[test]
fn verify_ir4_linkage_passes_single_event() {
    let ir3h = ContentHash::compute(b"ir3");
    let mut ir4 = Ir4Module::new(ir3h.clone(), "test.js");
    ir4.events.push(WitnessEvent {
        seq: 0,
        kind: WitnessEventKind::ExecutionCompleted,
        instruction_index: 0,
        payload_hash: ContentHash::compute(b"done"),
        timestamp_tick: 1,
    });
    assert!(verify_ir4_linkage(&ir4, &ir3h).is_ok());
}

#[test]
fn verify_ir4_linkage_fails_wrong_hash() {
    let ir3h = ContentHash::compute(b"ir3");
    let ir4 = Ir4Module::new(ir3h, "test.js");
    let wrong = ContentHash::compute(b"wrong");
    let err = verify_ir4_linkage(&ir4, &wrong).unwrap_err();
    assert_eq!(err.code, IrErrorCode::WitnessIntegrityViolation);
    assert_eq!(err.level, IrLevel::Ir4);
    assert!(err.message.contains("IR4 witness references IR3 hash"));
}

#[test]
fn verify_ir4_linkage_fails_non_monotonic_events() {
    let ir3h = ContentHash::compute(b"ir3");
    let mut ir4 = Ir4Module::new(ir3h.clone(), "test.js");
    ir4.events.push(WitnessEvent {
        seq: 5,
        kind: WitnessEventKind::HostcallDispatched,
        instruction_index: 0,
        payload_hash: ContentHash::compute(b"a"),
        timestamp_tick: 100,
    });
    ir4.events.push(WitnessEvent {
        seq: 3, // non-monotonic
        kind: WitnessEventKind::CapabilityChecked,
        instruction_index: 1,
        payload_hash: ContentHash::compute(b"b"),
        timestamp_tick: 200,
    });
    let err = verify_ir4_linkage(&ir4, &ir3h).unwrap_err();
    assert_eq!(err.code, IrErrorCode::WitnessIntegrityViolation);
    assert!(err.message.contains("not monotonic"));
}

#[test]
fn verify_ir4_linkage_fails_equal_seq_numbers() {
    let ir3h = ContentHash::compute(b"ir3");
    let mut ir4 = Ir4Module::new(ir3h.clone(), "test.js");
    ir4.events.push(WitnessEvent {
        seq: 1,
        kind: WitnessEventKind::HostcallDispatched,
        instruction_index: 0,
        payload_hash: ContentHash::compute(b"a"),
        timestamp_tick: 100,
    });
    ir4.events.push(WitnessEvent {
        seq: 1, // equal, not strictly monotonic
        kind: WitnessEventKind::CapabilityChecked,
        instruction_index: 1,
        payload_hash: ContentHash::compute(b"b"),
        timestamp_tick: 200,
    });
    let err = verify_ir4_linkage(&ir4, &ir3h).unwrap_err();
    assert_eq!(err.code, IrErrorCode::WitnessIntegrityViolation);
}

// ============================================================================
// 34. Full pipeline hash chain
// ============================================================================

#[test]
fn full_pipeline_hash_chain_integrity() {
    let (ir0, ir1, _ir2, ir3, ir4) = build_full_pipeline();
    let ir0_hash = ir0.content_hash();
    let ir3_hash = ir3.content_hash();

    // IR1 source references IR0
    assert!(verify_ir1_source(&ir1, &ir0_hash).is_ok());

    // IR3 specialization is valid (None)
    assert!(verify_ir3_specialization(&ir3).is_ok());

    // IR4 references IR3
    assert!(verify_ir4_linkage(&ir4, &ir3_hash).is_ok());
}

#[test]
fn full_pipeline_all_hashes_distinct() {
    let (ir0, ir1, ir2, ir3, ir4) = build_full_pipeline();
    let hashes = [
        ir0.content_hash(),
        ir1.content_hash(),
        ir2.content_hash(),
        ir3.content_hash(),
        ir4.content_hash(),
    ];
    // all pairwise distinct
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "hash[{i}] == hash[{j}]");
        }
    }
}

#[test]
fn full_pipeline_deterministic_across_runs() {
    let hashes_a: Vec<ContentHash> = {
        let (ir0, ir1, ir2, ir3, ir4) = build_full_pipeline();
        vec![
            ir0.content_hash(),
            ir1.content_hash(),
            ir2.content_hash(),
            ir3.content_hash(),
            ir4.content_hash(),
        ]
    };
    let hashes_b: Vec<ContentHash> = {
        let (ir0, ir1, ir2, ir3, ir4) = build_full_pipeline();
        vec![
            ir0.content_hash(),
            ir1.content_hash(),
            ir2.content_hash(),
            ir3.content_hash(),
            ir4.content_hash(),
        ]
    };
    assert_eq!(hashes_a, hashes_b);
}

#[test]
fn full_pipeline_cross_level_linkage_mismatch_detected() {
    let (ir0, _ir1, _ir2, _ir3, ir4) = build_full_pipeline();
    // IR4 does not link to IR0 — should fail
    let ir0_hash = ir0.content_hash();
    let err = verify_ir4_linkage(&ir4, &ir0_hash).unwrap_err();
    assert_eq!(err.code, IrErrorCode::WitnessIntegrityViolation);
}

// ============================================================================
// 35. IrVerifier — structured events
// ============================================================================

#[test]
fn verifier_default_creates_empty() {
    let verifier = IrVerifier::default();
    let mut v = verifier;
    let events = v.drain_events();
    assert!(events.is_empty());
}

#[test]
fn verifier_verify_ir0_success_emits_ok_event() {
    let ir0 = make_ir0();
    let hash = ir0.content_hash();
    let mut verifier = IrVerifier::new();
    verifier.verify_ir0(&ir0, &hash, "trace-1").unwrap();
    let events = verifier.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "ok");
    assert_eq!(events[0].event, "ir0_hash_verified");
    assert_eq!(events[0].level, IrLevel::Ir0);
    assert_eq!(events[0].trace_id, "trace-1");
    assert_eq!(events[0].component, "ir_contract");
    assert!(events[0].content_hash.is_some());
    assert!(events[0].error_code.is_none());
}

#[test]
fn verifier_verify_ir0_failure_emits_error_event() {
    let ir0 = make_ir0();
    let wrong = ContentHash::compute(b"wrong");
    let mut verifier = IrVerifier::new();
    let result = verifier.verify_ir0(&ir0, &wrong, "trace-err");
    assert!(result.is_err());
    let events = verifier.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(
        events[0].error_code.as_deref(),
        Some("IR_HASH_VERIFICATION_FAILED")
    );
    assert!(events[0].content_hash.is_none());
}

#[test]
fn verifier_verify_ir1_success_emits_ok_event() {
    let ir0_hash = ContentHash::compute(b"ir0");
    let ir1 = Ir1Module::new(ir0_hash.clone(), "test.js");
    let mut verifier = IrVerifier::new();
    verifier.verify_ir1(&ir1, &ir0_hash, "t-ir1").unwrap();
    let events = verifier.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "ir1_source_verified");
    assert_eq!(events[0].level, IrLevel::Ir1);
    assert_eq!(events[0].outcome, "ok");
}

#[test]
fn verifier_verify_ir1_failure_emits_error_event() {
    let ir0_hash = ContentHash::compute(b"ir0");
    let ir1 = Ir1Module::new(ir0_hash, "test.js");
    let wrong = ContentHash::compute(b"wrong");
    let mut verifier = IrVerifier::new();
    let result = verifier.verify_ir1(&ir1, &wrong, "t-ir1-err");
    assert!(result.is_err());
    let events = verifier.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(
        events[0].error_code.as_deref(),
        Some("IR_SOURCE_HASH_MISMATCH")
    );
}

#[test]
fn verifier_verify_ir3_success_emits_ok_event() {
    let src = ContentHash::compute(b"ir2");
    let ir3 = Ir3Module::new(src, "test.js");
    let mut verifier = IrVerifier::new();
    verifier.verify_ir3(&ir3, "t-ir3").unwrap();
    let events = verifier.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "ir3_specialization_verified");
    assert_eq!(events[0].level, IrLevel::Ir3);
    assert_eq!(events[0].outcome, "ok");
}

#[test]
fn verifier_verify_ir3_failure_emits_error_event() {
    let src = ContentHash::compute(b"ir2");
    let mut ir3 = Ir3Module::new(src, "test.js");
    ir3.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec![],
        optimization_class: "x".to_string(),
        validity_epoch: 1,
        rollback_token: ContentHash::compute(b"base"),
    });
    let mut verifier = IrVerifier::new();
    let result = verifier.verify_ir3(&ir3, "t-ir3-err");
    assert!(result.is_err());
    let events = verifier.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(
        events[0].error_code.as_deref(),
        Some("IR_INVALID_SPECIALIZATION_LINKAGE")
    );
}

#[test]
fn verifier_verify_ir4_success_emits_ok_event() {
    let ir3h = ContentHash::compute(b"ir3");
    let ir4 = Ir4Module::new(ir3h.clone(), "test.js");
    let mut verifier = IrVerifier::new();
    verifier.verify_ir4(&ir4, &ir3h, "t-ir4").unwrap();
    let events = verifier.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "ir4_linkage_verified");
    assert_eq!(events[0].level, IrLevel::Ir4);
    assert_eq!(events[0].outcome, "ok");
}

#[test]
fn verifier_verify_ir4_failure_emits_error_event() {
    let ir3h = ContentHash::compute(b"ir3");
    let ir4 = Ir4Module::new(ir3h, "test.js");
    let wrong = ContentHash::compute(b"wrong");
    let mut verifier = IrVerifier::new();
    let result = verifier.verify_ir4(&ir4, &wrong, "t-ir4-err");
    assert!(result.is_err());
    let events = verifier.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(
        events[0].error_code.as_deref(),
        Some("IR_WITNESS_INTEGRITY_VIOLATION")
    );
}

#[test]
fn verifier_accumulates_multiple_events() {
    let ir0 = make_ir0();
    let ir0_hash = ir0.content_hash();

    let mut verifier = IrVerifier::new();

    // Success
    verifier.verify_ir0(&ir0, &ir0_hash, "multi").unwrap();

    // Failure
    let wrong = ContentHash::compute(b"wrong");
    let _ = verifier.verify_ir0(&ir0, &wrong, "multi");

    let events = verifier.drain_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].outcome, "ok");
    assert_eq!(events[1].outcome, "error");
}

#[test]
fn verifier_drain_clears_events() {
    let ir0 = make_ir0();
    let hash = ir0.content_hash();
    let mut verifier = IrVerifier::new();
    verifier.verify_ir0(&ir0, &hash, "drain-test").unwrap();
    let first = verifier.drain_events();
    assert_eq!(first.len(), 1);
    let second = verifier.drain_events();
    assert!(second.is_empty());
}

#[test]
fn verifier_full_pipeline_emits_four_ok_events() {
    let (ir0, ir1, _ir2, ir3, ir4) = build_full_pipeline();
    let ir0_hash = ir0.content_hash();
    let ir3_hash = ir3.content_hash();

    let mut verifier = IrVerifier::new();
    verifier.verify_ir0(&ir0, &ir0_hash, "full").unwrap();
    verifier.verify_ir1(&ir1, &ir0_hash, "full").unwrap();
    verifier.verify_ir3(&ir3, "full").unwrap();
    verifier.verify_ir4(&ir4, &ir3_hash, "full").unwrap();

    let events = verifier.drain_events();
    assert_eq!(events.len(), 4);
    assert!(events.iter().all(|e| e.outcome == "ok"));
    assert!(events.iter().all(|e| e.component == "ir_contract"));
    assert!(events.iter().all(|e| e.trace_id == "full"));

    let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    assert_eq!(event_names[0], "ir0_hash_verified");
    assert_eq!(event_names[1], "ir1_source_verified");
    assert_eq!(event_names[2], "ir3_specialization_verified");
    assert_eq!(event_names[3], "ir4_linkage_verified");
}

// ============================================================================
// 36. IrContractEvent serde
// ============================================================================

#[test]
fn ir_contract_event_serde_roundtrip_ok() {
    let ir0 = make_ir0();
    let hash = ir0.content_hash();
    let mut verifier = IrVerifier::new();
    verifier.verify_ir0(&ir0, &hash, "serde-rt").unwrap();
    let events = verifier.drain_events();
    let json = serde_json::to_string(&events).unwrap();
    let restored: Vec<IrContractEvent> = serde_json::from_str(&json).unwrap();
    assert_eq!(events, restored);
}

#[test]
fn ir_contract_event_serde_roundtrip_error() {
    let ir0 = make_ir0();
    let wrong = ContentHash::compute(b"wrong");
    let mut verifier = IrVerifier::new();
    let _ = verifier.verify_ir0(&ir0, &wrong, "serde-err");
    let events = verifier.drain_events();
    let json = serde_json::to_string(&events).unwrap();
    let restored: Vec<IrContractEvent> = serde_json::from_str(&json).unwrap();
    assert_eq!(events, restored);
}

// ============================================================================
// 37. IrHeader canonical
// ============================================================================

#[test]
fn ir_header_canonical_deterministic() {
    let ir0 = make_ir0();
    let cv1 = ir0.header.canonical_value();
    let cv2 = ir0.header.canonical_value();
    assert_eq!(cv1, cv2);
}

#[test]
fn ir_header_with_source_hash_canonical() {
    let src = ContentHash::compute(b"source");
    let ir1 = Ir1Module::new(src, "test.js");
    let cv1 = ir1.header.canonical_value();
    let cv2 = ir1.header.canonical_value();
    assert_eq!(cv1, cv2);
}

// ============================================================================
// 38. Edge cases
// ============================================================================

#[test]
fn empty_string_source_label() {
    let ir0 = Ir0Module::from_syntax_tree(make_syntax_tree(), "");
    assert_eq!(ir0.header.source_label, "");
    let json = serde_json::to_string(&ir0).unwrap();
    let restored: Ir0Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir0, restored);
}

#[test]
fn unicode_source_label() {
    let ir0 = Ir0Module::from_syntax_tree(make_syntax_tree(), "test-\u{1F600}.js");
    assert!(ir0.header.source_label.contains('\u{1F600}'));
    let json = serde_json::to_string(&ir0).unwrap();
    let restored: Ir0Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir0, restored);
}

#[test]
fn empty_ir1_module_serde_and_hash() {
    let src = ContentHash::compute(b"src");
    let ir1 = Ir1Module::new(src, "empty.js");
    assert!(ir1.scopes.is_empty());
    assert!(ir1.ops.is_empty());
    let json = serde_json::to_string(&ir1).unwrap();
    let restored: Ir1Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir1, restored);
    assert_eq!(ir1.content_hash(), restored.content_hash());
}

#[test]
fn empty_ir2_module_serde_and_hash() {
    let src = ContentHash::compute(b"src");
    let ir2 = Ir2Module::new(src, "empty.js");
    let json = serde_json::to_string(&ir2).unwrap();
    let restored: Ir2Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir2, restored);
    assert_eq!(ir2.content_hash(), restored.content_hash());
}

#[test]
fn empty_ir3_module_serde_and_hash() {
    let src = ContentHash::compute(b"src");
    let ir3 = Ir3Module::new(src, "empty.js");
    let json = serde_json::to_string(&ir3).unwrap();
    let restored: Ir3Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir3, restored);
    assert_eq!(ir3.content_hash(), restored.content_hash());
}

#[test]
fn empty_ir4_module_serde_and_hash() {
    let ir3h = ContentHash::compute(b"ir3");
    let ir4 = Ir4Module::new(ir3h, "empty.js");
    let json = serde_json::to_string(&ir4).unwrap();
    let restored: Ir4Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir4, restored);
    assert_eq!(ir4.content_hash(), restored.content_hash());
}

#[test]
fn ir1_many_scopes_nested() {
    let src = ContentHash::compute(b"src");
    let mut ir1 = Ir1Module::new(src, "nested.js");
    ir1.scopes.push(ScopeNode {
        scope_id: ScopeId { depth: 0, index: 0 },
        parent: None,
        kind: ScopeKind::Global,
        bindings: vec![],
    });
    ir1.scopes.push(ScopeNode {
        scope_id: ScopeId { depth: 1, index: 0 },
        parent: Some(ScopeId { depth: 0, index: 0 }),
        kind: ScopeKind::Function,
        bindings: vec![
            ResolvedBinding {
                name: "a".to_string(),
                binding_id: 0,
                scope: ScopeId { depth: 1, index: 0 },
                kind: BindingKind::Parameter,
            },
            ResolvedBinding {
                name: "b".to_string(),
                binding_id: 1,
                scope: ScopeId { depth: 1, index: 0 },
                kind: BindingKind::Parameter,
            },
        ],
    });
    ir1.scopes.push(ScopeNode {
        scope_id: ScopeId { depth: 2, index: 0 },
        parent: Some(ScopeId { depth: 1, index: 0 }),
        kind: ScopeKind::Block,
        bindings: vec![ResolvedBinding {
            name: "temp".to_string(),
            binding_id: 2,
            scope: ScopeId { depth: 2, index: 0 },
            kind: BindingKind::Let,
        }],
    });

    let json = serde_json::to_string(&ir1).unwrap();
    let restored: Ir1Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir1, restored);
    assert_eq!(ir1.content_hash(), restored.content_hash());
}

#[test]
fn ir3_large_constant_pool() {
    let src = ContentHash::compute(b"src");
    let mut ir3 = Ir3Module::new(src, "large-pool.js");
    for i in 0..100 {
        ir3.constant_pool.push(format!("string_{i}"));
    }
    let json = serde_json::to_string(&ir3).unwrap();
    let restored: Ir3Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir3, restored);
    assert_eq!(ir3.content_hash(), restored.content_hash());
}

#[test]
fn ir4_many_events_monotonic_verified() {
    let ir3h = ContentHash::compute(b"ir3");
    let mut ir4 = Ir4Module::new(ir3h.clone(), "many-events.js");
    for i in 0..50_u64 {
        ir4.events.push(WitnessEvent {
            seq: i,
            kind: WitnessEventKind::CapabilityChecked,
            instruction_index: i as u32,
            payload_hash: ContentHash::compute(format!("payload-{i}").as_bytes()),
            timestamp_tick: i * 10,
        });
    }
    assert!(verify_ir4_linkage(&ir4, &ir3h).is_ok());
}

#[test]
fn ir4_many_hostcall_decisions() {
    let ir3h = ContentHash::compute(b"ir3");
    let mut ir4 = Ir4Module::new(ir3h, "decisions.js");
    for i in 0..20_u64 {
        ir4.hostcall_decisions.push(HostcallDecisionRecord {
            seq: i,
            capability: CapabilityTag(format!("cap:{i}")),
            allowed: i.is_multiple_of(2),
            instruction_index: i as u32,
        });
    }
    let json = serde_json::to_string(&ir4).unwrap();
    let restored: Ir4Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir4, restored);
}

// ============================================================================
// 39. Cross-concern integration scenarios
// ============================================================================

#[test]
fn ir_level_matches_module_header() {
    let (ir0, ir1, ir2, ir3, ir4) = build_full_pipeline();
    assert_eq!(ir0.header.level, IrLevel::Ir0);
    assert_eq!(ir1.header.level, IrLevel::Ir1);
    assert_eq!(ir2.header.level, IrLevel::Ir2);
    assert_eq!(ir3.header.level, IrLevel::Ir3);
    assert_eq!(ir4.header.level, IrLevel::Ir4);
}

#[test]
fn all_modules_carry_current_schema_version() {
    let (ir0, ir1, ir2, ir3, ir4) = build_full_pipeline();
    assert_eq!(ir0.header.schema_version, IrSchemaVersion::CURRENT);
    assert_eq!(ir1.header.schema_version, IrSchemaVersion::CURRENT);
    assert_eq!(ir2.header.schema_version, IrSchemaVersion::CURRENT);
    assert_eq!(ir3.header.schema_version, IrSchemaVersion::CURRENT);
    assert_eq!(ir4.header.schema_version, IrSchemaVersion::CURRENT);
}

#[test]
fn ir0_is_only_module_without_source_hash() {
    let (ir0, ir1, ir2, ir3, ir4) = build_full_pipeline();
    assert!(ir0.header.source_hash.is_none());
    assert!(ir1.header.source_hash.is_some());
    assert!(ir2.header.source_hash.is_some());
    assert!(ir3.header.source_hash.is_some());
    assert!(ir4.header.source_hash.is_some());
}

#[test]
fn capability_tag_flows_from_ir2_to_ir3() {
    let src = ContentHash::compute(b"test");
    let mut ir2 = Ir2Module::new(src.clone(), "cap-flow.js");
    let cap = CapabilityTag("net:http".to_string());
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::Call { arg_count: 1 },
        effect: EffectBoundary::NetworkEffect,
        required_capability: Some(cap.clone()),
        flow: None,
    });
    ir2.required_capabilities.push(cap.clone());

    let ir2_hash = ir2.content_hash();
    let mut ir3 = Ir3Module::new(ir2_hash, "cap-flow.js");
    ir3.instructions.push(Ir3Instruction::HostCall {
        capability: cap.clone(),
        args: RegRange { start: 0, count: 1 },
        dst: 2,
    });
    ir3.required_capabilities.push(cap);

    assert_eq!(ir2.required_capabilities[0], ir3.required_capabilities[0]);
}

#[test]
fn specialization_linkage_with_multiple_proofs() {
    let src = ContentHash::compute(b"test");
    let mut ir3 = Ir3Module::new(src, "multi-proof.js");
    ir3.specialization = Some(SpecializationLinkage {
        proof_input_ids: vec![
            "proof-type-guard".to_string(),
            "proof-range-check".to_string(),
            "proof-escape-analysis".to_string(),
        ],
        optimization_class: "compound_specialization".to_string(),
        validity_epoch: 999,
        rollback_token: ContentHash::compute(b"compound-baseline"),
    });
    assert!(verify_ir3_specialization(&ir3).is_ok());
    let json = serde_json::to_string(&ir3).unwrap();
    let restored: Ir3Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir3, restored);
}

#[test]
fn ir4_witness_with_all_event_kinds() {
    let ir3h = ContentHash::compute(b"ir3");
    let mut ir4 = Ir4Module::new(ir3h.clone(), "all-events.js");
    let kinds = [
        WitnessEventKind::HostcallDispatched,
        WitnessEventKind::CapabilityChecked,
        WitnessEventKind::ExceptionRaised,
        WitnessEventKind::GcTriggered,
        WitnessEventKind::ExecutionCompleted,
        WitnessEventKind::FlowLabelChecked,
        WitnessEventKind::DeclassificationRequested,
    ];
    for (i, kind) in kinds.iter().enumerate() {
        ir4.events.push(WitnessEvent {
            seq: i as u64,
            kind: *kind,
            instruction_index: i as u32,
            payload_hash: ContentHash::compute(format!("ev-{i}").as_bytes()),
            timestamp_tick: (i as u64) * 100,
        });
    }
    assert!(verify_ir4_linkage(&ir4, &ir3h).is_ok());
    let json = serde_json::to_string(&ir4).unwrap();
    let restored: Ir4Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir4, restored);
}

#[test]
fn ir2_with_all_effect_boundaries() {
    let src = ContentHash::compute(b"test");
    let mut ir2 = Ir2Module::new(src, "effects.js");
    for eb in [
        EffectBoundary::Pure,
        EffectBoundary::ReadEffect,
        EffectBoundary::WriteEffect,
        EffectBoundary::NetworkEffect,
        EffectBoundary::FsEffect,
        EffectBoundary::HostcallEffect,
    ] {
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::Nop,
            effect: eb,
            required_capability: None,
            flow: None,
        });
    }
    assert_eq!(ir2.ops.len(), 6);
    let json = serde_json::to_string(&ir2).unwrap();
    let restored: Ir2Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir2, restored);
}

#[test]
fn ir2_flow_annotation_with_all_label_types() {
    let src = ContentHash::compute(b"test");
    let mut ir2 = Ir2Module::new(src, "labels.js");
    let labels = [
        Label::Public,
        Label::Internal,
        Label::Confidential,
        Label::Secret,
        Label::TopSecret,
    ];
    for label in &labels {
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::Nop,
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: Some(FlowAnnotation {
                data_label: label.clone(),
                sink_clearance: Label::Public,
                declassification_required: false,
            }),
        });
    }
    let json = serde_json::to_string(&ir2).unwrap();
    let restored: Ir2Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir2, restored);
}

#[test]
fn ir1_all_binding_kinds_in_one_module() {
    let src = ContentHash::compute(b"test");
    let mut ir1 = Ir1Module::new(src, "bindings.js");
    let scope = ScopeId { depth: 0, index: 0 };
    let kinds = [
        BindingKind::Let,
        BindingKind::Const,
        BindingKind::Var,
        BindingKind::Parameter,
        BindingKind::Import,
        BindingKind::FunctionDecl,
    ];
    let mut bindings = Vec::new();
    for (i, kind) in kinds.iter().enumerate() {
        bindings.push(ResolvedBinding {
            name: format!("binding_{i}"),
            binding_id: i as u32,
            scope,
            kind: *kind,
        });
    }
    ir1.scopes.push(ScopeNode {
        scope_id: scope,
        parent: None,
        kind: ScopeKind::Module,
        bindings,
    });
    let json = serde_json::to_string(&ir1).unwrap();
    let restored: Ir1Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir1, restored);
}

#[test]
fn ir3_multiple_functions_with_calls() {
    let src = ContentHash::compute(b"test");
    let mut ir3 = Ir3Module::new(src, "multi-fn.js");
    // Function 0: add(a, b) -> a + b
    ir3.instructions.push(Ir3Instruction::Add {
        dst: 2,
        lhs: 0,
        rhs: 1,
    });
    ir3.instructions.push(Ir3Instruction::Return { value: 2 });
    // Function 1: main() -> call add(10, 20)
    ir3.instructions
        .push(Ir3Instruction::LoadInt { dst: 0, value: 10 });
    ir3.instructions
        .push(Ir3Instruction::LoadInt { dst: 1, value: 20 });
    ir3.instructions
        .push(Ir3Instruction::LoadInt { dst: 2, value: 0 }); // callee ref
    ir3.instructions.push(Ir3Instruction::Call {
        callee: 2,
        args: RegRange { start: 0, count: 2 },
        dst: 3,
    });
    ir3.instructions.push(Ir3Instruction::Return { value: 3 });

    ir3.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 2,
        frame_size: 3,
        name: Some("add".to_string()),
    });
    ir3.function_table.push(Ir3FunctionDesc {
        entry: 2,
        arity: 0,
        frame_size: 4,
        name: Some("main".to_string()),
    });

    let json = serde_json::to_string(&ir3).unwrap();
    let restored: Ir3Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir3, restored);
    assert_eq!(ir3.content_hash(), restored.content_hash());
}

#[test]
fn ir3_control_flow_instructions() {
    let src = ContentHash::compute(b"test");
    let mut ir3 = Ir3Module::new(src, "control-flow.js");
    ir3.instructions.push(Ir3Instruction::LoadBool {
        dst: 0,
        value: true,
    });
    ir3.instructions
        .push(Ir3Instruction::JumpIf { cond: 0, target: 3 });
    ir3.instructions.push(Ir3Instruction::Jump { target: 4 });
    ir3.instructions
        .push(Ir3Instruction::LoadInt { dst: 1, value: 1 });
    ir3.instructions
        .push(Ir3Instruction::LoadInt { dst: 1, value: 0 });
    ir3.instructions.push(Ir3Instruction::Return { value: 1 });

    let json = serde_json::to_string(&ir3).unwrap();
    let restored: Ir3Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir3, restored);
}

#[test]
fn ir3_property_access_instructions() {
    let src = ContentHash::compute(b"test");
    let mut ir3 = Ir3Module::new(src, "props.js");
    ir3.instructions.push(Ir3Instruction::LoadNull { dst: 0 }); // obj
    ir3.instructions.push(Ir3Instruction::LoadStr {
        dst: 1,
        pool_index: 0,
    }); // key
    ir3.instructions
        .push(Ir3Instruction::LoadInt { dst: 2, value: 42 }); // value
    ir3.instructions.push(Ir3Instruction::SetProperty {
        obj: 0,
        key: 1,
        val: 2,
    });
    ir3.instructions.push(Ir3Instruction::GetProperty {
        obj: 0,
        key: 1,
        dst: 3,
    });
    ir3.instructions.push(Ir3Instruction::Halt);
    ir3.constant_pool.push("prop".to_string());

    let json = serde_json::to_string(&ir3).unwrap();
    let restored: Ir3Module = serde_json::from_str(&json).unwrap();
    assert_eq!(ir3, restored);
}

// ============================================================================
// 40. Determinism stress
// ============================================================================

#[test]
fn determinism_across_10_iterations() {
    let reference_hashes: Vec<ContentHash> = {
        let (ir0, ir1, ir2, ir3, ir4) = build_full_pipeline();
        vec![
            ir0.content_hash(),
            ir1.content_hash(),
            ir2.content_hash(),
            ir3.content_hash(),
            ir4.content_hash(),
        ]
    };
    for iteration in 0..10 {
        let (ir0, ir1, ir2, ir3, ir4) = build_full_pipeline();
        let hashes = vec![
            ir0.content_hash(),
            ir1.content_hash(),
            ir2.content_hash(),
            ir3.content_hash(),
            ir4.content_hash(),
        ];
        assert_eq!(
            hashes, reference_hashes,
            "mismatch on iteration {iteration}"
        );
    }
}

#[test]
fn canonical_bytes_deterministic_across_10_iterations() {
    let (ir0_ref, ir1_ref, ir2_ref, ir3_ref, ir4_ref) = build_full_pipeline();
    let ref_bytes = vec![
        ir0_ref.canonical_bytes(),
        ir1_ref.canonical_bytes(),
        ir2_ref.canonical_bytes(),
        ir3_ref.canonical_bytes(),
        ir4_ref.canonical_bytes(),
    ];
    for iteration in 0..10 {
        let (ir0, ir1, ir2, ir3, ir4) = build_full_pipeline();
        let bytes = vec![
            ir0.canonical_bytes(),
            ir1.canonical_bytes(),
            ir2.canonical_bytes(),
            ir3.canonical_bytes(),
            ir4.canonical_bytes(),
        ];
        assert_eq!(bytes, ref_bytes, "bytes mismatch on iteration {iteration}");
    }
}
