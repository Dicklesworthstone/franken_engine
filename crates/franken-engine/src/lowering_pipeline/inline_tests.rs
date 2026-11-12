use super::*;
use crate::ast::{
    ArrowBody, AssignmentOperator, BinaryOperator, BindingPattern, BlockStatement, BreakStatement,
    CatchClause, ContinueStatement, DoWhileStatement, ExportDeclaration, ExportKind, Expression,
    ExpressionStatement, ForInStatement, ForOfStatement, ForStatement, FunctionDeclaration,
    FunctionParam, IfStatement, ImportDeclaration, LabeledStatement, MethodDefinition, MethodKind,
    ObjectPatternProperty, ObjectProperty, ParseGoal, ReturnStatement, SourceSpan, Statement,
    SwitchCase, SwitchStatement, SyntaxTree, ThrowStatement, TryCatchStatement, UnaryOperator,
    VariableDeclaration, VariableDeclarationKind, VariableDeclarator, WhileStatement,
};
use crate::parser_gap_inventory::{ParserGapSiteId, UnsupportedSyntaxDiagnostic};

fn span() -> SourceSpan {
    SourceSpan::new(0, 1, 1, 1, 1, 2)
}

// bd-9vouw.1: every flow annotation is clamped to the lowering unit's
// label ceiling (`ir2_flow_label_ceiling`). A fixture with no sensitive
// source is bounded at Internal, which hides the simulator's own fail-high
// rules that several tests pin. These opaque sources keep the ceiling at
// TopSecret so those rules stay observable with unchanged assertions. They
// run before, and outside, every protected region or flow under test.

/// Source prefix: an unsummarized dynamic hostcall.
const OPAQUE_CEILING_SOURCE: &str = "hostcall('fixture.opaque'); ";

/// IR1 prefix: an opaque module load (code outside this IR).
fn push_opaque_ceiling_source(ops: &mut Vec<Ir1Op>) {
    ops.push(Ir1Op::ImportModule {
        import_attributes: Default::default(),
        specifier: "./fixture_opaque.js".into(),
    });
    ops.push(Ir1Op::Pop);
}

// bd-9vouw.19: a literal's text is not a label source, so a fixture's
// secret comes from a real one: an entropy read, whose RandomRead result
// contract floors the value at Secret. It pushes one value, like the
// keyword literal it replaces. Its host exceptions are Internal under
// ProviderInternal provenance and fail high under Unknown
// (`hostcall_flow_label_ceiling`).
fn secret_source_op() -> Ir1Op {
    Ir1Op::HostCall {
        capability: "random_read".to_string(),
        arg_count: 0,
    }
}

/// A Secret string, as the keyword string literals these fixtures used to
/// load: `crypto.randomUUID()`, whose result the flow analysis knows is a
/// primitive. A finite operation on it (a string method, a crypto input)
/// joins its Secret label, where an opaque `random_read` value fails high.
fn secret_string_op() -> Ir1Op {
    Ir1Op::HostCall {
        capability: "builtin:CryptoRandomUUID".to_string(),
        arg_count: 0,
    }
}

/// The flow annotation of the first HostCall with `capability` (a
/// fixture's secret source is a HostCall too, so "the first HostCall" is
/// ambiguous).
fn hostcall_flow<'a>(
    ir2: &'a Ir2Module,
    capability: &str,
) -> Option<&'a crate::ir_contract::FlowAnnotation> {
    ir2.ops
        .iter()
        .find(|op| {
            matches!(&op.inner, Ir1Op::HostCall { capability: found, .. } if found == capability)
        })
        .and_then(|op| op.flow.as_ref())
}

fn script_ir0() -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(42),
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "fixture.js")
}

#[test]
fn lowering_rejects_backversioned_derived_constructor_ops_bd_ppfz7() {
    let source_hash = ContentHash::compute(b"engine-derived-lowering-schema");
    let legacy_version = crate::ir_contract::IrSchemaVersion {
        major: 0,
        minor: 7,
        patch: 0,
    };

    let mut malformed_ir1 = Ir1Module::new(source_hash, "legacy-derived-ir1.js");
    malformed_ir1.header.schema_version = legacy_version;
    malformed_ir1.ops = vec![Ir1Op::ConstructSuper { arg_count: 0 }];
    assert!(lower_ir1_to_ir2(&malformed_ir1).is_err());

    let inner = Ir1Op::RegisterDerivedConstructor {
        default_constructor: false,
    };
    let (effect, required_capability, flow) = classify_ir1_op(&inner);
    let mut malformed_ir2 = Ir2Module::new(source_hash, "legacy-derived-ir2.js");
    malformed_ir2.header.schema_version = legacy_version;
    malformed_ir2.ops = vec![Ir2Op {
        inner,
        effect,
        required_capability,
        flow,
        span: None,
    }];
    assert!(lower_ir2_to_ir3(&malformed_ir2).is_err());

    let mut legacy_ir1 = Ir1Module::new(source_hash, "legacy-ir1.js");
    legacy_ir1.header.schema_version = legacy_version;
    legacy_ir1.ops = vec![
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Return,
    ];
    let legacy_ir2 = lower_ir1_to_ir2(&legacy_ir1)
        .expect("legacy IR1 without newer operations should lower")
        .module;
    assert_eq!(legacy_ir2.header.schema_version, legacy_version);
    let legacy_ir3 = lower_ir2_to_ir3(&legacy_ir2)
        .expect("legacy IR2 without newer operations should lower")
        .module;
    assert_eq!(legacy_ir3.header.schema_version, legacy_version);
}

#[test]
fn bd_qsiov_exec_file_request_label_excludes_only_callable_callbacks() {
    let exec_file_inputs = |source_arguments: Vec<(Label, FlowValueShape)>| {
        let mut inputs = source_arguments
            .into_iter()
            .enumerate()
            .rev()
            .map(|(identity, (label, shape))| FlowValue {
                identity,
                label,
                crypto_origin: None,
                shape,
                process_operation: None,
                stream: None,
                fs_operation: None,
            })
            .collect::<Vec<_>>();
        inputs.push(FlowValue {
            identity: usize::MAX,
            label: Label::Public,
            crypto_origin: None,
            shape: FlowValueShape::Primitive,
            process_operation: Some(ChildProcessOperation::ExecFile),
            stream: None,
            fs_operation: None,
        });
        inputs
    };

    assert_eq!(
        process_spawn_request_label(&exec_file_inputs(vec![
            (Label::Public, FlowValueShape::Primitive),
            (Label::TopSecret, FlowValueShape::Callable),
        ])),
        Label::Public,
        "a callback in the args slot is not request data"
    );
    assert_eq!(
        process_spawn_request_label(&exec_file_inputs(vec![
            (Label::Public, FlowValueShape::Primitive),
            (Label::Secret, FlowValueShape::Unknown),
            (Label::TopSecret, FlowValueShape::Callable),
        ])),
        Label::Secret,
        "a callback in the options slot is not request data"
    );
    assert_eq!(
        process_spawn_request_label(&exec_file_inputs(vec![
            (Label::Public, FlowValueShape::Primitive),
            (Label::Internal, FlowValueShape::Unknown),
            (Label::Secret, FlowValueShape::Unknown),
            (Label::TopSecret, FlowValueShape::Callable),
        ])),
        Label::Secret,
        "the fourth callback is excluded from the three request fields"
    );
    assert_eq!(
        process_spawn_request_label(&exec_file_inputs(vec![
            (Label::Public, FlowValueShape::Primitive),
            (Label::Internal, FlowValueShape::Unknown),
            (Label::TopSecret, FlowValueShape::Unknown),
        ])),
        Label::TopSecret,
        "without a callback all three optional request positions are joined"
    );
}

#[test]
fn lower_ir0_to_ir1_emits_witness_and_scope() {
    let ir0 = script_ir0();
    let result = lower_ir0_to_ir1(&ir0).expect("IR0->IR1 should succeed");

    assert_eq!(result.witness.pass_id, "ir0_to_ir1");
    assert_eq!(result.module.header.level, IrLevel::Ir1);
    assert_eq!(result.module.scopes.len(), 1);
    assert!(!result.module.ops.is_empty());
    assert!(
        result
            .witness
            .invariant_checks
            .iter()
            .all(|check| check.passed)
    );
}

#[test]
fn lower_ir1_to_ir2_collects_capabilities_deterministically() {
    let ir0 = script_ir0();
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("IR0->IR1 should succeed")
        .module;
    let result = lower_ir1_to_ir2(&ir1).expect("IR1->IR2 should succeed");

    assert_eq!(result.witness.pass_id, "ir1_to_ir2");
    assert_eq!(result.module.header.level, IrLevel::Ir2);
    assert!(
        result
            .witness
            .invariant_checks
            .iter()
            .all(|check| check.passed)
    );
    assert!(
        result
            .witness
            .invariant_checks
            .iter()
            .any(|check| check.name == "ir2_static_flow_coverage_ratio")
    );
}

// ── Ir2Op span stamping (bd-fqlfw.1.5) ──────────────────────────────

fn span_for_test(line: u64) -> crate::ast::SourceSpan {
    crate::ast::SourceSpan::new(0, 10, line, 1, line, 11)
}

fn ir1_with_stack_valid_ops_and_spans(op_count: usize, op_spans: Vec<Ir1OpSpanEntry>) -> Ir1Module {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"span-stamping-ir0"), "spans.js");
    for index in 0..op_count {
        ir1.ops.push(if index == 0 {
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            }
        } else {
            Ir1Op::Nop
        });
    }
    ir1.op_spans = op_spans;
    ir1
}

#[test]
fn ir2_span_stamping_narrowest_range_wins_regardless_of_order() {
    // Outer entry covers [0, 3); inner covers [1, 2). Both recording
    // orders must yield the same result: the inner span on op 1, the
    // outer span on ops 0 and 2.
    for entries in [
        vec![
            Ir1OpSpanEntry {
                op_start: 1,
                op_end: 2,
                span: span_for_test(2),
            },
            Ir1OpSpanEntry {
                op_start: 0,
                op_end: 3,
                span: span_for_test(1),
            },
        ],
        vec![
            Ir1OpSpanEntry {
                op_start: 0,
                op_end: 3,
                span: span_for_test(1),
            },
            Ir1OpSpanEntry {
                op_start: 1,
                op_end: 2,
                span: span_for_test(2),
            },
        ],
    ] {
        let ir1 = ir1_with_stack_valid_ops_and_spans(3, entries);
        let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
        assert_eq!(ir2.ops[0].span, Some(span_for_test(1)));
        assert_eq!(ir2.ops[1].span, Some(span_for_test(2)));
        assert_eq!(ir2.ops[2].span, Some(span_for_test(1)));
    }
}

#[test]
fn ir2_span_stamping_clamps_out_of_bounds_entries() {
    let ir1 = ir1_with_stack_valid_ops_and_spans(
        2,
        vec![
            Ir1OpSpanEntry {
                op_start: 1,
                op_end: 99,
                span: span_for_test(7),
            },
            Ir1OpSpanEntry {
                op_start: 50,
                op_end: 60,
                span: span_for_test(8),
            },
        ],
    );
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    assert_eq!(ir2.ops[0].span, None);
    assert_eq!(ir2.ops[1].span, Some(span_for_test(7)));
}

#[test]
fn ir2_span_stamping_empty_table_leaves_all_spans_none() {
    let ir1 = ir1_with_stack_valid_ops_and_spans(3, Vec::new());
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    assert!(ir2.ops.iter().all(|op| op.span.is_none()));
}

#[test]
fn ir2_span_is_identity_neutral_for_hash_eq_and_serde() {
    // The span side-table and Ir2Op::span are diagnostic provenance:
    // content hashes, equality, and serialized bytes must be identical
    // with and without them (the bd-fqlfw.1.5 zero-churn contract).
    let spanned = ir1_with_stack_valid_ops_and_spans(
        2,
        vec![Ir1OpSpanEntry {
            op_start: 0,
            op_end: 2,
            span: span_for_test(3),
        }],
    );
    let unspanned = ir1_with_stack_valid_ops_and_spans(2, Vec::new());
    assert_eq!(spanned, unspanned);
    assert_eq!(spanned.content_hash(), unspanned.content_hash());
    assert_eq!(
        serde_json::to_string(&spanned).expect("serialize ir1"),
        serde_json::to_string(&unspanned).expect("serialize ir1"),
    );

    let ir2_spanned = lower_ir1_to_ir2(&spanned).expect("IR1->IR2").module;
    let ir2_unspanned = lower_ir1_to_ir2(&unspanned).expect("IR1->IR2").module;
    assert!(ir2_spanned.ops.iter().all(|op| op.span.is_some()));
    assert!(ir2_unspanned.ops.iter().all(|op| op.span.is_none()));
    assert_eq!(ir2_spanned, ir2_unspanned);
    assert_eq!(ir2_spanned.content_hash(), ir2_unspanned.content_hash());
    assert_eq!(
        serde_json::to_string(&ir2_spanned).expect("serialize ir2"),
        serde_json::to_string(&ir2_unspanned).expect("serialize ir2"),
    );
}

#[test]
fn expression_lowering_records_nested_span_table_entries() {
    // `obj.a.b` lowers the inner member (`obj.a`) before the outer one,
    // so the side-table must hold two same-start entries with the inner
    // (narrower) range recorded first and the outer range exactly one op
    // wider (the outer GetProperty). Distinct span values per nesting
    // level make narrowest-range-wins observable end-to-end in IR2.
    let inner_span = span_for_test(2);
    let outer_span = span_for_test(1);
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Member {
                object: Box::new(Expression::Member {
                    object: Box::new(Expression::Identifier("obj".to_string())),
                    property: Box::new(Expression::Identifier("a".to_string())),
                    computed: false,
                    span: Some(inner_span),
                }),
                property: Box::new(Expression::Identifier("b".to_string())),
                computed: false,
                span: Some(outer_span),
            },
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "nested_member.js");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0->IR1").module;
    assert_eq!(
        ir1.op_spans.len(),
        2,
        "expected inner+outer member entries, got {:?}",
        ir1.op_spans
    );
    let inner = ir1.op_spans[0];
    let outer = ir1.op_spans[1];
    assert_eq!(inner.span, inner_span, "inner entry recorded first");
    assert_eq!(outer.span, outer_span, "outer entry recorded second");
    assert_eq!(inner.op_start, outer.op_start);
    assert_eq!(outer.op_end, inner.op_end + 1);
    assert!(matches!(
        ir1.ops[outer.op_end - 1],
        Ir1Op::GetProperty { .. }
    ));

    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    for (i, op) in ir2
        .ops
        .iter()
        .enumerate()
        .take(inner.op_end)
        .skip(inner.op_start)
    {
        assert_eq!(
            op.span,
            Some(inner_span),
            "inner-member op {i} must carry the narrower inner span"
        );
    }
    assert_eq!(
        ir2.ops[outer.op_end - 1].span,
        Some(outer_span),
        "the outer GetProperty must carry the outer member's span"
    );
}

#[test]
fn lower_ir1_to_ir2_zero_flow_ops_reports_zero_static_coverage() {
    let ir1 = Ir1Module::new(ContentHash::compute(b"zero-flow-ir0"), "zero_flow.js");
    let result = lower_ir1_to_ir2(&ir1).expect("IR1->IR2 should succeed");
    let coverage = result
        .witness
        .invariant_checks
        .iter()
        .find(|check| check.name == "ir2_static_flow_coverage_ratio")
        .expect("coverage check should be present");

    assert!(coverage.passed);
    assert!(coverage.detail.contains("static_coverage_millionths=0"));
    assert!(coverage.detail.contains("total_flow_ops=0"));
}

#[test]
fn lower_ir2_to_ir3_produces_exec_instructions() {
    let ir0 = script_ir0();
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("IR0->IR1 should succeed")
        .module;
    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("IR1->IR2 should succeed")
        .module;
    let result = lower_ir2_to_ir3(&ir2).expect("IR2->IR3 should succeed");

    assert_eq!(result.witness.pass_id, "ir2_to_ir3");
    assert_eq!(result.module.header.level, IrLevel::Ir3);
    assert!(!result.module.instructions.is_empty());
    assert!(matches!(
        result.module.instructions.last(),
        Some(Ir3Instruction::Halt)
    ));
    assert!(
        result
            .witness
            .invariant_checks
            .iter()
            .all(|check| check.passed)
    );
}

#[test]
fn lower_ir2_to_ir3_resolves_jump_if_falsy_targets() {
    let mut ir2 = Ir2Module::new(ContentHash::compute(b"jump-if-falsy"), "jump_if_falsy.js");
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::LoadLiteral {
            value: Ir1Literal::Boolean(false),
        },
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::JumpIfFalsy { label_id: 7 },
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(1),
        },
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::Return,
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::Label { id: 7 },
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(2),
        },
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::Return,
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });

    let ir3 = lower_ir2_to_ir3(&ir2)
        .expect("IR2->IR3 should resolve conditional control-flow")
        .module;

    // The condition value (`LoadBool false`) lands in register 1, not 0:
    // module-level binding/temporary allocation starts at register 1 because
    // r0 is reserved for the script completion value (bd-fqlfw.2.11.1). The
    // jump TARGETS (instruction indices 3 and 5) are unaffected by register
    // numbering. (bd-8zvfi: this assertion's `cond: 0` was the stale engine
    // twin of bd-7duxc after the register-0 reservation landed.)
    assert!(matches!(
        ir3.instructions.get(1),
        Some(Ir3Instruction::JumpIf { cond: 1, target: 3 })
    ));
    assert!(matches!(
        ir3.instructions.get(2),
        Some(Ir3Instruction::Jump { target: 5 })
    ));
    assert!(
        ir3.instructions
            .iter()
            .all(|instruction| match instruction {
                Ir3Instruction::Jump { target }
                | Ir3Instruction::JumpIf { target, .. }
                | Ir3Instruction::JumpIfNullish { target, .. } => {
                    *target != 0
                }
                _ => true,
            })
    );
}

#[test]
fn lower_ir2_to_ir3_rejects_missing_jump_labels() {
    let mut ir2 = Ir2Module::new(ContentHash::compute(b"missing-label"), "missing_label.js");
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::Jump { label_id: 42 },
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });

    let err = lower_ir2_to_ir3(&ir2).expect_err("missing label should fail closed");
    assert_eq!(
        err,
        LoweringPipelineError::InvariantViolation {
            detail: "lowered control-flow references missing label",
        }
    );
}

#[test]
fn lower_ir2_to_ir3_emits_begin_try_end_try_instructions() {
    let mut ir2 = Ir2Module::new(ContentHash::compute(b"begin-try"), "begin_try.js");
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::BeginTry {
            catch_label: 1,
            finally_label: None,
        },
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(9),
        },
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::EndTry,
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::Label { id: 1 },
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::Return,
        effect: EffectBoundary::Pure,
        required_capability: None,
        flow: None,
        span: None,
    });

    let ir3 = lower_ir2_to_ir3(&ir2)
        .expect("IR2->IR3 should emit BeginTry/EndTry instructions")
        .module;

    assert!(matches!(
        ir3.instructions.first(),
        Some(Ir3Instruction::BeginTry { .. })
    ));
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::EndTry))
    );
    // Catch label should produce an EnterCatch instruction
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::EnterCatch { .. }))
    );
}

#[test]
fn hermetic_http_hostcalls_accept_only_closed_or_summarized_inputs() {
    let mut next_identity = 0;
    let closed_options = fresh_shaped_flow_value(
        Label::Internal,
        FlowValueShape::FreshAggregate,
        &mut next_identity,
    );
    let callback = fresh_shaped_flow_value(
        Label::Internal,
        FlowValueShape::Callable,
        &mut next_identity,
    );
    let unknown =
        fresh_shaped_flow_value(Label::Internal, FlowValueShape::Unknown, &mut next_identity);

    for capability in [
        "builtin:HttpCreateServer",
        "builtin:HttpGet",
        "builtin:HttpRequest",
    ] {
        assert!(hostcall_exception_is_operand_derived(
            capability,
            &[closed_options.clone(), callback.clone()],
            HostIoExceptionProvenance::Unknown,
        ));
        assert!(!hostcall_exception_is_operand_derived(
            capability,
            std::slice::from_ref(&unknown),
            HostIoExceptionProvenance::Unknown,
        ));
    }
}

#[test]
fn protected_abort_registration_keeps_operand_labels_and_builtin_authority() {
    let mut next_identity = 0;
    let signal =
        fresh_shaped_flow_value(Label::Secret, FlowValueShape::Unknown, &mut next_identity);
    let callback = fresh_shaped_flow_value(
        Label::Internal,
        FlowValueShape::Callable,
        &mut next_identity,
    );
    let tag = "builtin:EventsAddAbortListener";
    assert!(hostcall_exception_is_operand_derived(
        tag,
        &[signal.clone(), callback],
        HostIoExceptionProvenance::Unknown,
    ));
    assert!(!hostcall_exception_is_operand_derived(
        tag,
        std::slice::from_ref(&signal),
        HostIoExceptionProvenance::Unknown,
    ));
    let row = crate::capability::hostcall_registry_row(tag).expect("private builtin registry");
    assert_eq!(
        row.authority,
        Some(crate::capability::RuntimeCapability::Builtin)
    );
    assert_eq!(
        row.result_contract.result_label(&Label::Secret, None),
        Label::Secret
    );
    assert!(!hostcall_exception_is_operand_derived(
        "fs:read",
        std::slice::from_ref(&signal),
        HostIoExceptionProvenance::Unknown,
    ));
}

#[test]
fn void_function_summary_uses_public_implicit_undefined_return() {
    let label = summarize_function_body(
        &[],
        &[],
        &[Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        }],
        &BTreeMap::new(),
        HostIoExceptionProvenance::Unknown,
        0,
    );

    assert_eq!(label, Label::Public);
}

#[test]
fn explicit_dynamic_hostcall_return_remains_fail_high() {
    let label = summarize_function_body(
        &[],
        &[],
        &[
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("secret_token".into()),
            },
            Ir1Op::HostCall {
                capability: "hostcall.invoke".to_string(),
                arg_count: 1,
            },
            Ir1Op::Return,
        ],
        &BTreeMap::new(),
        HostIoExceptionProvenance::Unknown,
        0,
    );

    assert_eq!(label, Label::TopSecret);
}

#[test]
fn dynamic_hostcall_paths_insert_runtime_ifc_guard() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "dynamic_flow.js");
    ir1.ops.push(secret_source_op());
    ir1.ops.push(Ir1Op::HostCall {
        capability: "hostcall.invoke".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("IR1->IR2 should succeed")
        .module;
    assert!(
        hostcall_flow(&ir2, "hostcall.invoke")
            .expect("flow annotation")
            .declassification_required
    );

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
    assert!(hostcall_caps.contains(&IFC_RUNTIME_GUARD_CAPABILITY));
    assert!(hostcall_caps.contains(&"hostcall.invoke"));

    let guard_index = ir3
        .instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                Ir3Instruction::HostCall { capability, .. }
                if capability.0 == IFC_RUNTIME_GUARD_CAPABILITY
            )
        })
        .expect("guard hostcall");
    let invoke_index = ir3
        .instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                Ir3Instruction::HostCall { capability, .. }
                if capability.0 == "hostcall.invoke"
            )
        })
        .expect("dynamic hostcall");
    assert!(guard_index < invoke_index);
}

fn nested_function_with_body(body_ops: Vec<Ir1Op>) -> Ir1Op {
    Ir1Op::CreateFunction {
        name: None,
        param_names: Vec::new(),
        body_ops,
        free_vars: Vec::new(),
        free_var_ids: Vec::new(),
        runtime_global_loads: Vec::new(),
        child_captured_locals: Vec::new(),
        local_lexical_bindings: Vec::new(),
        is_generator: false,
        is_async: false,
        is_arrow: false,
        rest_param_index: None,
        source_text: None,
        sloppy: false,
    }
}

#[test]
fn immediate_factory_authority_excludes_uninvoked_methods_and_generators() {
    let hostcall = |capability: &str| Ir1Op::HostCall {
        capability: capability.to_string(),
        arg_count: 0,
    };
    let mut generator = nested_function_with_body(vec![hostcall("timer")]);
    if let Ir1Op::CreateFunction { is_generator, .. } = &mut generator {
        *is_generator = true;
    }
    let nested_factory =
        nested_function_with_body(vec![hostcall("builtin:ObjectCreate"), Ir1Op::Return]);
    let ops = vec![
        nested_function_with_body(vec![
            hostcall("builtin:EventEmitterConstructorRef"),
            nested_function_with_body(vec![hostcall("timer")]),
            Ir1Op::Pop,
            generator,
            Ir1Op::Call { arg_count: 0 },
            Ir1Op::Pop,
            nested_factory,
            Ir1Op::Call { arg_count: 0 },
            Ir1Op::Return,
        ]),
        Ir1Op::Call { arg_count: 0 },
    ];
    let mut required = BTreeSet::new();
    collect_immediately_invoked_capabilities(&ops, &mut required);
    assert_eq!(
        required,
        BTreeSet::from([
            "builtin:EventEmitterConstructorRef".to_string(),
            "builtin:ObjectCreate".to_string(),
        ])
    );
}

#[test]
fn realm_value_authority_matches_runtime_without_claiming_lexical_shadows() {
    for (name, expected) in [("Object", "builtin"), ("setTimeout", "timer")] {
        let (_, capability, _) = classify_ir1_op(&Ir1Op::LoadName {
            name: name.to_string(),
            allow_missing: false,
        });
        assert_eq!(capability, Some(CapabilityTag(expected.to_string())));
    }
    assert_eq!(
        classify_ir1_op(&Ir1Op::LoadBinding { binding_id: 0 }).1,
        None
    );
    assert_eq!(
        classify_ir1_op(&Ir1Op::LoadName {
            name: "ordinaryGuestValue".to_string(),
            allow_missing: false,
        })
        .1,
        None
    );
}

#[test]
fn nested_dynamic_hostcall_inserts_runtime_ifc_guard_bd_wyazf() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"nested-dynamic-flow"),
        "nested_dynamic_flow.js",
    );
    ir1.ops.push(nested_function_with_body(vec![
        secret_source_op(),
        Ir1Op::HostCall {
            capability: "hostcall.invoke".to_string(),
            arg_count: 1,
        },
        Ir1Op::Return,
    ]));
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("nested dynamic IR1->IR2")
        .module;
    let ir3 = lower_ir2_to_ir3(&ir2)
        .expect("nested dynamic IR2->IR3")
        .module;
    let hostcall_caps: Vec<&str> = ir3
        .instructions
        .iter()
        .filter_map(|instruction| match instruction {
            Ir3Instruction::HostCall { capability, .. } => Some(capability.0.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        hostcall_caps.contains(&IFC_RUNTIME_GUARD_CAPABILITY),
        "nested hostcall.invoke must insert ifc.check_flow, got {hostcall_caps:?}"
    );
    assert!(hostcall_caps.contains(&"hostcall.invoke"));
    let guard_index = hostcall_caps
        .iter()
        .position(|cap| *cap == IFC_RUNTIME_GUARD_CAPABILITY)
        .expect("guard");
    let invoke_index = hostcall_caps
        .iter()
        .position(|cap| *cap == "hostcall.invoke")
        .expect("invoke");
    assert!(guard_index < invoke_index);

    let context = LoweringContext::new("trace-nested", "decision-nested", "policy-nested");
    let artifact = build_ir2_flow_proof_artifact(&ir2, &context).expect("nested flow artifact");
    assert!(
        artifact
            .runtime_checkpoints
            .iter()
            .any(|entry| { entry.capability.as_deref() == Some("hostcall.invoke") }),
        "artifact must record the nested dynamic hostcall checkpoint, got {:?}",
        artifact.runtime_checkpoints
    );
}

#[test]
fn nested_static_hostcall_skips_runtime_ifc_guard_bd_wyazf() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"nested-static-flow"),
        "nested_static_flow.js",
    );
    ir1.ops.push(nested_function_with_body(vec![
        Ir1Op::HostCall {
            capability: "promise:resolve".to_string(),
            arg_count: 0,
        },
        Ir1Op::Return,
    ]));
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("nested static IR1->IR2")
        .module;
    let ir3 = lower_ir2_to_ir3(&ir2)
        .expect("nested static IR2->IR3")
        .module;
    let hostcall_caps: Vec<&str> = ir3
        .instructions
        .iter()
        .filter_map(|instruction| match instruction {
            Ir3Instruction::HostCall { capability, .. } => Some(capability.0.as_str()),
            _ => None,
        })
        .collect();
    assert!(hostcall_caps.contains(&"promise:resolve"));
    assert!(
        !hostcall_caps.contains(&IFC_RUNTIME_GUARD_CAPABILITY),
        "public nested promise:resolve must not insert ifc.check_flow"
    );
}

#[test]
fn nested_multi_arg_hostcall_join_is_operand_order_invariant_bd_wyazf() {
    for secret_first in [true, false] {
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(b"nested-flow-order"),
            "nested_flow_order.js",
        );
        let mut body_ops = Vec::new();
        let public = Ir1Op::LoadLiteral {
            value: Ir1Literal::String("public-value".into()),
        };
        if secret_first {
            body_ops.extend([secret_source_op(), public]);
        } else {
            body_ops.extend([public, secret_source_op()]);
        }
        body_ops.push(Ir1Op::HostCall {
            capability: "net.write".to_string(),
            arg_count: 2,
        });
        body_ops.push(Ir1Op::Return);
        ir1.ops.push(nested_function_with_body(body_ops));
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("nested operand-aware IR1->IR2")
            .module;
        let annotated = annotate_nested_body_ops(
            nested_function_body_ops(&ir2.ops[0].inner).expect("nested body"),
            HostIoExceptionProvenance::Unknown,
            &ir2_flow_label_ceiling(&ir2.ops, HostIoExceptionProvenance::Unknown),
        )
        .expect("nested body flow");
        let flow = annotated
            .iter()
            .find(|op| {
                matches!(&op.inner, Ir1Op::HostCall { capability, .. } if capability == "net.write")
            })
            .and_then(|op| op.flow.as_ref())
            .expect("nested hostcall flow");
        assert_eq!(
            flow.data_label,
            Label::Secret,
            "secret_first={secret_first}"
        );
        assert!(
            flow.declassification_required,
            "secret_first={secret_first}"
        );

        let ir3 = lower_ir2_to_ir3(&ir2)
            .expect("nested guarded IR2->IR3")
            .module;
        assert!(
            ir3.instructions.iter().any(|instruction| matches!(
                instruction,
                Ir3Instruction::HostCall { capability, .. }
                    if capability.0 == IFC_RUNTIME_GUARD_CAPABILITY
            )),
            "Secret-vs-Public nested net.write must insert ifc.check_flow (secret_first={secret_first})"
        );
    }
}

#[test]
fn import_module_capability_survives_ir2_to_ir3_bd_iyp3h() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"module-import-capability"),
        "module_import_capability.js",
    );
    ir1.ops.push(Ir1Op::ImportModule {
        import_attributes: Default::default(),
        specifier: "./dependency.js".into(),
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("ImportModule should lower to IR2")
        .module;
    assert_eq!(
        ir2.required_capabilities,
        vec![CapabilityTag("module.import".to_string())]
    );

    let ir3 = lower_ir2_to_ir3(&ir2)
        .expect("ImportModule should lower to IR3")
        .module;
    assert_eq!(
        ir3.required_capabilities,
        vec![CapabilityTag("module.import".to_string())]
    );
    assert!(
        ir3.instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::ImportModule { .. }))
    );
}

#[test]
fn multi_argument_hostcall_flow_join_is_operand_order_invariant_bd_bscab() {
    for secret_first in [true, false] {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-order"), "flow_order.js");
        let public = Ir1Op::LoadLiteral {
            value: Ir1Literal::String("public-value".into()),
        };
        if secret_first {
            ir1.ops.extend([secret_source_op(), public]);
        } else {
            ir1.ops.extend([public, secret_source_op()]);
        }
        ir1.ops.push(Ir1Op::HostCall {
            capability: "net.write".to_string(),
            arg_count: 2,
        });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("operand-aware IR1 to IR2 lowering")
            .module;
        let flow = hostcall_flow(&ir2, "net.write").expect("hostcall flow annotation");
        assert_eq!(flow.data_label, Label::Secret);
        assert_eq!(flow.sink_clearance, Label::Public);
        assert!(flow.declassification_required);

        let ir3 = lower_ir2_to_ir3(&ir2)
            .expect("guarded IR2 to IR3 lowering")
            .module;
        assert!(ir3.instructions.iter().any(|instruction| matches!(
            instruction,
            Ir3Instruction::HostCall { capability, .. }
                if capability.0 == IFC_RUNTIME_GUARD_CAPABILITY
        )));
    }
}

#[test]
fn catch_flow_uses_protected_exception_provenance_bd_bscab() {
    let cases = [
        (
            "public-builtin-error",
            vec![],
            vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String("public-input".into()),
                },
                Ir1Op::HostCall {
                    capability: "builtin:CryptoCreateHash".to_string(),
                    arg_count: 1,
                },
                Ir1Op::Pop,
            ],
            Label::Internal,
            false,
        ),
        (
            "secret-explicit-throw",
            // The secret is read before the protected region, so only the
            // explicit throw (not the entropy read's own host exception)
            // can reach the handler.
            vec![
                secret_source_op(),
                Ir1Op::StoreBinding { binding_id: 90 },
                Ir1Op::Pop,
            ],
            vec![Ir1Op::LoadBinding { binding_id: 90 }, Ir1Op::Throw],
            Label::Secret,
            true,
        ),
        (
            "guest-callback-hostcall",
            vec![],
            vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String("public-callback".into()),
                },
                Ir1Op::HostCall {
                    capability: "builtin:ArrayPrototypeSome".to_string(),
                    arg_count: 1,
                },
                Ir1Op::Pop,
            ],
            Label::TopSecret,
            true,
        ),
    ];

    for (name, before_ops, protected_ops, expected_label, expected_declassification) in cases {
        let mut ir1 = Ir1Module::new(ContentHash::compute(name.as_bytes()), format!("{name}.js"));
        push_opaque_ceiling_source(&mut ir1.ops);
        ir1.ops.extend(before_ops);
        ir1.ops.push(Ir1Op::BeginTry {
            catch_label: 41,
            finally_label: None,
        });
        ir1.ops.extend(protected_ops);
        ir1.ops.push(Ir1Op::EndTry);
        ir1.ops.push(Ir1Op::Jump { label_id: 42 });
        ir1.ops.push(Ir1Op::Label { id: 41 });
        ir1.ops.push(Ir1Op::HostCall {
            capability: "console:log".to_string(),
            arg_count: 1,
        });
        ir1.ops.push(Ir1Op::Pop);
        ir1.ops.push(Ir1Op::Label { id: 42 });
        ir1.ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("catch flow inference must accept well-formed protected regions")
            .module;
        let console_flow = ir2
            .ops
            .iter()
            .find(|op| {
                matches!(
                    &op.inner,
                    Ir1Op::HostCall { capability, .. } if capability == "console:log"
                )
            })
            .and_then(|op| op.flow.as_ref())
            .expect("catch console flow annotation");
        assert_eq!(console_flow.data_label, expected_label, "{name}");
        assert_eq!(
            console_flow.declassification_required, expected_declassification,
            "{name}"
        );
    }
}

#[test]
fn product_catch_contracts_recover_only_finite_native_paths_bd_bscab() {
    let cases = [
        (
            "console_literal",
            "try { console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::Internal,
            false,
        ),
        (
            "buffer_alloc_negative",
            "try { Buffer.alloc(-1); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::Internal,
            false,
        ),
        (
            "os_set_priority",
            "const os = require('os'); try { os.setPriority(0, 1000); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::Internal,
            false,
        ),
        (
            "path_join",
            "const path = require('path'); try { path.join('a', 1); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::Internal,
            false,
        ),
        (
            "url_parse",
            "try { new URL('not a url'); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::Internal,
            false,
        ),
        (
            "zlib_gunzip_sync",
            "const zlib = require('zlib'); try { zlib.gunzipSync(Buffer.from('not gzip')); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::Internal,
            false,
        ),
        (
            "crypto_timing_safe_equal",
            "const crypto = require('crypto'); try { crypto.timingSafeEqual(Buffer.from('a'), Buffer.from('ab')); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::Internal,
            false,
        ),
        (
            "crypto_random_int",
            "const crypto = require('crypto'); try { crypto.randomInt(5, 5); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::Internal,
            false,
        ),
        (
            "crypto_invalid_hash",
            "const crypto = require('crypto'); try { crypto.createHash('not-a-real-hash'); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::Internal,
            false,
        ),
        (
            "secret_console_input",
            // bd-9vouw.19: the secret is an entropy read before the try.
            "const crypto = require('crypto'); const secret = crypto.randomUUID(); try { console.log(secret); } catch (error) { console.log(error); }",
            Label::Secret,
            true,
        ),
        (
            "unknown_console_input_stays_fail_high",
            "const value = {}; value.changed = true; try { console.log(value); } catch (error) { console.log(error); }",
            Label::TopSecret,
            true,
        ),
        (
            "fs_provider_error_stays_fail_high",
            "const fs = require('fs'); try { fs.readFileSync('missing', 'utf8'); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::TopSecret,
            true,
        ),
        (
            "buffer_instance_method_stays_fail_high",
            "try { Buffer.from('abc').toString('bogus'); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::TopSecret,
            true,
        ),
        (
            "url_object_input_stays_fail_high",
            "try { new URL({}); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::TopSecret,
            true,
        ),
        (
            "path_object_input_stays_fail_high",
            "const path = require('path'); try { path.join({}); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::TopSecret,
            true,
        ),
        (
            "os_object_input_stays_fail_high",
            "const os = require('os'); try { os.setPriority({}, 1); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::TopSecret,
            true,
        ),
        (
            "unknown_zlib_sync_input_stays_fail_high",
            "const zlib = require('zlib'); const input = Buffer.from('not gzip'); input.changed = true; try { zlib.gunzipSync(input); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::TopSecret,
            true,
        ),
        (
            "zlib_callback_stays_fail_high",
            "const zlib = require('zlib'); try { zlib.gunzip(Buffer.from('not gzip'), () => {}); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::TopSecret,
            true,
        ),
        (
            "object_unary_stays_fail_high",
            "try { -{}; console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::TopSecret,
            true,
        ),
        (
            "object_unary_plus_stays_fail_high",
            "try { +{}; console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::TopSecret,
            true,
        ),
        (
            "object_bitwise_not_stays_fail_high",
            "try { ~{}; console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::TopSecret,
            true,
        ),
        (
            "noncoercing_object_unary",
            "try { typeof {}; void {}; !{}; console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::Internal,
            false,
        ),
        (
            "primitive_numeric_unary",
            "try { +1; ~1; console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::Internal,
            false,
        ),
        (
            "coercing_unary_result_is_primitive",
            "const coerced = -{}; try { Buffer.from(coerced); console.log('no-throw'); } catch (error) { console.log(error); }",
            Label::Internal,
            false,
        ),
    ];

    for (name, source, expected_label, expected_declassification) in cases {
        // Fail-high cases pin the simulator's rule under a TopSecret
        // ceiling; precision cases keep their plain source.
        let source = if expected_label == Label::TopSecret {
            format!("{OPAQUE_CEILING_SOURCE}{source}")
        } else {
            source.to_string()
        };
        let tree = crate::parser_api_stability::parse_script(&source)
            .unwrap_or_else(|error| panic!("parse {name}: {error}"));
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("{name}_bd_bscab.js"));
        let ir1 = lower_ir0_to_ir1(&ir0)
            .unwrap_or_else(|error| panic!("lower {name} to IR1: {error}"))
            .module;
        let ir2 = lower_ir1_to_ir2(&ir1)
            .unwrap_or_else(|error| panic!("lower {name} to IR2: {error}"))
            .module;
        let catch_console_flow = ir2
            .ops
            .iter()
            .rev()
            .find(|op| {
                matches!(
                    &op.inner,
                    Ir1Op::HostCall { capability, .. } if capability == "console:log"
                )
            })
            .and_then(|op| op.flow.as_ref())
            .unwrap_or_else(|| panic!("catch console flow for {name}"));
        assert_eq!(catch_console_flow.data_label, expected_label, "{name}");
        assert_eq!(
            catch_console_flow.declassification_required, expected_declassification,
            "{name}"
        );
    }
}

#[test]
fn filesystem_catch_flow_uses_authenticated_provider_and_operand_provenance_bd_padqo() {
    fn catch_console_flow(
        name: &str,
        source: &str,
        provenance: HostIoExceptionProvenance,
    ) -> (Label, bool) {
        let tree = crate::parser_api_stability::parse_script(source)
            .unwrap_or_else(|error| panic!("parse {name}: {error}"));
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("{name}_bd_padqo.js"));
        let ir1 = lower_ir0_to_ir1(&ir0)
            .unwrap_or_else(|error| panic!("lower {name} to IR1: {error}"))
            .module;
        let ir2 = lower_ir1_to_ir2_with_host_io_exception_provenance(&ir1, provenance)
            .unwrap_or_else(|error| panic!("lower {name} to IR2: {error}"))
            .module;
        let flow = ir2
            .ops
            .iter()
            .rev()
            .find(|op| {
                matches!(
                    &op.inner,
                    Ir1Op::HostCall { capability, .. } if capability == "console:log"
                )
            })
            .and_then(|op| op.flow.as_ref())
            .unwrap_or_else(|| panic!("catch console flow for {name}"));
        (flow.data_label.clone(), flow.declassification_required)
    }

    let sync_public = "const fs = require('fs'); try { fs.readFileSync('missing', 'utf8'); } catch (error) { console.log(error); }";
    assert_eq!(
        catch_console_flow(
            "unknown_provider",
            sync_public,
            HostIoExceptionProvenance::Unknown,
        ),
        (Label::TopSecret, true),
        "an unauthenticated provider must retain the fail-high catch contract"
    );
    assert_eq!(
        catch_console_flow(
            "bounded_provider",
            sync_public,
            HostIoExceptionProvenance::ProviderInternal,
        ),
        (Label::Internal, false),
        "the canonical provider may expose its bounded Internal error state"
    );

    // bd-9vouw.19: the secret is an entropy read made before the protected
    // region (a literal's text is not a label source).
    let sync_secret = "const crypto = require('crypto'); const secretPath = crypto.randomUUID(); const fs = require('fs'); try { fs.readFileSync(secretPath, 'utf8'); } catch (error) { console.log(error); }";
    assert_eq!(
        catch_console_flow(
            "secret_path",
            sync_secret,
            HostIoExceptionProvenance::ProviderInternal,
        ),
        (Label::Secret, true),
        "provider authentication must not erase the direct path operand label"
    );

    let sync_secret_content = "const crypto = require('crypto'); const secret = crypto.randomUUID(); const fs = require('fs'); try { fs.writeFileSync('missing-parent/output.txt', secret); } catch (error) { console.log(error); }";
    assert_eq!(
        catch_console_flow(
            "secret_content",
            sync_secret_content,
            HostIoExceptionProvenance::ProviderInternal,
        ),
        (Label::Secret, true),
        "provider authentication must not erase the direct write-content label"
    );

    let callback = format!(
        "{OPAQUE_CEILING_SOURCE}const fs = require('fs'); try {{ fs.readFile('missing', () => {{}}); }} catch (error) {{ console.log(error); }}"
    );
    assert_eq!(
        catch_console_flow(
            "guest_callback",
            &callback,
            HostIoExceptionProvenance::ProviderInternal,
        ),
        (Label::TopSecret, true),
        "a guest callback remains fail-high even with the canonical provider"
    );
}

/// bd-zco6t: the numeric fd-lifecycle corpus fixtures must lower without
/// any UnauthorizedFlow under the canonical ProviderInternal provenance.
/// Before the fd result-shape rules, openSync's Unknown-shaped fd made
/// every later writeSync/readSync non-operand-derived: their TopSecret
/// exception contract poisoned the catch, and the shape invalidation
/// destroyed the Buffer proof `buf.toString('utf8')` depends on.
/// BufferObject is now retained through that invalidation so the
/// rewritten toString hostcall still authenticates after `fs.readSync`.
#[test]
fn fd_lifecycle_fixtures_lower_without_unauthorized_flow_bd_zco6t() {
    fn assert_flow_clean(name: &str, source: &str) {
        let tree = crate::parser_api_stability::parse_script(source)
            .unwrap_or_else(|error| panic!("parse {name}: {error}"));
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("{name}_bd_zco6t.js"));
        let ir1 = lower_ir0_to_ir1(&ir0)
            .unwrap_or_else(|error| panic!("lower {name} to IR1: {error}"))
            .module;
        if name == "fixture_0022_readsync" {
            assert_eq!(
                count_hostcall_deep(&ir1.ops, "builtin:BufferObjectToString"),
                1,
                "0022 must rewrite buf.toString after the intervening fd ops"
            );
        }
        let ir2 = lower_ir1_to_ir2_with_host_io_exception_provenance(
            &ir1,
            HostIoExceptionProvenance::ProviderInternal,
        )
        .unwrap_or_else(|error| panic!("lower {name} to IR2: {error}"))
        .module;
        let context =
            LoweringContext::new("trace-bd-zco6t", "decision-bd-zco6t", "policy-bd-zco6t");
        if let Err(error) = build_ir2_flow_proof_artifact(&ir2, &context) {
            panic!("{name} must lower without UnauthorizedFlow: {error}");
        }
        // The console sinks are the ops the isolate denied: every one of
        // them must carry at most Internal after the fd-lifecycle and
        // finite-observation fixes.
        for (index, op) in ir2.ops.iter().enumerate() {
            if let Ir1Op::HostCall { capability, .. } = &op.inner
                && capability == "console:log"
                && let Some(flow) = op.flow.as_ref()
            {
                assert!(
                    flow.data_label <= Label::Internal,
                    "{name} console sink at op {index} must not exceed Internal: {:?}",
                    flow.data_label
                );
            }
        }
    }

    // Corpus fixture 0022: BufferObject must survive intervening
    // GetProperty/CallMethod of `fs.readSync`/`closeSync`/`console.log`
    // so the rewritten `buf.toString` hostcall still authenticates.
    assert_flow_clean(
        "fixture_0022_readsync",
        "const fs = require('fs');\n\
         fs.writeFileSync('r.txt', 'abcdefgh');\n\
         const fd = fs.openSync('r.txt', 'r');\n\
         const buf = Buffer.alloc(4);\n\
         const n = fs.readSync(fd, buf, 0, 4, 2);\n\
         fs.closeSync(fd);\n\
         console.log(n);\n\
         console.log(buf.toString('utf8'));\n",
    );

    // The stale-fd probe: an operand-derived writeSync's EBADF is
    // Internal-join(operands), so the catch observation can sink at
    // Internal instead of denying TopSecret -> Internal.
    assert_flow_clean(
        "stale_fd_ebadf_catch",
        "const fs = require('fs');\n\
         const fd = fs.openSync('gone.txt', 'w');\n\
         fs.closeSync(fd);\n\
         try {\n\
           fs.writeSync(fd, 'late');\n\
           console.log('unreachable');\n\
         } catch (error) {\n\
           console.log('caught:' + (String(error).includes('EBADF')));\n\
         }\n",
    );
}

#[test]
fn caught_crypto_lifecycle_error_keeps_authenticated_provenance_bd_bscab() {
    let source = r#"
        const crypto = require('crypto');
        const cbcText = Buffer.from('0c276227d7db10379bfbb334ea96a5fc', 'hex');
        const bad = crypto.createDecipheriv(
            'aes-256-cbc',
            Buffer.alloc(32, 2),
            Buffer.alloc(16, 2),
        );
        try {
            bad.update(cbcText);
            bad.final();
        } catch (error) {
            console.log(error instanceof Error);
        }
    "#;
    let tree = crate::parser_api_stability::parse_script(source).expect("parse crypto script");
    let ir0 = Ir0Module::from_syntax_tree(tree, "caught_crypto_lifecycle_error.js");
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("crypto lifecycle source should lower to IR1")
        .module;
    assert_eq!(
        count_hostcall_deep(&ir1.ops, "builtin:CryptoObjectUpdate"),
        1
    );
    assert_eq!(
        count_hostcall_deep(&ir1.ops, "builtin:CryptoObjectFinal"),
        1
    );
    let ir2 = lower_ir1_to_ir2(&ir1).unwrap_or_else(|error| {
        panic!(
            "crypto lifecycle catch flow should remain finite: {error}; IR1={:#?}",
            ir1.ops
        )
    });
    let instanceof_flow = ir2
        .module
        .ops
        .iter()
        .find(|op| {
            matches!(
                &op.inner,
                Ir1Op::HostCall { capability, .. }
                    if capability == "builtin:instanceof:Error"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("caught error instanceof flow annotation");
    assert_eq!(instanceof_flow.data_label, Label::Internal);
    assert!(!instanceof_flow.declassification_required);
    let console_flow = ir2
        .module
        .ops
        .iter()
        .find(|op| {
            matches!(
                &op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "console:log"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("caught error console flow annotation");
    assert_eq!(console_flow.data_label, Label::Internal);
    assert!(!console_flow.declassification_required);
}

#[test]
fn catch_flow_excludes_abrupt_forwarder_finalizer_bd_bscab() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"catch-forwarder"),
        "catch_forwarder.js",
    );
    // bd-9vouw.19: the forwarder's secret is an entropy read made before
    // the protected region, so the assertion below still distinguishes a
    // forwarder throw that leaks into the catch (Secret) from one that
    // does not (Internal).
    ir1.ops.extend([
        secret_source_op(),
        Ir1Op::StoreBinding { binding_id: 95 },
        Ir1Op::Pop,
        Ir1Op::BeginTry {
            catch_label: 41,
            finally_label: Some(45),
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("sha256".into()),
        },
        Ir1Op::HostCall {
            capability: "builtin:CryptoCreateHash".to_string(),
            arg_count: 1,
        },
        Ir1Op::Pop,
        Ir1Op::Jump { label_id: 44 },
        Ir1Op::Label { id: 43 },
        Ir1Op::EndTry,
        Ir1Op::LoadBinding { binding_id: 95 },
        Ir1Op::Throw,
        Ir1Op::Label { id: 44 },
        Ir1Op::EndTry,
        Ir1Op::Jump { label_id: 42 },
        Ir1Op::Label { id: 41 },
        Ir1Op::HostCall {
            capability: "console:log".to_string(),
            arg_count: 1,
        },
        Ir1Op::Pop,
        Ir1Op::Jump { label_id: 42 },
        Ir1Op::Label { id: 45 },
        Ir1Op::EnterFinally,
        Ir1Op::EndFinally,
        Ir1Op::Label { id: 42 },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Return,
    ]);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("forwarder finalizer lies outside the catch provenance region")
        .module;
    let console_flow = ir2
        .ops
        .iter()
        .find(|op| {
            matches!(
                &op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "console:log"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("catch console flow annotation");
    assert_eq!(console_flow.data_label, Label::Internal);
    assert!(!console_flow.declassification_required);
}

#[test]
fn nested_catch_flow_distinguishes_swallow_from_rethrow_bd_bscab() {
    for (rethrow, expected_outer_label, expected_declassification) in
        [(false, Label::Internal, false), (true, Label::Secret, true)]
    {
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(if rethrow {
                b"nested-rethrow"
            } else {
                b"nested-swallow"
            }),
            "nested_catch.js",
        );
        // bd-9vouw.19: the secret is read before the protected regions.
        ir1.ops.extend([
            secret_source_op(),
            Ir1Op::StoreBinding { binding_id: 95 },
            Ir1Op::Pop,
            Ir1Op::BeginTry {
                catch_label: 90,
                finally_label: None,
            },
            Ir1Op::BeginTry {
                catch_label: 91,
                finally_label: None,
            },
            Ir1Op::LoadBinding { binding_id: 95 },
            Ir1Op::Throw,
            Ir1Op::EndTry,
            Ir1Op::Jump { label_id: 92 },
            Ir1Op::Label { id: 91 },
        ]);
        ir1.ops
            .push(if rethrow { Ir1Op::Throw } else { Ir1Op::Pop });
        ir1.ops.extend([
            Ir1Op::Label { id: 92 },
            Ir1Op::EndTry,
            Ir1Op::Jump { label_id: 93 },
            Ir1Op::Label { id: 90 },
            Ir1Op::HostCall {
                capability: "console:log".to_string(),
                arg_count: 1,
            },
            Ir1Op::Pop,
            Ir1Op::Label { id: 93 },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            },
            Ir1Op::Return,
        ]);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("nested catch provenance must remain stack balanced")
            .module;
        let console_flow = ir2
            .ops
            .iter()
            .find(|op| {
                matches!(
                    &op.inner,
                    Ir1Op::HostCall { capability, .. } if capability == "console:log"
                )
            })
            .and_then(|op| op.flow.as_ref())
            .expect("outer catch console flow annotation");
        assert_eq!(
            console_flow.data_label, expected_outer_label,
            "rethrow={rethrow}"
        );
        assert_eq!(
            console_flow.declassification_required, expected_declassification,
            "rethrow={rethrow}"
        );
    }
}

#[test]
fn deeply_nested_catch_events_remain_lifo_bd_bscab() {
    const DEPTH: u32 = 64;

    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"deep-catch-events"),
        "deep_catch_events.js",
    );
    for depth in 0..DEPTH {
        ir1.ops.push(Ir1Op::BeginTry {
            catch_label: 1_000 + depth,
            finally_label: None,
        });
    }
    ir1.ops.extend([
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Pop,
    ]);
    for depth in (0..DEPTH).rev() {
        ir1.ops.extend([
            Ir1Op::EndTry,
            Ir1Op::Jump {
                label_id: 2_000 + depth,
            },
            Ir1Op::Label { id: 1_000 + depth },
            Ir1Op::Pop,
            Ir1Op::Label { id: 2_000 + depth },
        ]);
    }
    ir1.ops.extend([
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Return,
    ]);

    lower_ir1_to_ir2(&ir1).expect("deeply nested catch metadata must terminate in LIFO order");
}

#[test]
fn flow_inference_budget_fails_closed_on_reverse_dependency_chain_bd_bscab() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"reverse-flow-chain"),
        "reverse_flow_chain.js",
    );
    for binding_id in 1..=20 {
        ir1.ops.extend([
            Ir1Op::LoadBinding {
                binding_id: binding_id + 1,
            },
            Ir1Op::StoreBinding { binding_id },
            Ir1Op::Pop,
        ]);
    }
    ir1.ops.extend([
        secret_source_op(),
        Ir1Op::StoreBinding { binding_id: 21 },
        Ir1Op::Pop,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Return,
    ]);

    let error = lower_ir1_to_ir2(&ir1).expect_err("inference must fail closed at its budget");
    assert!(matches!(
        error,
        LoweringPipelineError::InvariantViolation {
            detail: "IR2 flow-label inference exceeded its pass budget"
        }
    ));
}

#[test]
fn catch_metadata_rejects_malformed_regions_bd_bscab() {
    let cases = [
        (
            "duplicate-label",
            vec![
                Ir1Op::Label { id: 7 },
                Ir1Op::Label { id: 7 },
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined,
                },
                Ir1Op::Return,
            ],
            "lowered exception flow contains a duplicate label",
        ),
        (
            "missing-finally-only-target",
            vec![
                Ir1Op::BeginTry {
                    catch_label: 7,
                    finally_label: Some(7),
                },
                Ir1Op::EndTry,
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined,
                },
                Ir1Op::Return,
            ],
            "lowered try references missing catch label",
        ),
        (
            "reversed-catch-target",
            vec![
                Ir1Op::Label { id: 7 },
                Ir1Op::BeginTry {
                    catch_label: 7,
                    finally_label: None,
                },
                Ir1Op::EndTry,
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined,
                },
                Ir1Op::Return,
            ],
            "lowered catch label precedes its protected region",
        ),
        (
            "missing-end-try",
            vec![
                Ir1Op::BeginTry {
                    catch_label: 7,
                    finally_label: None,
                },
                Ir1Op::Jump { label_id: 8 },
                Ir1Op::Label { id: 7 },
                Ir1Op::Pop,
                Ir1Op::Label { id: 8 },
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined,
                },
                Ir1Op::Return,
            ],
            "lowered protected region has no EndTry marker",
        ),
    ];

    for (name, ops, expected_detail) in cases {
        let mut ir1 = Ir1Module::new(ContentHash::compute(name.as_bytes()), format!("{name}.js"));
        ir1.ops = ops;
        let error = lower_ir1_to_ir2(&ir1).expect_err("malformed catch metadata must fail");
        assert!(
            matches!(
                &error,
                LoweringPipelineError::InvariantViolation { detail }
                    if *detail == expected_detail
            ),
            "{name}: {error:?}"
        );
    }
}

#[test]
fn hostcall_flow_joins_only_consumed_operands_bd_bscab() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-slice"), "flow_slice.js");
    // bd-9vouw.19: the unconsumed value below the argument is a real
    // Secret (an entropy read); with a Public literal there, the
    // assertion below would hold even if the join read past its operands.
    ir1.ops.push(secret_source_op());
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("public-value".into()),
    });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "fs.read".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("operand-sliced IR1 to IR2 lowering")
        .module;
    let flow = hostcall_flow(&ir2, "fs.read").expect("hostcall flow annotation");
    assert_eq!(flow.data_label, Label::Public);
    assert!(!flow.declassification_required);
}

// -- bd-pafik: stream pipeline callback / Promise rejection provenance --

fn pafik_callback_fn(
    param_count: usize,
    body_ops: Vec<Ir1Op>,
    free: Vec<(String, BindingId)>,
) -> Ir1Op {
    Ir1Op::CreateFunction {
        name: None,
        param_names: (0..param_count).map(|index| format!("p{index}")).collect(),
        body_ops,
        free_vars: free.iter().map(|(name, _)| name.clone()).collect(),
        free_var_ids: free.iter().map(|(_, id)| *id).collect(),
        runtime_global_loads: Vec::new(),
        child_captured_locals: Vec::new(),
        local_lexical_bindings: Vec::new(),
        is_generator: false,
        is_async: false,
        is_arrow: false,
        rest_param_index: None,
        source_text: None,
        sloppy: false,
    }
}

/// Body of a well-behaved write callback: `callback(new Error("boom"))`.
fn pafik_reporting_callback_body() -> Vec<Ir1Op> {
    vec![
        Ir1Op::LoadBinding { binding_id: 2 },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("boom".into()),
        },
        Ir1Op::HostCall {
            capability: "builtin:Error".to_string(),
            arg_count: 1,
        },
        Ir1Op::Call { arg_count: 1 },
        Ir1Op::Return,
    ]
}

/// Module: construct a Writable sink (binding 0) from `sink_callback`, a
/// Readable source (binding 1), then `try { await pipeline(src, sink) }
/// catch (e)` storing the caught value into binding 2. Returns the IR2
/// data label of that catch-side StoreBinding.
fn pafik_pipeline_catch_label(sink_callback: Ir1Op, pipeline_stage_is_stream: bool) -> Label {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"bd-pafik"), "bd_pafik.js");
    push_opaque_ceiling_source(&mut ir1.ops);
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("write".into()),
    });
    ir1.ops.push(sink_callback);
    ir1.ops.push(Ir1Op::NewObject { count: 1 });
    if pipeline_stage_is_stream {
        ir1.ops.push(Ir1Op::HostCall {
            capability: "builtin:StreamWritable".to_string(),
            arg_count: 1,
        });
    }
    ir1.ops.push(Ir1Op::StoreBinding { binding_id: 0 });
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("chunk-a".into()),
    });
    ir1.ops.push(Ir1Op::NewArray { count: 1 });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "builtin:StreamReadableFrom".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::StoreBinding { binding_id: 1 });
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(Ir1Op::BeginTry {
        catch_label: 1,
        finally_label: None,
    });
    ir1.ops.push(Ir1Op::LoadBinding { binding_id: 1 });
    ir1.ops.push(Ir1Op::LoadBinding { binding_id: 0 });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "builtin:StreamPromisesPipeline".to_string(),
        arg_count: 2,
    });
    ir1.ops.push(Ir1Op::Await);
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(Ir1Op::EndTry);
    ir1.ops.push(Ir1Op::Jump { label_id: 2 });
    ir1.ops.push(Ir1Op::Label { id: 1 });
    ir1.ops.push(Ir1Op::StoreBinding { binding_id: 2 });
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(Ir1Op::Label { id: 2 });
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::Undefined,
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("bd-pafik pipeline module must lower")
        .module;
    let mut catch_store_labels = ir2
        .ops
        .iter()
        .enumerate()
        .filter(|(_, op)| matches!(op.inner, Ir1Op::StoreBinding { binding_id: 2 }))
        .map(|(index, op)| {
            (
                index,
                op.flow
                    .as_ref()
                    .expect("catch StoreBinding flow annotation")
                    .data_label
                    .clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(catch_store_labels.len(), 1, "exactly one catch store");
    catch_store_labels.pop().expect("catch store present").1
}

/// Link test: the pure options/constructor/pipeline resolution helpers,
/// with hand-built flow values (no simulator in the loop).
#[test]
fn stream_authentication_helpers_resolve_supported_chain_bd_pafik() {
    let mut next_identity = 0usize;
    // The options object's VALUE label carries the bd-qjh7y JoinInputs
    // poison (the callback function value's fail-high return summary);
    // the authenticated summary must not re-import it.
    let mut options = fresh_shaped_flow_value(
        Label::TopSecret,
        FlowValueShape::CallableContainer,
        &mut next_identity,
    );
    options.stream = Some(StreamFlowInfo::CallbackCarrier(
        StreamCallbackSummary::Supported(Label::Internal),
    ));
    assert_eq!(
        stream_constructor_summary(std::slice::from_ref(&options), &Label::TopSecret),
        StreamCallbackSummary::Supported(Label::Internal)
    );
    let mut carrierless = fresh_flow_value(Label::Internal, &mut next_identity);
    assert_eq!(
        stream_constructor_summary(std::slice::from_ref(&carrierless), &Label::Internal),
        StreamCallbackSummary::Unsupported
    );
    carrierless.stream = Some(StreamFlowInfo::CallbackCarrier(
        StreamCallbackSummary::Unsupported,
    ));
    assert_eq!(
        stream_constructor_summary(std::slice::from_ref(&carrierless), &Label::Internal),
        StreamCallbackSummary::Unsupported
    );

    let mut states = BTreeMap::new();
    states.insert(3usize, StreamCallbackSummary::Supported(Label::Internal));
    states.insert(8usize, StreamCallbackSummary::Supported(Label::Public));
    // Stage VALUES may carry poisoned JoinInputs labels; only the
    // authenticated per-stage summaries flow into the rejection.
    let mut sink = fresh_flow_value(Label::TopSecret, &mut next_identity);
    sink.stream = Some(StreamFlowInfo::Stream { origin: 3 });
    let mut source = fresh_flow_value(Label::TopSecret, &mut next_identity);
    source.stream = Some(StreamFlowInfo::Stream { origin: 8 });
    assert_eq!(
        stream_pipeline_rejection(&[sink.clone(), source.clone()], &states),
        Some(Label::Internal)
    );
    let plain = fresh_flow_value(Label::Internal, &mut next_identity);
    assert_eq!(stream_pipeline_rejection(&[sink, plain], &states), None);
    assert_eq!(stream_pipeline_rejection(&[], &states), None);
}

/// Link test: the pipeline HOSTCALL's own exception override (no Await in
/// the region). If this passes while the Await test fails, the break is
/// on the Await side; if this fails, the break is in constructor/options
/// authentication or the hostcall override.
#[test]
fn pipeline_hostcall_bounds_catch_without_await_bd_pafik() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"bd-pafik-noawait"), "bd_pafik_na.js");
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("write".into()),
    });
    ir1.ops.push(pafik_callback_fn(
        3,
        pafik_reporting_callback_body(),
        Vec::new(),
    ));
    ir1.ops.push(Ir1Op::NewObject { count: 1 });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "builtin:StreamWritable".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::StoreBinding { binding_id: 0 });
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(Ir1Op::BeginTry {
        catch_label: 1,
        finally_label: None,
    });
    ir1.ops.push(Ir1Op::LoadBinding { binding_id: 0 });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "builtin:StreamPromisesPipeline".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(Ir1Op::EndTry);
    ir1.ops.push(Ir1Op::Jump { label_id: 2 });
    ir1.ops.push(Ir1Op::Label { id: 1 });
    ir1.ops.push(Ir1Op::StoreBinding { binding_id: 2 });
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(Ir1Op::Label { id: 2 });
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::Undefined,
    });
    ir1.ops.push(Ir1Op::Return);
    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("bd-pafik no-await module must lower")
        .module;
    let label = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::StoreBinding { binding_id: 2 }))
        .and_then(|op| op.flow.as_ref())
        .expect("catch StoreBinding flow annotation")
        .data_label
        .clone();
    assert_ne!(label, Label::TopSecret);
    assert_eq!(
        label.join(&Label::Internal),
        Label::Internal,
        "authenticated pipeline hostcall must bound its own throw, got {label:?}"
    );
}

#[test]
fn pipeline_await_transfers_bounded_rejection_bd_pafik() {
    // A pipeline of authenticated streams whose only callback reports
    // errors through its engine continuation must not poison the catch
    // binding with TopSecret: the Await transfers the static rejection
    // summary instead. On the pre-bd-pafik simulator this label was
    // TopSecret (Await had no settlement provenance).
    let label = pafik_pipeline_catch_label(
        pafik_callback_fn(3, pafik_reporting_callback_body(), Vec::new()),
        true,
    );
    assert_ne!(label, Label::TopSecret);
    assert_eq!(
        label.join(&Label::Internal),
        Label::Internal,
        "public-data pipeline rejection must stay at the Internal floor, got {label:?}"
    );
}

#[test]
fn pipeline_with_unknown_stage_keeps_fail_high_bd_pafik() {
    // The same shape, but the sink stage is a plain object instead of an
    // authenticated stream: unknown stages keep the fail-high default.
    let label = pafik_pipeline_catch_label(
        pafik_callback_fn(3, pafik_reporting_callback_body(), Vec::new()),
        false,
    );
    assert_eq!(label, Label::TopSecret);
}

#[test]
fn pipeline_mutating_callback_keeps_fail_high_bd_pafik() {
    // A callback whose body mutates the heap has no supported summary
    // (mutation / alias escape fails high), so the pipeline rejection
    // stays TopSecret.
    let mutating_body = vec![
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("v".into()),
        },
        Ir1Op::LoadBinding { binding_id: 0 },
        Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static("k".into()),
            strict: true,
        },
        Ir1Op::Pop,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Return,
    ];
    let label = pafik_pipeline_catch_label(pafik_callback_fn(3, mutating_body, Vec::new()), true);
    assert_eq!(label, Label::TopSecret);
}

#[test]
fn pipeline_callback_capture_labels_flow_into_rejection_bd_pafik() {
    // A callback that throws a captured secret must surface at least that
    // secret's label on the catch binding (captured-labels correspondence).
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"bd-pafik-cap"), "bd_pafik_cap.js");
    // binding 3 holds a Secret (an entropy read, bd-9vouw.19); the
    // callback captures it.
    ir1.ops.push(secret_source_op());
    ir1.ops.push(Ir1Op::StoreBinding { binding_id: 3 });
    ir1.ops.push(Ir1Op::Pop);
    let capture_name = format!("{CAPTURE_CELL_NAME_PREFIX}3\0leak");
    let throwing_body = vec![
        Ir1Op::LoadBinding { binding_id: 7 },
        Ir1Op::Throw,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Return,
    ];
    let callback = pafik_callback_fn(3, throwing_body, vec![(capture_name, 7)]);
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("write".into()),
    });
    ir1.ops.push(callback);
    ir1.ops.push(Ir1Op::NewObject { count: 1 });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "builtin:StreamWritable".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::BeginTry {
        catch_label: 1,
        finally_label: None,
    });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "builtin:StreamPromisesPipeline".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::Await);
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(Ir1Op::EndTry);
    ir1.ops.push(Ir1Op::Jump { label_id: 2 });
    ir1.ops.push(Ir1Op::Label { id: 1 });
    ir1.ops.push(Ir1Op::StoreBinding { binding_id: 4 });
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(Ir1Op::Label { id: 2 });
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::Undefined,
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("bd-pafik capture module must lower")
        .module;
    let label = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::StoreBinding { binding_id: 4 }))
        .and_then(|op| op.flow.as_ref())
        .expect("catch StoreBinding flow annotation")
        .data_label
        .clone();
    assert_eq!(
        label.join(&Label::Secret),
        label,
        "captured Secret must reach the catch binding, got {label:?}"
    );
}

#[test]
fn stream_callback_summary_admissions_bd_pafik() {
    let labels = BTreeMap::new();
    // Reporting through the engine continuation is supported.
    assert_eq!(
        summarize_stream_callback_exceptions(
            3,
            None,
            &pafik_reporting_callback_body(),
            &[],
            &[],
            &BTreeSet::new(),
            &labels,
        ),
        StreamCallbackSummary::Supported(Label::Internal)
    );
    // Calling a data parameter (not the continuation) is not.
    let call_data_param = vec![
        Ir1Op::LoadBinding { binding_id: 0 },
        Ir1Op::Call { arg_count: 0 },
        Ir1Op::Return,
    ];
    assert_eq!(
        summarize_stream_callback_exceptions(
            3,
            None,
            &call_data_param,
            &[],
            &[],
            &BTreeSet::new(),
            &labels,
        ),
        StreamCallbackSummary::Unsupported
    );
    // Nested function creation (recursion vector) is not.
    let nested = vec![
        pafik_callback_fn(0, vec![Ir1Op::Return], Vec::new()),
        Ir1Op::Pop,
        Ir1Op::Return,
    ];
    assert_eq!(
        summarize_stream_callback_exceptions(3, None, &nested, &[], &[], &BTreeSet::new(), &labels,),
        StreamCallbackSummary::Unsupported
    );
    // A method call on a capture proven to be a fresh plain aggregate is
    // supported; on any other capture it is not.
    let push_on_capture = vec![
        Ir1Op::LoadBinding { binding_id: 9 },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("push".into()),
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("entry".into()),
        },
        Ir1Op::CallMethod { arg_count: 1 },
        Ir1Op::Return,
    ];
    let capture = [(format!("{CAPTURE_CELL_NAME_PREFIX}5\0events"), 9u32)];
    let free_ids = [9u32];
    let free_names = [capture[0].0.clone()];
    assert_eq!(
        summarize_stream_callback_exceptions(
            3,
            None,
            &push_on_capture,
            &free_ids,
            &free_names,
            &BTreeSet::from([9u32]),
            &labels,
        ),
        StreamCallbackSummary::Supported(Label::Internal)
    );
    assert_eq!(
        summarize_stream_callback_exceptions(
            3,
            None,
            &push_on_capture,
            &free_ids,
            &free_names,
            &BTreeSet::new(),
            &labels,
        ),
        StreamCallbackSummary::Unsupported
    );
}

#[test]
fn computed_values_preserve_nonfinal_secret_operands_bd_bscab() {
    let cases = [
        vec![
            secret_source_op(),
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-rhs".into()),
            },
            Ir1Op::BinaryOp {
                operator: BinaryOperator::Add,
            },
        ],
        vec![
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-callee".into()),
            },
            secret_string_op(),
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-arg".into()),
            },
            Ir1Op::CallMethod { arg_count: 1 },
        ],
    ];

    for (case_index, prefix) in cases.into_iter().enumerate() {
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(format!("computed-flow-{case_index}").as_bytes()),
            format!("computed_flow_{case_index}.js"),
        );
        ir1.ops.extend(prefix);
        ir1.ops.push(Ir1Op::HostCall {
            capability: "net.write".to_string(),
            arg_count: 1,
        });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("computed operand flow lowering")
            .module;
        let flow = hostcall_flow(&ir2, "net.write").expect("hostcall flow annotation");
        assert_eq!(flow.data_label, Label::Secret, "case {case_index}");
        assert!(flow.declassification_required, "case {case_index}");
    }
}

#[test]
fn aggregate_and_invocation_results_join_every_direct_input_bd_bscab() {
    let cases = [
        vec![
            secret_source_op(),
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-argument".into()),
            },
            Ir1Op::Call { arg_count: 1 },
        ],
        vec![
            secret_source_op(),
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-key".into()),
            },
            Ir1Op::GetProperty {
                key: Ir1PropertyKey::Dynamic,
            },
        ],
        vec![
            secret_source_op(),
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-element".into()),
            },
            Ir1Op::NewArray { count: 2 },
        ],
        vec![
            secret_source_op(),
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-value".into()),
            },
            Ir1Op::NewObject { count: 1 },
        ],
        vec![
            secret_source_op(),
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-argument".into()),
            },
            Ir1Op::Construct { arg_count: 1 },
        ],
        vec![
            secret_source_op(),
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-expression".into()),
            },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-quasi".into()),
            },
            Ir1Op::TemplateLiteral { quasi_count: 2 },
        ],
    ];

    for (case_index, prefix) in cases.into_iter().enumerate() {
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(format!("aggregate-flow-{case_index}").as_bytes()),
            format!("aggregate_flow_{case_index}.js"),
        );
        ir1.ops.extend(prefix);
        ir1.ops.push(Ir1Op::HostCall {
            capability: "net.write".to_string(),
            arg_count: 1,
        });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("aggregate operand flow lowering")
            .module;
        let flow = hostcall_flow(&ir2, "net.write").expect("hostcall flow annotation");
        assert_eq!(flow.data_label, Label::Secret, "case {case_index}");
        assert!(flow.declassification_required, "case {case_index}");
    }
}

#[test]
fn closure_capture_labels_use_outer_origin_ids_bd_bscab() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"closure-capture-flow"),
        "closure_capture_flow.js",
    );
    ir1.ops.push(secret_source_op());
    ir1.ops.push(Ir1Op::StoreBinding { binding_id: 17 });
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(Ir1Op::CreateFunction {
        name: None,
        param_names: Vec::new(),
        body_ops: vec![Ir1Op::LoadBinding { binding_id: 0 }, Ir1Op::Return],
        free_vars: vec![capture_cell_name("secret_capture", 17)],
        free_var_ids: vec![0],
        runtime_global_loads: Vec::new(),
        child_captured_locals: Vec::new(),
        local_lexical_bindings: Vec::new(),
        is_generator: false,
        is_async: false,
        is_arrow: false,
        rest_param_index: None,
        source_text: None,
        sloppy: false,
    });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "net.write".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("closure capture flow lowering")
        .module;
    let flow = hostcall_flow(&ir2, "net.write").expect("hostcall flow annotation");
    assert_eq!(flow.data_label, Label::Secret);
    assert!(flow.declassification_required);
}

#[test]
fn function_values_retain_unknown_runtime_floor_bd_bscab() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"function-output-floor"),
        "function_output_floor.js",
    );
    ir1.ops.push(Ir1Op::CreateFunction {
        name: None,
        param_names: Vec::new(),
        body_ops: vec![
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("secret_return".into()),
            },
            Ir1Op::Return,
        ],
        free_vars: Vec::new(),
        free_var_ids: Vec::new(),
        runtime_global_loads: Vec::new(),
        child_captured_locals: Vec::new(),
        local_lexical_bindings: Vec::new(),
        is_generator: false,
        is_async: false,
        is_arrow: false,
        rest_param_index: None,
        source_text: None,
        sloppy: false,
    });
    ir1.ops.push(Ir1Op::Call { arg_count: 0 });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "net.write".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("function output floor lowering")
        .module;
    let flow = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::HostCall { .. }))
        .and_then(|op| op.flow.as_ref())
        .expect("hostcall flow annotation");
    assert_eq!(flow.data_label, Label::Internal);
    assert!(flow.declassification_required);
}

#[test]
fn declared_function_values_retain_unknown_runtime_floor_bd_bscab() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"declared-function-output-floor"),
        "declared_function_output_floor.js",
    );
    ir1.ops.push(Ir1Op::DeclareFunction {
        name: "secretReturningFunction".to_string(),
        binding_id: 23,
        param_names: Vec::new(),
        body_ops: vec![
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("secret_return".into()),
            },
            Ir1Op::Return,
        ],
        free_vars: Vec::new(),
        free_var_ids: Vec::new(),
        runtime_global_loads: Vec::new(),
        child_captured_locals: Vec::new(),
        local_lexical_bindings: Vec::new(),
        is_generator: false,
        is_async: false,
        rest_param_index: None,
        source_text: None,
        sloppy: false,
    });
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(Ir1Op::LoadBinding { binding_id: 23 });
    ir1.ops.push(Ir1Op::Call { arg_count: 0 });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "net.write".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("declared function output floor lowering")
        .module;
    let flow = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::HostCall { .. }))
        .and_then(|op| op.flow.as_ref())
        .expect("hostcall flow annotation");
    assert_eq!(flow.data_label, Label::Internal);
    assert!(flow.declassification_required);
}

#[test]
fn await_and_yield_retain_unknown_runtime_floor_bd_bscab() {
    for (case_index, suspension) in [Ir1Op::Await, Ir1Op::Yield { delegate: false }]
        .into_iter()
        .enumerate()
    {
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(format!("suspension-floor-{case_index}").as_bytes()),
            format!("suspension_floor_{case_index}.js"),
        );
        ir1.ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::String("public-value".into()),
        });
        ir1.ops.push(suspension);
        ir1.ops.push(Ir1Op::HostCall {
            capability: "net.write".to_string(),
            arg_count: 1,
        });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("suspension output floor lowering")
            .module;
        let flow = ir2
            .ops
            .iter()
            .find(|op| matches!(op.inner, Ir1Op::HostCall { .. }))
            .and_then(|op| op.flow.as_ref())
            .expect("hostcall flow annotation");
        assert_eq!(flow.data_label, Label::Internal, "case {case_index}");
        assert!(flow.declassification_required, "case {case_index}");
    }
}

#[test]
fn unrecognized_capture_identity_fails_high_bd_bscab() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"unknown-capture-flow"),
        "unknown_capture_flow.js",
    );
    ir1.ops.push(Ir1Op::CreateFunction {
        name: Some("recursive".to_string()),
        param_names: Vec::new(),
        body_ops: vec![
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            },
            Ir1Op::Return,
        ],
        free_vars: vec!["recursive".to_string()],
        free_var_ids: vec![0],
        runtime_global_loads: Vec::new(),
        child_captured_locals: Vec::new(),
        local_lexical_bindings: Vec::new(),
        is_generator: false,
        is_async: false,
        is_arrow: false,
        rest_param_index: None,
        source_text: None,
        sloppy: false,
    });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "net.write".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("unknown capture identity remains structurally valid")
        .module;
    let flow = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::HostCall { .. }))
        .and_then(|op| op.flow.as_ref())
        .expect("hostcall flow annotation");
    assert_eq!(flow.data_label, Label::TopSecret);
    assert!(flow.declassification_required);
}

fn network_egress_label(ir1: &Ir1Module) -> Label {
    lower_ir1_to_ir2(ir1)
        .expect("function summary fixture must lower")
        .module
        .ops
        .iter()
        .find(|op| {
            matches!(
                &op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "net.write"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("network egress flow annotation")
        .data_label
        .clone()
}

fn secret_returning_function() -> Ir1Op {
    Ir1Op::CreateFunction {
        name: None,
        param_names: Vec::new(),
        body_ops: vec![secret_source_op(), Ir1Op::Return],
        free_vars: Vec::new(),
        free_var_ids: Vec::new(),
        runtime_global_loads: Vec::new(),
        child_captured_locals: Vec::new(),
        local_lexical_bindings: Vec::new(),
        is_generator: false,
        is_async: false,
        is_arrow: false,
        rest_param_index: None,
        source_text: None,
        sloppy: false,
    }
}

#[test]
fn canonical_capture_mapping_matches_runtime_frame_slots_bd_qjh7y() {
    let names = vec![
        capture_cell_name("captured", 7),
        class_expression_self_capture_name("Named", 11),
    ];
    assert_eq!(
        canonical_function_capture_origins(&names, &[99, 101]),
        Some(vec![
            FunctionCaptureOrigin {
                enclosing_id: 7,
                body_id: 99,
            },
            FunctionCaptureOrigin {
                enclosing_id: 11,
                body_id: 101,
            },
        ])
    );
    assert_eq!(
        canonical_function_capture_origins(&["uncanonical".to_string()], &[99]),
        None,
        "a capture without the runtime's enclosing-cell identity must fail high"
    );
}

#[test]
fn no_capture_return_summary_survives_call_into_egress_bd_qjh7y() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"qjh7y-call"), "qjh7y_call.js");
    ir1.ops.extend([
        secret_returning_function(),
        Ir1Op::StoreBinding { binding_id: 1 },
        Ir1Op::Pop,
        Ir1Op::LoadBinding { binding_id: 1 },
        Ir1Op::Call { arg_count: 0 },
        Ir1Op::HostCall {
            capability: "net.write".to_string(),
            arg_count: 1,
        },
        Ir1Op::Return,
    ]);

    assert_eq!(network_egress_label(&ir1), Label::Secret);
}

#[test]
fn capture_origin_not_body_id_drives_return_summary_bd_qjh7y() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"qjh7y-capture-origin"),
        "qjh7y_capture_origin.js",
    );
    ir1.ops.extend([
        secret_source_op(),
        Ir1Op::StoreBinding { binding_id: 7 },
        Ir1Op::Pop,
        Ir1Op::CreateFunction {
            name: None,
            param_names: Vec::new(),
            body_ops: vec![Ir1Op::LoadBinding { binding_id: 99 }, Ir1Op::Return],
            free_vars: vec![capture_cell_name("captured", 7)],
            free_var_ids: vec![99],
            runtime_global_loads: Vec::new(),
            child_captured_locals: Vec::new(),
            local_lexical_bindings: Vec::new(),
            is_generator: false,
            is_async: false,
            is_arrow: false,
            rest_param_index: None,
            source_text: None,
            sloppy: false,
        },
        Ir1Op::Call { arg_count: 0 },
        Ir1Op::HostCall {
            capability: "net.write".to_string(),
            arg_count: 1,
        },
        Ir1Op::Return,
    ]);

    assert_eq!(network_egress_label(&ir1), Label::Secret);
}

#[test]
fn nested_and_method_function_summaries_reach_egress_bd_qjh7y() {
    let nested_body = vec![
        secret_returning_function(),
        Ir1Op::StoreBinding { binding_id: 2 },
        Ir1Op::Pop,
        Ir1Op::LoadBinding { binding_id: 2 },
        Ir1Op::Call { arg_count: 0 },
        Ir1Op::Return,
    ];
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"qjh7y-nested-method"),
        "qjh7y_nested_method.js",
    );
    let method = Ir1Op::CreateFunction {
        name: None,
        param_names: Vec::new(),
        body_ops: nested_body,
        free_vars: Vec::new(),
        free_var_ids: Vec::new(),
        runtime_global_loads: Vec::new(),
        child_captured_locals: Vec::new(),
        local_lexical_bindings: Vec::new(),
        is_generator: false,
        is_async: true,
        is_arrow: false,
        rest_param_index: None,
        source_text: None,
        sloppy: false,
    };
    ir1.ops.extend([
        Ir1Op::NewObject { count: 0 },
        method,
        Ir1Op::DefineMethod {
            key: Ir1PropertyKey::Static("read".into()),
        },
        Ir1Op::StoreBinding { binding_id: 3 },
        Ir1Op::Pop,
        Ir1Op::LoadBinding { binding_id: 3 },
        Ir1Op::LoadBinding { binding_id: 3 },
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Static("read".into()),
        },
        Ir1Op::CallMethod { arg_count: 0 },
        Ir1Op::HostCall {
            capability: "net.write".to_string(),
            arg_count: 1,
        },
        Ir1Op::Return,
    ]);

    assert_eq!(network_egress_label(&ir1), Label::Secret);
}

#[test]
fn branch_async_and_generator_summaries_reach_egress_bd_qjh7y() {
    let cases = [
        (
            "branch",
            false,
            false,
            vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Boolean(false),
                },
                Ir1Op::JumpIfFalsyConsume { label_id: 1 },
                secret_source_op(),
                Ir1Op::Return,
                Ir1Op::Label { id: 1 },
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String("public-result".into()),
                },
                Ir1Op::Return,
            ],
        ),
        (
            "async",
            true,
            false,
            vec![secret_source_op(), Ir1Op::Return],
        ),
        (
            "generator",
            false,
            true,
            vec![
                secret_source_op(),
                Ir1Op::Yield { delegate: false },
                Ir1Op::Return,
            ],
        ),
    ];

    for (name, is_async, is_generator, body_ops) in cases {
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(name.as_bytes()),
            format!("qjh7y_{name}.js"),
        );
        ir1.ops.extend([
            Ir1Op::CreateFunction {
                name: Some(name.to_string()),
                param_names: Vec::new(),
                body_ops,
                free_vars: Vec::new(),
                free_var_ids: Vec::new(),
                runtime_global_loads: Vec::new(),
                child_captured_locals: Vec::new(),
                local_lexical_bindings: Vec::new(),
                is_generator,
                is_async,
                is_arrow: false,
                rest_param_index: None,
                source_text: None,
                sloppy: false,
            },
            Ir1Op::Call { arg_count: 0 },
            Ir1Op::HostCall {
                capability: "net.write".to_string(),
                arg_count: 1,
            },
            Ir1Op::Return,
        ]);

        assert_eq!(
            network_egress_label(&ir1),
            Label::Secret,
            "{name} return/yield sources must survive the call boundary"
        );
    }
}

#[test]
fn unsupported_callee_fails_high_bd_qjh7y() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"qjh7y-unknown"), "qjh7y_unknown.js");
    ir1.ops.extend([
        Ir1Op::LoadBinding { binding_id: 404 },
        Ir1Op::Call { arg_count: 0 },
        Ir1Op::HostCall {
            capability: "net.write".to_string(),
            arg_count: 1,
        },
        Ir1Op::Return,
    ]);

    assert_eq!(network_egress_label(&ir1), Label::TopSecret);
}

#[test]
fn binding_flow_fixed_point_is_store_order_invariant_bd_bscab() {
    for secret_first in [true, false] {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"binding-flow"), "binding_flow.js");
        let public = Ir1Op::LoadLiteral {
            value: Ir1Literal::String("public-value".into()),
        };
        let stores = if secret_first {
            [secret_source_op(), public]
        } else {
            [public, secret_source_op()]
        };
        for value in stores {
            ir1.ops.push(value);
            ir1.ops.push(Ir1Op::StoreBinding { binding_id: 7 });
            ir1.ops.push(Ir1Op::Pop);
        }
        ir1.ops.push(Ir1Op::LoadBinding { binding_id: 7 });
        ir1.ops.push(Ir1Op::HostCall {
            capability: "net.write".to_string(),
            arg_count: 1,
        });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("binding fixed-point lowering")
            .module;
        let flow = hostcall_flow(&ir2, "net.write").expect("hostcall flow annotation");
        assert_eq!(
            flow.data_label,
            Label::Secret,
            "secret_first={secret_first}"
        );
        assert!(
            flow.declassification_required,
            "secret_first={secret_first}"
        );
    }
}

#[test]
fn backward_binding_dependency_reaches_fixed_point_bd_bscab() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"binding-backedge-flow"),
        "binding_backedge_flow.js",
    );
    ir1.ops.push(Ir1Op::Label { id: 1 });
    ir1.ops.push(Ir1Op::LoadBinding { binding_id: 11 });
    ir1.ops.push(Ir1Op::StoreBinding { binding_id: 12 });
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(secret_source_op());
    ir1.ops.push(Ir1Op::StoreBinding { binding_id: 11 });
    ir1.ops.push(Ir1Op::Pop);
    ir1.ops.push(Ir1Op::Jump { label_id: 1 });
    ir1.ops.push(Ir1Op::LoadBinding { binding_id: 12 });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "net.write".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("backward binding flow reaches a fixed point")
        .module;
    let flow = hostcall_flow(&ir2, "net.write").expect("hostcall flow annotation");
    assert_eq!(flow.data_label, Label::Secret);
    assert!(flow.declassification_required);
}

#[test]
fn malformed_hostcall_operand_shape_fails_closed_bd_bscab() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-underflow"), "flow_underflow.js");
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("only-one".into()),
    });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "net.write".to_string(),
        arg_count: 2,
    });

    assert!(matches!(
        lower_ir1_to_ir2(&ir1),
        Err(LoweringPipelineError::ValueStackUnderflow)
    ));
}

#[test]
fn parsed_source_preserves_nonfinal_secret_hostcall_operand_bd_bscab() {
    let tree = crate::parser_api_stability::parse_script(
        // bd-9vouw.19: the non-final (path) operand's secret is an entropy read.
        "const crypto = require('crypto'); const secretPath = crypto.randomUUID(); \
         const fs = require('fs'); fs.writeFileSync(secretPath, 'public-data');",
    )
    .expect("parse source-level multi-argument hostcall");
    let ir0 = Ir0Module::from_syntax_tree(tree, "source_operand_order_bd_bscab.js");
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("lower source-level multi-argument hostcall to IR1")
        .module;
    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("lower source-level multi-argument hostcall to IR2")
        .module;
    let flow = ir2
        .ops
        .iter()
        .find(|op| {
            matches!(
                &op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "fs:write"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("fs write hostcall flow annotation");
    assert_eq!(flow.data_label, Label::Secret);
    assert_eq!(flow.sink_clearance, Label::Internal);
    assert!(flow.declassification_required);
}

#[test]
fn statically_proven_label_preserving_hostcall_skips_runtime_ifc_guard() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "static_flow.js");
    ir1.ops.push(Ir1Op::HostCall {
        capability: "promise:resolve".to_string(),
        arg_count: 0,
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("IR1->IR2 should succeed")
        .module;
    let hostcall_op = ir2
        .ops
        .iter()
        .find(|op| matches!(op.effect, EffectBoundary::HostcallEffect))
        .expect("hostcall op");
    let flow = hostcall_op.flow.as_ref().expect("flow annotation");
    assert!(!flow.declassification_required);
    assert_eq!(flow.data_label, Label::Public);

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
    assert!(hostcall_caps.contains(&"promise:resolve"));
    assert!(!hostcall_caps.contains(&IFC_RUNTIME_GUARD_CAPABILITY));
}

#[test]
fn hostcall_source_contracts_label_results_without_tainting_requests_bd_z1peg() {
    let lower_source_into_console = |capability: &str| {
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(capability.as_bytes()),
            format!("{capability}_result_flow.js"),
        );
        ir1.ops.push(Ir1Op::HostCall {
            capability: capability.to_string(),
            arg_count: 0,
        });
        ir1.ops.push(Ir1Op::HostCall {
            capability: "console:log".to_string(),
            arg_count: 1,
        });
        lower_ir1_to_ir2(&ir1)
            .expect("HostCall result flow should lower")
            .module
    };

    for (capability, result_label, requires_declassification) in [
        ("fs.read", Label::Internal, false),
        ("builtin:CryptoRandomUUID", Label::Secret, true),
        ("builtin:ApplyHostCall", Label::TopSecret, true),
        (
            "builtin:ApplyHostCall:promise:resolve",
            Label::Public,
            false,
        ),
        ("future:host-source", Label::TopSecret, true),
    ] {
        let ir2 = lower_source_into_console(capability);
        let hostcall = ir2
            .ops
            .iter()
            .find(|op| {
                matches!(&op.inner, Ir1Op::HostCall { capability: tag, .. } if tag == capability)
            })
            .and_then(|op| op.flow.as_ref())
            .expect("source HostCall flow annotation");
        assert_eq!(
            hostcall.data_label,
            Label::Public,
            "the source operation itself has no classified input"
        );

        let console = ir2
            .ops
            .iter()
            .find(|op| {
                matches!(&op.inner, Ir1Op::HostCall { capability, .. } if capability == "console:log")
            })
            .and_then(|op| op.flow.as_ref())
            .expect("console consumer flow annotation");
        assert_eq!(console.data_label, result_label, "{capability}");
        assert_eq!(
            console.declassification_required, requires_declassification,
            "{capability}"
        );
    }
}

#[test]
fn probe_dump_ir2_flows_for_sign_fixture_bd_53l89_temporary() {
    let ops = lower_script_source_ops(
        r#"
        const crypto = require('crypto');
        const pair = crypto.generateKeyPairSync('ed25519');
        const message = Buffer.from('franken engine signs');
        const tamperedMessage = Buffer.from('franken engine signS');
        const signature = crypto.sign(null, message, pair);
        crypto.verify(null, message, pair, signature);
        crypto.verify(null, tamperedMessage, pair, signature);
        console.log('roundtrip-ok');
    "#,
        "probe-sign",
    );
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"probe-sign"), "probe_sign.js");
    ir1.ops = ops;
    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("IR1->IR2 should succeed")
        .module;
    for (index, op) in ir2.ops.iter().enumerate() {
        let Some(flow) = op.flow.as_ref() else {
            continue;
        };
        if flow.data_label == Label::Public && flow.sink_clearance == Label::Public {
            continue;
        }
        println!(
            "FLOW op={index} cap={:?} data={:?} sink={:?} declass={} inner={:?}",
            op.required_capability.as_ref().map(|tag| tag.0.clone()),
            flow.data_label,
            flow.sink_clearance,
            flow.declassification_required,
            op.inner,
        );
    }
}

#[test]
fn ir2_flow_proof_artifact_records_static_proof() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "static_flow.js");
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("hostcall<\"fs.read\">".into()),
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("IR1->IR2 should succeed")
        .module;
    let context = LoweringContext::new("trace-static", "decision-static", "policy-static");
    let artifact =
        build_ir2_flow_proof_artifact(&ir2, &context).expect("static flow artifact should succeed");

    assert!(artifact.denied_flows.is_empty());
    assert!(artifact.required_declassifications.is_empty());
    assert!(artifact.runtime_checkpoints.is_empty());
    assert!(
        artifact
            .proved_flows
            .iter()
            .any(|entry| entry.proof_method == ProofMethod::StaticAnalysis
                && entry.capability.as_deref() == Some("fs.read"))
    );
    assert!(artifact.artifact_id.starts_with("sha256:"));
}

#[test]
fn get_property_read_is_pure_set_and_delete_stay_checked_bd_az056() {
    // The exact classification change: a property READ is not an information
    // sink (its result carries the receiver label for real egress checks),
    // while SetProperty/DeleteProperty stay checked to fail-close the
    // unpersisted heap-label boundary (bd-ojvo1).
    assert!(matches!(
        classify_ir1_op(&Ir1Op::GetProperty {
            key: Ir1PropertyKey::Static("x".into()),
        })
        .0,
        EffectBoundary::Pure
    ));
    assert!(matches!(
        classify_ir1_op(&Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static("x".into()),
            strict: true,
        })
        .0,
        EffectBoundary::ReadEffect
    ));
    assert!(matches!(
        classify_ir1_op(&Ir1Op::DeleteProperty {
            key: Ir1PropertyKey::Static("x".into()),
        })
        .0,
        EffectBoundary::ReadEffect
    ));
}

#[test]
fn property_read_off_a_high_value_is_not_an_egress_bd_az056() {
    // Reproduces bd-az056 at the flow-proof level: reading a property off a
    // high-labeled value (a Secret entropy read here, bd-9vouw.19 -- the
    // same shape as a caught exception carrying the fail-high user-Call
    // exception label) must NOT be denied. Before reclassifying GetProperty
    // as Pure this failed closed with Secret -> Internal, which rejected
    // the pervasive `catch (e) { e.message }` idiom.
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"az056-ir0"), "prop_read_az056.js");
    ir1.ops.push(secret_source_op());
    ir1.ops.push(Ir1Op::GetProperty {
        key: Ir1PropertyKey::Static("length".into()),
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("IR1->IR2 should succeed")
        .module;
    let context = LoweringContext::new("trace-az056", "decision-az056", "policy-az056");
    let artifact =
        build_ir2_flow_proof_artifact(&ir2, &context).expect("flow artifact should succeed");

    assert!(
        artifact.denied_flows.is_empty(),
        "reading a property off a high value must not deny: {:?}",
        artifact.denied_flows
    );
}

#[test]
fn ir2_flow_proof_artifact_records_dynamic_runtime_checkpoint() {
    let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "dynamic_flow.js");
    ir1.ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String("secret_token".into()),
    });
    ir1.ops.push(Ir1Op::HostCall {
        capability: "hostcall.invoke".to_string(),
        arg_count: 1,
    });
    ir1.ops.push(Ir1Op::Return);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("IR1->IR2 should succeed")
        .module;
    let context = LoweringContext::new("trace-dyn", "decision-dyn", "policy-dyn");
    let artifact = build_ir2_flow_proof_artifact(&ir2, &context)
        .expect("dynamic flow artifact should succeed");

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
fn ir2_flow_proof_artifact_detects_required_declassification() {
    let mut ir2 = Ir2Module::new(ContentHash::compute(b"ir1"), "declass_fixture.js");
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::HostCall {
            capability: "declassify.audit".to_string(),
            arg_count: 1,
        },
        effect: EffectBoundary::HostcallEffect,
        required_capability: Some(CapabilityTag("declassify.audit".to_string())),
        flow: Some(FlowAnnotation {
            data_label: Label::Secret,
            sink_clearance: Label::Public,
            declassification_required: true,
        }),
        span: None,
    });

    let context = LoweringContext::new("trace-declass", "decision-declass", "policy-declass");
    let artifact = build_ir2_flow_proof_artifact(&ir2, &context)
        .expect("declassification route should be tracked");

    assert!(artifact.denied_flows.is_empty());
    assert!(artifact.proved_flows.is_empty());
    assert_eq!(artifact.required_declassifications.len(), 1);
    assert_eq!(
        artifact.required_declassifications[0].obligation_id,
        "declass-op-0"
    );
    assert_eq!(
        artifact.required_declassifications[0].decision_contract_id,
        "decision-declass"
    );
    assert_eq!(
        artifact.required_declassifications[0]
            .declassification_route_ref
            .as_deref(),
        Some("declassify.audit")
    );
    assert!(artifact.required_declassifications[0].requires_operator_approval);
    assert!(artifact.required_declassifications[0].receipt_linkage_required);
    assert_eq!(
        artifact.required_declassifications[0].replay_command_hint,
        REQUIRED_DECLASSIFICATION_REPLAY_COMMAND_HINT
    );
    assert!(
        !artifact.required_declassifications[0]
            .replay_command_hint
            .contains("--obligation")
    );
}

#[test]
fn ir2_flow_proof_artifact_keeps_distinct_obligation_ids_for_repeated_matching_flows() {
    let mut ir2 = Ir2Module::new(ContentHash::compute(b"ir1"), "declass_repeat_fixture.js");
    for _ in 0..2 {
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::HostCall {
                capability: "declassify.audit".to_string(),
                arg_count: 1,
            },
            effect: EffectBoundary::HostcallEffect,
            required_capability: Some(CapabilityTag("declassify.audit".to_string())),
            flow: Some(FlowAnnotation {
                data_label: Label::Secret,
                sink_clearance: Label::Public,
                declassification_required: true,
            }),
            span: None,
        });
    }

    let context = LoweringContext::new("trace-repeat", "decision-repeat", "policy-repeat");
    let artifact = build_ir2_flow_proof_artifact(&ir2, &context)
        .expect("repeated declassification routes should be tracked independently");

    assert!(artifact.denied_flows.is_empty());
    assert!(artifact.proved_flows.is_empty());
    assert_eq!(artifact.required_declassifications.len(), 2);
    assert_eq!(
        artifact.required_declassifications[0].obligation_id,
        "declass-op-0"
    );
    assert_eq!(
        artifact.required_declassifications[1].obligation_id,
        "declass-op-1"
    );
    assert_eq!(artifact.required_declassifications[0].op_index, 0);
    assert_eq!(artifact.required_declassifications[1].op_index, 1);
}

#[test]
fn ir2_flow_proof_artifact_rejects_unauthorized_static_flow() {
    let mut ir2 = Ir2Module::new(ContentHash::compute(b"ir1"), "denied_fixture.js");
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::HostCall {
            capability: "fs.write".to_string(),
            arg_count: 1,
        },
        effect: EffectBoundary::HostcallEffect,
        required_capability: Some(CapabilityTag("fs.write".to_string())),
        flow: Some(FlowAnnotation {
            data_label: Label::Secret,
            sink_clearance: Label::Public,
            declassification_required: true,
        }),
        span: None,
    });

    let context = LoweringContext::new("trace-deny", "decision-deny", "policy-deny");
    let err = build_ir2_flow_proof_artifact(&ir2, &context).expect_err("must fail closed");

    match err {
        LoweringPipelineError::UnauthorizedFlow {
            op_index,
            source_label,
            sink_clearance,
            detail,
        } => {
            assert_eq!(op_index, 0);
            assert_eq!(source_label, Label::Secret);
            assert_eq!(sink_clearance, Label::Public);
            assert!(detail.contains("artifact_id=sha256:"));
            assert!(detail.contains("denied_flow_count=1"));
        }
        // SAFETY: Test validates lowering pipeline error type matches expected variant
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn ir2_flow_proof_artifact_is_deterministic() {
    let mut ir2 = Ir2Module::new(ContentHash::compute(b"ir1"), "deterministic_fixture.js");
    ir2.ops.push(Ir2Op {
        inner: Ir1Op::HostCall {
            capability: "declassify.audit".to_string(),
            arg_count: 1,
        },
        effect: EffectBoundary::HostcallEffect,
        required_capability: Some(CapabilityTag("declassify.audit".to_string())),
        flow: Some(FlowAnnotation {
            data_label: Label::Secret,
            sink_clearance: Label::Public,
            declassification_required: true,
        }),
        span: None,
    });

    let context = LoweringContext::new("trace-det", "decision-det", "policy-det");
    let first = build_ir2_flow_proof_artifact(&ir2, &context).expect("first");
    let second = build_ir2_flow_proof_artifact(&ir2, &context).expect("second");

    assert_eq!(first, second);
    // SAFETY: to_string cannot fail on derived Serialize struct
    let first_json = serde_json::to_string(&first).expect("serialize derived Serialize");
    // SAFETY: to_string cannot fail on derived Serialize struct
    let second_json = serde_json::to_string(&second).expect("serialize derived Serialize");
    assert_eq!(first_json, second_json);
}

#[test]
fn pipeline_output_includes_flow_proof_artifact() {
    let ir0 = script_ir0();
    let context = LoweringContext::new("trace-artifact", "decision-artifact", "policy-artifact");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

    assert_eq!(
        output.ir2_flow_proof_artifact.schema_version,
        IFC_FLOW_PROOF_SCHEMA_VERSION
    );
    assert!(
        output
            .ir2_flow_proof_artifact
            .artifact_id
            .starts_with("sha256:")
    );
}

#[test]
fn pipeline_emits_structured_events_with_governance_fields() {
    let ir0 = script_ir0();
    let context = LoweringContext::new("trace-a", "decision-a", "policy-a");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

    assert_eq!(output.events.len(), 4);
    assert!(output.events.iter().all(|event| {
        !event.trace_id.is_empty()
            && !event.decision_id.is_empty()
            && !event.policy_id.is_empty()
            && !event.component.is_empty()
            && !event.event.is_empty()
            && !event.outcome.is_empty()
    }));
    assert!(
        output
            .events
            .iter()
            .any(|event| event.event == "ir2_flow_check_completed")
    );
    assert_eq!(output.witnesses.len(), 3);
    assert_eq!(output.isomorphism_ledger.len(), 3);
}

#[test]
fn pipeline_is_deterministic_for_identical_input() {
    let ir0 = script_ir0();
    let context = LoweringContext::new("trace-b", "decision-b", "policy-b");
    let first = lower_ir0_to_ir3(&ir0, &context).expect("first run should succeed");
    let second = lower_ir0_to_ir3(&ir0, &context).expect("second run should succeed");

    assert_eq!(first.ir1.content_hash(), second.ir1.content_hash());
    assert_eq!(first.ir2.content_hash(), second.ir2.content_hash());
    assert_eq!(first.ir3.content_hash(), second.ir3.content_hash());
    assert_eq!(first.witnesses, second.witnesses);
    assert_eq!(first.isomorphism_ledger, second.isomorphism_ledger);
}

#[test]
fn alien2_ir3_output_is_byte_identical_golden() {
    // bd-o4cbn.10.3 (PERF-ALIEN-2.3): the bumpalo `LoweringArena` introduced in
    // ALIEN-2.2 is a pure allocation-strategy refactor and MUST NOT change the
    // emitted IR3 (ExecIR). These goldens freeze the canonical instruction bytes
    // (`Ir3Module::canonical_bytes`) and the content hash of `lower_ir0_to_ir3` for
    // fixed pure programs, so any future arena/region change that perturbs ExecIR is
    // caught. Allocation-only changes must remain byte-identical; an explicit IR
    // schema migration may re-bless the header and content hash while the instruction
    // body remains unchanged. These values include the bd-gqaa4 schema 0.14 header.
    // let_decl/const_decl re-blessed for bd-9vouw.23 (26054b0eb): root bindings now
    // get their registers before statement temporaries, so the binding and its
    // initializer temporary swap registers 1 and 2 (3 bytes: LoadInt dst, Move
    // dst/src; opcodes and order unchanged). This is a lowering change, not an
    // arena/allocation one.
    let cases: Vec<(&str, Ir0Module, &str, &str)> = vec![
        (
            "numeric_literal",
            script_ir0(),
            "07000000060000000d636f6e7374616e745f706f6f6c06000000000000000e66756e6374696f6e5f7461626c650600000001070000000500000005617269747901000000000000000000000005656e7472790100000000000000000000000a6672616d655f73697a650100000000000000020000000c69735f67656e657261746f720300000000046e616d6505000000046d61696e000000066865616465720700000004000000056c6576656c05000000036972330000000e736368656d615f76657273696f6e0700000003000000056d616a6f72010000000000000000000000056d696e6f7201000000000000000e0000000570617463680100000000000000000000000b736f757263655f686173680400000020498ec9a2efd2cea4ee7bc65a59bc701fae32e1503d4b90d2682f72d5a892ea300000000c736f757263655f6c6162656c050000000a666978747572652e6a730000000c696e737472756374696f6e730600000004070000000300000003647374010000000000000001000000026f7005000000086c6f61645f696e740000000576616c756502000000000000002a070000000300000003647374010000000000000000000000026f7005000000046d6f7665000000037372630100000000000000010700000002000000026f70050000000672657475726e0000000576616c75650100000000000000000700000001000000026f70050000000468616c740000001572657175697265645f6361706162696c697469657306000000000000000e7370656369616c697a6174696f6e08",
            "sha256:ddf4fcc82ed6467be48d748fd7533e2f33f4c01e9d58a786da7c32548734adc1",
        ),
        (
            "let_decl",
            {
                let tree = SyntaxTree {
                    goal: ParseGoal::Script,
                    body: vec![Statement::VariableDeclaration(VariableDeclaration {
                        kind: VariableDeclarationKind::Let,
                        declarations: vec![VariableDeclarator {
                            pattern: BindingPattern::Identifier("value".to_string()),
                            initializer: Some(Expression::NumericLiteral(7)),
                            span: span(),
                        }],
                        span: span(),
                    })],
                    span: span(),
                };
                Ir0Module::from_syntax_tree(tree, "alien2_let.js")
            },
            "07000000060000000d636f6e7374616e745f706f6f6c06000000000000000e66756e6374696f6e5f7461626c650600000001070000000500000005617269747901000000000000000000000005656e7472790100000000000000000000000a6672616d655f73697a650100000000000000030000000c69735f67656e657261746f720300000000046e616d6505000000046d61696e000000066865616465720700000004000000056c6576656c05000000036972330000000e736368656d615f76657273696f6e0700000003000000056d616a6f72010000000000000000000000056d696e6f7201000000000000000e0000000570617463680100000000000000000000000b736f757263655f686173680400000020d4fbfa63f3f11621663b6b1c12467f5da116d712dbe190e3e843a33cf29e059c0000000c736f757263655f6c6162656c050000000d616c69656e325f6c65742e6a730000000c696e737472756374696f6e730600000004070000000300000003647374010000000000000002000000026f7005000000086c6f61645f696e740000000576616c7565020000000000000007070000000300000003647374010000000000000001000000026f7005000000046d6f7665000000037372630100000000000000020700000002000000026f70050000000672657475726e0000000576616c75650100000000000000000700000001000000026f70050000000468616c740000001572657175697265645f6361706162696c697469657306000000000000000e7370656369616c697a6174696f6e08",
            "sha256:9ac8471c8bef60f92794235bee18dd36eba2fbd9b067e729f740f45dedd050ba",
        ),
        (
            "const_decl",
            {
                let tree = SyntaxTree {
                    goal: ParseGoal::Script,
                    body: vec![Statement::VariableDeclaration(VariableDeclaration {
                        kind: VariableDeclarationKind::Const,
                        declarations: vec![VariableDeclarator {
                            pattern: BindingPattern::Identifier("answer".to_string()),
                            initializer: Some(Expression::NumericLiteral(42)),
                            span: span(),
                        }],
                        span: span(),
                    })],
                    span: span(),
                };
                Ir0Module::from_syntax_tree(tree, "alien2_const.js")
            },
            "07000000060000000d636f6e7374616e745f706f6f6c06000000000000000e66756e6374696f6e5f7461626c650600000001070000000500000005617269747901000000000000000000000005656e7472790100000000000000000000000a6672616d655f73697a650100000000000000030000000c69735f67656e657261746f720300000000046e616d6505000000046d61696e000000066865616465720700000004000000056c6576656c05000000036972330000000e736368656d615f76657273696f6e0700000003000000056d616a6f72010000000000000000000000056d696e6f7201000000000000000e0000000570617463680100000000000000000000000b736f757263655f68617368040000002070f184bf7d762cae605ae8653fcefdc6f2dff14e6c0cb0cbbe841b4b3279953d0000000c736f757263655f6c6162656c050000000f616c69656e325f636f6e73742e6a730000000c696e737472756374696f6e730600000004070000000300000003647374010000000000000002000000026f7005000000086c6f61645f696e740000000576616c756502000000000000002a070000000300000003647374010000000000000001000000026f7005000000046d6f7665000000037372630100000000000000020700000002000000026f70050000000672657475726e0000000576616c75650100000000000000000700000001000000026f70050000000468616c740000001572657175697265645f6361706162696c697469657306000000000000000e7370656369616c697a6174696f6e08",
            "sha256:4182bd586f0332fb692e9ac9e36ee7f74dd5aca70790a60e799ea7dbd6e69fa0",
        ),
    ];

    // Pass 1: lower every case, confirm intra-run determinism, and record the actual
    // ExecIR fingerprint (printed under `--nocapture` to support re-blessing).
    let mut actual: Vec<(String, String)> = Vec::new();
    for (name, ir0, _golden_canon, _golden_hash) in cases.iter() {
        let context = LoweringContext::new("alien2-trace", "alien2-decision", "alien2-policy");
        let output =
            lower_ir0_to_ir3(ir0, &context).expect("fixed pure program should lower to IR3");
        // Re-lower with identical input: IR3 ExecIR must be reproducible bit-for-bit.
        let again = lower_ir0_to_ir3(ir0, &context).expect("re-lowering should succeed");
        assert_eq!(
            output.ir3.canonical_bytes(),
            again.ir3.canonical_bytes(),
            "{name}: IR3 canonical bytes are not deterministic"
        );
        assert_eq!(
            output.ir3.content_hash(),
            again.ir3.content_hash(),
            "{name}: IR3 content hash is not deterministic"
        );

        let canon_hex = hex::encode(output.ir3.canonical_bytes());
        let hash = hash_string(&output.ir3.content_hash());
        eprintln!("ALIEN-2.3 GOLDEN {name}: canon_hex={canon_hex} hash={hash}");
        actual.push((canon_hex, hash));
    }

    // Pass 2: byte-identity guard against the frozen goldens (assertions #1 and #2).
    for ((name, _ir0, golden_canon, golden_hash), (canon_hex, hash)) in
        cases.iter().zip(actual.iter())
    {
        assert_eq!(
            canon_hex.as_str(),
            *golden_canon,
            "{name}: IR3 ExecIR canonical instruction bytes changed vs frozen golden"
        );
        assert_eq!(
            hash.as_str(),
            *golden_hash,
            "{name}: IR3 content hash changed vs frozen golden"
        );
    }
}

#[test]
fn empty_ir0_body_fails_deterministically() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: Vec::new(),
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "empty.js");
    let error = lower_ir0_to_ir1(&ir0).expect_err("empty IR0 should fail");
    assert_eq!(error, LoweringPipelineError::EmptyIr0Body);
}

// ================================================================
// Additional coverage tests
// ================================================================

// -- LoweringContext --

#[test]
fn lowering_context_new() {
    let ctx = LoweringContext::new("trace-1", "decision-1", "policy-1");
    assert_eq!(ctx.trace_id, "trace-1");
    assert_eq!(ctx.decision_id, "decision-1");
    assert_eq!(ctx.policy_id, "policy-1");
}

#[test]
fn lowering_context_serde_roundtrip() {
    let ctx = LoweringContext::new("t", "d", "p");
    // SAFETY: to_string cannot fail on derived Serialize struct
    let json = serde_json::to_string(&ctx).expect("serialize derived Serialize");
    // SAFETY: from_str cannot fail on valid JSON from to_string roundtrip
    let parsed: LoweringContext =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(ctx, parsed);
}

// -- LoweringEvent serde --

#[test]
fn lowering_event_serde_roundtrip() {
    let event = LoweringEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "lowering_pipeline".to_string(),
        event: "test".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("FE-LOWER-0001".to_string()),
    };
    // SAFETY: to_string cannot fail on derived Serialize struct
    let json = serde_json::to_string(&event).expect("serialize derived Serialize");
    // SAFETY: from_str cannot fail on valid JSON from to_string roundtrip
    let parsed: LoweringEvent = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(event, parsed);
}

// -- InvariantCheck serde --

#[test]
fn invariant_check_serde_roundtrip() {
    let check = InvariantCheck {
        name: "test_check".to_string(),
        passed: true,
        detail: "detail".to_string(),
    };
    // SAFETY: to_string cannot fail on derived Serialize struct
    let json = serde_json::to_string(&check).expect("serialize derived Serialize");
    // SAFETY: from_str cannot fail on valid JSON from to_string roundtrip
    let parsed: InvariantCheck = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(check, parsed);
}

// -- PassWitness serde --

#[test]
fn pass_witness_serde_roundtrip() {
    let witness = PassWitness {
        pass_id: "ir0_to_ir1".to_string(),
        input_hash: "sha256:abc".to_string(),
        output_hash: "sha256:def".to_string(),
        rollback_token: "sha256:abc".to_string(),
        invariant_checks: vec![InvariantCheck {
            name: "check1".to_string(),
            passed: true,
            detail: "ok".to_string(),
        }],
    };
    let json = serde_json::to_string(&witness).expect("serialize derived Serialize");
    let parsed: PassWitness = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(witness, parsed);
}

// -- IsomorphismLedgerEntry serde --

#[test]
fn isomorphism_ledger_entry_serde_roundtrip() {
    let entry = IsomorphismLedgerEntry {
        pass_id: "ir1_to_ir2".to_string(),
        input_hash: "sha256:123".to_string(),
        output_hash: "sha256:456".to_string(),
        input_op_count: 10,
        output_op_count: 15,
    };
    let json = serde_json::to_string(&entry).expect("serialize derived Serialize");
    let parsed: IsomorphismLedgerEntry =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(entry, parsed);
}

// -- FlowInferenceMetrics --

#[test]
fn flow_inference_metrics_zero_ops_returns_zero() {
    let metrics = FlowInferenceMetrics {
        total_flow_ops: 0,
        static_proven_ops: 0,
        runtime_check_ops: 0,
    };
    assert_eq!(metrics.static_coverage_millionths(), 0);
}

#[test]
fn flow_inference_metrics_all_static() {
    let metrics = FlowInferenceMetrics {
        total_flow_ops: 10,
        static_proven_ops: 10,
        runtime_check_ops: 0,
    };
    assert_eq!(metrics.static_coverage_millionths(), 1_000_000);
}

#[test]
fn flow_inference_metrics_half_static() {
    let metrics = FlowInferenceMetrics {
        total_flow_ops: 10,
        static_proven_ops: 5,
        runtime_check_ops: 5,
    };
    assert_eq!(metrics.static_coverage_millionths(), 500_000);
}

#[test]
fn flow_inference_metrics_one_of_many_static() {
    let metrics = FlowInferenceMetrics {
        total_flow_ops: 8,
        static_proven_ops: 1,
        runtime_check_ops: 7,
    };
    assert_eq!(metrics.static_coverage_millionths(), 125_000);
}

#[test]
fn flow_inference_metrics_none_static() {
    let metrics = FlowInferenceMetrics {
        total_flow_ops: 4,
        static_proven_ops: 0,
        runtime_check_ops: 4,
    };
    assert_eq!(metrics.static_coverage_millionths(), 0);
}

// -- extract_hostcall_capability --

#[test]
fn extract_hostcall_capability_valid() {
    assert_eq!(
        extract_hostcall_capability("hostcall<\"fs.read\">"),
        Some("fs.read".to_string())
    );
}

#[test]
fn extract_hostcall_capability_embedded() {
    assert_eq!(
        extract_hostcall_capability("something hostcall<\"net.write\"> more"),
        Some("net.write".to_string())
    );
}

#[test]
fn extract_hostcall_capability_accepts_parser_preserved_escape_form() {
    assert_eq!(
        extract_hostcall_capability(r#"hostcall<\"net.write\">"#),
        Some("net.write".to_string())
    );
}

#[test]
fn extract_hostcall_capability_no_marker() {
    assert_eq!(extract_hostcall_capability("plain string"), None);
}

#[test]
fn extract_hostcall_capability_empty_capability() {
    assert_eq!(extract_hostcall_capability("hostcall<\"\">"), None);
}

#[test]
fn extract_hostcall_capability_whitespace_only() {
    assert_eq!(extract_hostcall_capability("hostcall<\"   \">"), None);
}

#[test]
fn extract_hostcall_capability_missing_close() {
    assert_eq!(extract_hostcall_capability("hostcall<\"fs.read"), None);
}

// -- sink_clearance_from_capability --

#[test]
fn sink_clearance_hostcall_invoke() {
    assert_eq!(
        sink_clearance_from_capability("hostcall.invoke"),
        Label::Internal
    );
}

#[test]
fn sink_clearance_destructuring_intrinsics_are_finite_internal_computation() {
    for capability in [
        "builtin:DestructureIteratorInit",
        "builtin:DestructureIteratorNext",
        "builtin:DestructureIteratorElide",
        "builtin:DestructureIteratorDone",
    ] {
        assert_eq!(sink_clearance_from_capability(capability), Label::TopSecret);
    }
    assert_eq!(
        sink_clearance_from_capability("builtin:DestructureIteratorFutureMethod"),
        Label::Internal
    );
    assert_eq!(sink_clearance_from_capability("net.write"), Label::Public);
    assert_eq!(
        sink_clearance_from_capability("console:log"),
        Label::Internal
    );
    let (effect, capability, flow) = classify_ir1_op(&Ir1Op::IteratorClose {
        reason: IteratorCloseReason::Break,
    });
    assert_eq!(effect, EffectBoundary::Pure);
    assert!(capability.is_none() && flow.is_none());
}

#[test]
fn sink_clearance_buffer_object_allowlist_is_exact_bd_nx5cb() {
    assert_eq!(
        sink_clearance_from_capability("builtin:BufferObjectToString"),
        Label::TopSecret
    );
    assert_eq!(
        sink_clearance_from_capability("builtin:BufferObjectEquals"),
        Label::TopSecret,
        "bd-dign3 follow-up: equality is a byte-content oracle"
    );
    assert_eq!(
        sink_clearance_from_capability("builtin:BufferObjectFutureMethod"),
        Label::Internal,
        "future Buffer instance methods require their own provenance audit"
    );
}

#[test]
fn sink_clearance_network_capabilities() {
    assert_eq!(sink_clearance_from_capability("net.write"), Label::Public);
    assert_eq!(sink_clearance_from_capability("net_connect"), Label::Public);
    assert_eq!(
        sink_clearance_from_capability("network.send"),
        Label::Public
    );
    assert_eq!(
        sink_clearance_from_capability("process.spawn"),
        Label::Public
    );
    assert_eq!(
        sink_clearance_from_capability("process_exec"),
        Label::Public
    );
    assert_eq!(
        sink_clearance_from_capability("spawn_worker"),
        Label::Public
    );
}

#[test]
fn sink_clearance_credential_capabilities() {
    assert_eq!(
        sink_clearance_from_capability("credential.read"),
        Label::TopSecret
    );
    assert_eq!(
        sink_clearance_from_capability("key_material.derive"),
        Label::TopSecret
    );
}

#[test]
fn sink_clearance_secret_capabilities() {
    assert_eq!(sink_clearance_from_capability("read_secret"), Label::Secret);
    assert_eq!(
        sink_clearance_from_capability("token.validate"),
        Label::Secret
    );
    assert_eq!(
        sink_clearance_from_capability("api_key.fetch"),
        Label::Secret
    );
}

#[test]
fn sink_clearance_fs_capabilities() {
    assert_eq!(sink_clearance_from_capability("fs.read"), Label::Internal);
    assert_eq!(sink_clearance_from_capability("fs.write"), Label::Internal);
}

#[test]
fn sink_clearance_import_capabilities() {
    assert_eq!(
        sink_clearance_from_capability("module.import"),
        Label::Internal
    );
    assert_eq!(
        sink_clearance_from_capability("import.resolve"),
        Label::Internal
    );
}

#[test]
fn sink_clearance_declassify() {
    assert_eq!(
        sink_clearance_from_capability("declassify.check"),
        Label::Public
    );
}

#[test]
fn sink_clearance_unknown_defaults_internal() {
    assert_eq!(sink_clearance_from_capability("custom.op"), Label::Internal);
}

// -- classify_ir1_op --

#[test]
fn classify_import_module() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::ImportModule {
        import_attributes: Default::default(),
        specifier: "mod".into(),
    });
    assert_eq!(effect, EffectBoundary::ReadEffect);
    assert!(cap.is_some());
    assert_eq!(
        cap.expect("operation should succeed for valid inputs").0,
        "module.import"
    );
    assert!(flow.is_some());
}

#[test]
fn classify_call() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::Call { arg_count: 1 });
    assert_eq!(effect, EffectBoundary::Pure);
    assert!(cap.is_none());
    assert!(flow.is_none());
}

#[test]
fn classify_await() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::Await);
    assert_eq!(effect, EffectBoundary::ReadEffect);
    assert!(cap.is_none());
    assert!(flow.is_some());
}

#[test]
fn classify_load_literal_string_hostcall() {
    let (effect, cap, _flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
        value: Ir1Literal::String("hostcall<\"fs.read\">".into()),
    });
    assert_eq!(effect, EffectBoundary::HostcallEffect);
    assert!(cap.is_some());
    assert_eq!(
        cap.expect("operation should succeed for valid inputs").0,
        "fs.read"
    );
}

#[test]
fn classify_load_literal_string_plain() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
        value: Ir1Literal::String("hello".into()),
    });
    assert_eq!(effect, EffectBoundary::Pure);
    assert!(cap.is_none());
    assert!(flow.is_none());
}

#[test]
fn classify_load_literal_integer() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
        value: Ir1Literal::Integer(42),
    });
    assert_eq!(effect, EffectBoundary::Pure);
    assert!(cap.is_none());
    assert!(flow.is_none());
}

#[test]
fn classify_load_literal_boolean() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
        value: Ir1Literal::Boolean(true),
    });
    assert_eq!(effect, EffectBoundary::Pure);
    assert!(cap.is_none());
    assert!(flow.is_none());
}

#[test]
fn classify_load_literal_null() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
        value: Ir1Literal::Null,
    });
    assert_eq!(effect, EffectBoundary::Pure);
    assert!(cap.is_none());
    assert!(flow.is_none());
}

#[test]
fn classify_load_literal_undefined() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
        value: Ir1Literal::Undefined,
    });
    assert_eq!(effect, EffectBoundary::Pure);
    assert!(cap.is_none());
    assert!(flow.is_none());
}

#[test]
fn classify_load_binding() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadBinding { binding_id: 0 });
    assert_eq!(effect, EffectBoundary::Pure);
    assert!(cap.is_none());
    assert!(flow.is_none());
}

#[test]
fn classify_store_binding() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::StoreBinding { binding_id: 0 });
    assert_eq!(effect, EffectBoundary::Pure);
    assert!(cap.is_none());
    assert!(flow.is_none());
}

#[test]
fn classify_export_binding() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::ExportBinding {
        name: "foo".to_string(),
        binding_id: 0,
    });
    assert_eq!(effect, EffectBoundary::Pure);
    assert!(cap.is_none());
    assert!(flow.is_none());
}

#[test]
fn classify_return() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::Return);
    assert_eq!(effect, EffectBoundary::Pure);
    assert!(cap.is_none());
    assert!(flow.is_none());
}

#[test]
fn classify_nop() {
    let (effect, cap, flow) = classify_ir1_op(&Ir1Op::Nop);
    assert_eq!(effect, EffectBoundary::Pure);
    assert!(cap.is_none());
    assert!(flow.is_none());
}

// -- push_constant_optimized dedup --

#[test]
fn push_constant_optimized_deduplicates() {
    let mut pool = ConstantPool::new();
    let idx1 = push_constant_optimized(&mut pool, "hello");
    let idx2 = push_constant_optimized(&mut pool, "world");
    let idx3 = push_constant_optimized(&mut pool, "hello");
    assert_eq!(idx1, 0);
    assert_eq!(idx2, 1);
    assert_eq!(idx3, 0); // dedup
    assert_eq!(pool.into_vec().len(), 2);
}

#[test]
fn push_constant_optimized_distinguishes_exact_utf16_units_bd_vltnh() {
    let mut pool = ConstantPool::new();
    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);

    assert_eq!(push_constant_optimized(&mut pool, d800.clone()), 0);
    assert_eq!(push_constant_optimized(&mut pool, d801.clone()), 1);
    assert_eq!(push_constant_optimized(&mut pool, d800.clone()), 0);
    assert_eq!(pool.into_vec(), vec![d800, d801]);
}

#[test]
fn static_float_property_keys_use_ecmascript_number_spelling_bd_vltnh() {
    for (value, expected) in [
        (1e-7_f64, "1e-7"),
        (1e20_f64, "100000000000000000000"),
        (1e21_f64, "1e+21"),
        (-0.0_f64, "0"),
    ] {
        assert_eq!(
            canonical_static_object_property_key(&Expression::FloatLiteral(value.to_bits()))
                .expect("float property key should canonicalize"),
            expected
        );
    }
}

// -- lower_literal_to_ir3_optimized --

#[test]
fn lower_literal_string_to_ir3() {
    let mut instructions = Vec::new();
    let mut pool = ConstantPool::new();
    lower_literal_to_ir3_optimized(
        &Ir1Literal::String("hello".into()),
        0,
        &mut instructions,
        &mut pool,
    );
    assert_eq!(instructions.len(), 1);
    assert!(matches!(
        instructions[0],
        Ir3Instruction::LoadStr {
            dst: 0,
            pool_index: 0
        }
    ));
    assert_eq!(pool.into_vec(), vec![JsString::from("hello")]);
}

#[test]
fn lower_literal_integer_to_ir3() {
    let mut instructions = Vec::new();
    let mut pool = ConstantPool::new();
    lower_literal_to_ir3_optimized(&Ir1Literal::Integer(99), 1, &mut instructions, &mut pool);
    assert_eq!(instructions.len(), 1);
    assert!(matches!(
        instructions[0],
        Ir3Instruction::LoadInt { dst: 1, value: 99 }
    ));
    assert!(pool.into_vec().is_empty());
}

#[test]
fn lower_literal_boolean_to_ir3() {
    let mut instructions = Vec::new();
    let mut pool = ConstantPool::new();
    lower_literal_to_ir3_optimized(&Ir1Literal::Boolean(true), 2, &mut instructions, &mut pool);
    assert_eq!(instructions.len(), 1);
    assert!(matches!(
        instructions[0],
        Ir3Instruction::LoadBool {
            dst: 2,
            value: true
        }
    ));
}

#[test]
fn lower_literal_null_to_ir3() {
    let mut instructions = Vec::new();
    let mut pool = ConstantPool::new();
    lower_literal_to_ir3_optimized(&Ir1Literal::Null, 3, &mut instructions, &mut pool);
    assert_eq!(instructions.len(), 1);
    assert!(matches!(
        instructions[0],
        Ir3Instruction::LoadNull { dst: 3 }
    ));
}

#[test]
fn lower_literal_undefined_to_ir3() {
    let mut instructions = Vec::new();
    let mut pool = ConstantPool::new();
    lower_literal_to_ir3_optimized(&Ir1Literal::Undefined, 4, &mut instructions, &mut pool);
    assert_eq!(instructions.len(), 1);
    assert!(matches!(
        instructions[0],
        Ir3Instruction::LoadUndefined { dst: 4 }
    ));
}

// -- flow_requires_runtime_check --

#[test]
fn flow_requires_runtime_check_dynamic_capability() {
    let cap = CapabilityTag("hostcall.invoke".to_string());
    assert!(flow_requires_runtime_check(None, &cap));
}

#[test]
fn flow_requires_runtime_check_declassification() {
    let cap = CapabilityTag("fs.read".to_string());
    let annotation = FlowAnnotation {
        data_label: Label::Secret,
        sink_clearance: Label::Public,
        declassification_required: true,
    };
    assert!(flow_requires_runtime_check(Some(&annotation), &cap));
}

#[test]
fn flow_requires_runtime_check_custom_label() {
    let cap = CapabilityTag("fs.read".to_string());
    let annotation = FlowAnnotation {
        data_label: Label::Custom {
            name: "my_label".to_string(),
            level: 50,
        },
        sink_clearance: Label::Internal,
        declassification_required: false,
    };
    assert!(flow_requires_runtime_check(Some(&annotation), &cap));
}

#[test]
fn flow_requires_runtime_check_static_safe() {
    let cap = CapabilityTag("fs.read".to_string());
    let annotation = FlowAnnotation {
        data_label: Label::Internal,
        sink_clearance: Label::Internal,
        declassification_required: false,
    };
    assert!(!flow_requires_runtime_check(Some(&annotation), &cap));
}

#[test]
fn flow_requires_runtime_check_none_flow_static_cap() {
    let cap = CapabilityTag("fs.read".to_string());
    assert!(!flow_requires_runtime_check(None, &cap));
}

// -- LoweringPipelineError Display --

#[test]
fn lowering_pipeline_error_display_empty_ir0() {
    let err = LoweringPipelineError::EmptyIr0Body;
    assert_eq!(err.to_string(), "IR0 module has no statements");
}

#[test]
fn lowering_pipeline_error_display_ir_contract() {
    let err = LoweringPipelineError::IrContractValidation {
        code: "FE-IR-001".to_string(),
        level: IrLevel::Ir1,
        message: "bad scope".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("FE-IR-001"));
    assert!(display.contains("bad scope"));
}

#[test]
fn lowering_pipeline_error_display_invariant() {
    let err = LoweringPipelineError::InvariantViolation {
        detail: "duplicate binding IDs in IR1 scope graph",
    };
    assert!(err.to_string().contains("duplicate binding IDs"));
}

#[test]
fn lowering_pipeline_error_display_unsupported_syntax() {
    let err =
        LoweringPipelineError::UnsupportedSyntax(Box::new(UnsupportedSyntaxDiagnostic::from_site(
            ParserGapSiteId::ForInStatementPlaceholder,
            "ir0",
            Some(span()),
        )));
    let display = err.to_string();
    assert!(display.contains("FE-PARSER-GAP-FOR-IN-0001"));
    assert!(display.contains("lower_ir0_to_ir1.for_in_placeholder"));
}

// -- Module lowering with imports --

#[test]
fn lower_module_with_import() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Import(ImportDeclaration {
            import_attributes: Default::default(),
            clause: ImportClause::Default {
                local: "_".to_string(),
            },
            source: "lodash".into(),
            binding: Some("_".to_string()),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "module_import.mjs");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_import = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::ImportModule { specifier, .. } if specifier == "lodash"));
    assert!(has_import);
    assert_eq!(result.module.scopes[0].kind, ScopeKind::Module);
}

/// bd-1xl17.b helper: lower ESM `source` (Module goal) to its IR1 op stream.
fn lower_esm_source_ops(source: &str, label: &str) -> Vec<Ir1Op> {
    let tree = crate::parser_api_stability::parse_module(source).expect("parse ESM module");
    let ir0 = Ir0Module::from_syntax_tree(tree, label);
    lower_ir0_to_ir1(&ir0).expect("lower IR0->IR1").module.ops
}

fn ops_have_hostcall(ops: &[Ir1Op], cap: &str) -> bool {
    ops.iter()
        .any(|op| matches!(op, Ir1Op::HostCall { capability, .. } if capability.as_str() == cap))
}

/// bd-3894s: the `arg_count` of the first HostCall carrying `cap` in the
/// lowered ops — 1 for a bare URL-only call, 2 once the options/init object
/// (arg[1]) is forwarded so the interpreter can frame the real
/// method/headers/body.
fn first_hostcall_arg_count(ops: &[Ir1Op], cap: &str) -> Option<u32> {
    ops.iter().find_map(|op| match op {
        Ir1Op::HostCall {
            capability,
            arg_count,
        } if capability == cap => Some(*arg_count),
        _ => None,
    })
}

/// bd-3894s slice (2): the `arg_count` of the first `net:request` HostCall —
/// the immediate `http.get`/`fetch` egress form.
fn net_request_arg_count(ops: &[Ir1Op]) -> Option<u32> {
    first_hostcall_arg_count(ops, "net:request")
}

fn ops_have_fs_import_module(ops: &[Ir1Op]) -> bool {
    ops.iter().any(|op| {
        matches!(op, Ir1Op::ImportModule { specifier, .. }
            if module_source_matches(specifier, is_fs_module_specifier))
    })
}

fn ops_have_http_import_module(ops: &[Ir1Op]) -> bool {
    ops.iter().any(|op| {
        matches!(op, Ir1Op::ImportModule { specifier, .. }
            if module_source_matches(specifier, is_http_module_specifier))
    })
}

fn ops_have_https_import_module(ops: &[Ir1Op]) -> bool {
    ops.iter().any(|op| {
        matches!(op, Ir1Op::ImportModule { specifier, .. }
            if module_source_matches(specifier, is_https_module_specifier))
    })
}

/// bd-1xl17.b: a named ESM import (`import { writeFileSync, readFileSync } from
/// 'node:fs'`) used as direct calls lowers to fs:write/fs:read HostCalls and
/// elides the (fault-prone) node:fs module load.
#[test]
fn esm_named_fs_import_lowers_to_hostcalls_bd_1xl17_b() {
    let ops = lower_esm_source_ops(
        "import { writeFileSync, readFileSync } from 'node:fs';\n\
         writeFileSync('out.txt', 'bytes');\n\
         readFileSync('out.txt');\n",
        "esm_named_fs.mjs",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:write"),
        "expected fs:write hostcall"
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "expected fs:read hostcall"
    );
    assert!(
        !ops_have_fs_import_module(&ops),
        "node:fs module load must be elided for the confirmed named import"
    );
}

/// bd-1xl17.b: named ESM import recognition respects `as` renames — the local
/// name (`rd`), not the imported name, is what the call site uses.
#[test]
fn esm_named_fs_import_rename_lowers_to_hostcalls_bd_1xl17_b() {
    let ops = lower_esm_source_ops(
        "import { readFileSync as rd } from 'node:fs';\n\
         rd('out.txt');\n",
        "esm_named_rename_fs.mjs",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "a renamed fs named import must still lower to fs:read"
    );
    assert!(
        !ops_have_fs_import_module(&ops),
        "node:fs module load must be elided"
    );
}

/// bd-1xl17.b: a namespace ESM import (`import * as fs from 'node:fs'`) used as
/// `fs.readFileSync/...` lowers to HostCalls via the shared member-call
/// recognizer.
#[test]
fn esm_namespace_fs_import_lowers_to_hostcalls_bd_1xl17_b() {
    let ops = lower_esm_source_ops(
        "import * as fs from 'node:fs';\n\
         fs.writeFileSync('out.txt', 'bytes');\n\
         fs.readFileSync('out.txt');\n",
        "esm_namespace_fs.mjs",
    );
    assert!(ops_have_hostcall(&ops, "fs:write"));
    assert!(ops_have_hostcall(&ops, "fs:read"));
    assert!(
        !ops_have_fs_import_module(&ops),
        "node:fs module load must be elided"
    );
}

/// bd-1xl17.b: a default ESM import (`import fs from 'node:fs'`) used as
/// `fs.readFileSync/...` lowers to HostCalls.
#[test]
fn esm_default_fs_import_lowers_to_hostcalls_bd_1xl17_b() {
    let ops = lower_esm_source_ops(
        "import fs from 'node:fs';\n\
         fs.writeFileSync('out.txt', 'bytes');\n\
         fs.readFileSync('out.txt');\n",
        "esm_default_fs.mjs",
    );
    assert!(ops_have_hostcall(&ops, "fs:write"));
    assert!(ops_have_hostcall(&ops, "fs:read"));
    assert!(
        !ops_have_fs_import_module(&ops),
        "node:fs module load must be elided"
    );
}

/// bd-1xl17.b fail-closed: a bare/UNUSED fs import is NOT recognized — the
/// node:fs module load is preserved and no fs HostCall is emitted, so the
/// import keeps its current (runtime module-load) behavior. The ESM analogue
/// of the require-binding usage-gating (bd-1xl17.a) that preserves the
/// ambient-authority denial of bare/unused requires.
#[test]
fn esm_unused_fs_import_is_not_recognized_bd_1xl17_b() {
    let ops = lower_esm_source_ops(
        "import { readFileSync } from 'node:fs';\n",
        "esm_unused_fs.mjs",
    );
    assert!(
        ops_have_fs_import_module(&ops),
        "an unused fs named import must keep its module load (no recognition)"
    );
    assert!(
        !ops_have_hostcall(&ops, "fs:read"),
        "an unused fs named import must not emit an fs hostcall"
    );
}

/// bd-1xl17.d helper: lower script-goal `source` to its IR1 op stream (the
/// non-Module analogue of [`lower_esm_source_ops`]).
/// Lowering runs on its own provisioned stack, so a small caller thread
/// can lower a deeply nested program. On the caller's stack, one level of
/// function expression plus for-of takes about 270 KiB of debug-build
/// lowering frames, more than this 256 KiB thread has.
#[test]
fn nested_program_lowers_from_a_small_caller_thread() {
    let mut body = String::from("out.push(1);");
    for depth in 0..12 {
        body = format!("(function () {{ for (const x{depth} of [1]) {{ {body} }} }})();");
    }
    let source = format!("var out = []; {body}");
    let ops = std::thread::Builder::new()
        .name("small-caller".into())
        .stack_size(256 * 1024)
        .spawn(move || lower_script_source_ops(&source, "nested_small_caller.js").len())
        .expect("spawn small caller thread")
        .join()
        .expect("lowering must not overflow the caller's stack");
    assert!(ops > 0);
}

fn lower_script_source_ops(source: &str, label: &str) -> Vec<Ir1Op> {
    let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
    let ir0 = Ir0Module::from_syntax_tree(tree, label);
    lower_ir0_to_ir1(&ir0).expect("lower IR0->IR1").module.ops
}

/// bd-1xl17.d helper: arg_count of the first `fs:read` HostCall, if any.
fn fs_read_hostcall_arg_count(ops: &[Ir1Op]) -> Option<u32> {
    ops.iter().find_map(|op| match op {
        Ir1Op::HostCall {
            capability,
            arg_count,
        } if capability.as_str() == "fs:read" => Some(*arg_count),
        _ => None,
    })
}

/// bd-201vt helper: arg_count of the first `fs:write` HostCall, if any.
fn fs_write_hostcall_arg_count(ops: &[Ir1Op]) -> Option<u32> {
    ops.iter().find_map(|op| match op {
        Ir1Op::HostCall {
            capability,
            arg_count,
        } if capability.as_str() == "fs:write" => Some(*arg_count),
        _ => None,
    })
}

fn ops_deep_match(ops: &[Ir1Op], predicate: &impl Fn(&Ir1Op) -> bool) -> bool {
    ops.iter().any(|op| {
        predicate(op)
            || matches!(op,
                Ir1Op::DeclareFunction { body_ops, .. }
                    | Ir1Op::CreateFunction { body_ops, .. }
                if ops_deep_match(body_ops, predicate))
    })
}

fn count_hostcall_deep(ops: &[Ir1Op], expected: &str) -> usize {
    ops.iter()
        .map(|op| match op {
            Ir1Op::HostCall { capability, .. } if capability == expected => 1,
            Ir1Op::DeclareFunction { body_ops, .. } | Ir1Op::CreateFunction { body_ops, .. } => {
                count_hostcall_deep(body_ops, expected)
            }
            _ => 0,
        })
        .sum()
}

fn count_ops_deep(ops: &[Ir1Op], predicate: &impl Fn(&Ir1Op) -> bool) -> usize {
    ops.iter()
        .map(|op| {
            usize::from(predicate(op))
                + match op {
                    Ir1Op::DeclareFunction { body_ops, .. }
                    | Ir1Op::CreateFunction { body_ops, .. } => count_ops_deep(body_ops, predicate),
                    _ => 0,
                }
        })
        .sum()
}

fn assert_crypto_ambient_denied_bd_2z157(source: &str, label: &str) {
    let tree = if matches!(
        label,
        "named module alias export" | "default module alias export"
    ) {
        crate::parser_api_stability::parse_module(source).expect("parse crypto module")
    } else {
        crate::parser_api_stability::parse_script(source).expect("parse crypto source")
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, format!("crypto_{label}_bd_2z157.js"));
    let error = lower_ir0_to_ir1(&ir0)
        .expect_err("untrusted crypto possession must preserve ambient denial");
    assert!(
        matches!(
            error,
            LoweringPipelineError::AmbientAuthorityViolation { .. }
        ),
        "{label} should preserve ambient crypto denial, got {error:?}"
    );
}

#[test]
fn crypto_deterministic_static_surface_lowers_with_exact_capabilities_bd_2z157() {
    let ops = lower_script_source_ops(
        "const crypto = require('crypto');\n\
         crypto.createHash('sha256').update('abc').digest('hex');\n\
         crypto.createHmac('sha256', 'key').update('abc').digest('hex');\n\
         crypto.timingSafeEqual(Buffer.from('a'), Buffer.from('a'));\n\
         crypto.pbkdf2Sync('pw', 'salt', 10, 8, 'sha256');\n\
         crypto.pbkdf2('pw', 'salt', 10, 8, 'sha256', (_err, _key) => {\n\
           crypto.pbkdf2Sync('pw', 'salt', 10, 8, 'sha256');\n\
         });\n\
         crypto.scryptSync('pw', 'salt', 8);\n\
         crypto.createCipheriv('aes-128-ctr', Buffer.alloc(16), Buffer.alloc(16));\n\
         crypto.createDecipheriv('aes-128-ctr', Buffer.alloc(16), Buffer.alloc(16));\n\
         crypto.getHashes();\n\
         crypto.getCiphers();\n\
         crypto.constants.RSA_PKCS1_PADDING;\n\
         try { crypto.randomInt(5, 5); } catch (_error) {}\n\
         try { crypto.randomInt(0); } catch (_error) {}\n",
        "crypto_static_surface_bd_2z157.js",
    );

    for (capability, expected_count) in [
        ("builtin:CryptoCreateHash", 1),
        ("builtin:CryptoCreateHmac", 1),
        ("builtin:CryptoTimingSafeEqual", 1),
        ("builtin:CryptoPbkdf2Sync", 2),
        ("builtin:CryptoPbkdf2", 1),
        ("builtin:CryptoScryptSync", 1),
        ("builtin:CryptoCreateCipheriv", 1),
        ("builtin:CryptoCreateDecipheriv", 1),
        ("builtin:CryptoGetHashes", 1),
        ("builtin:CryptoGetCiphers", 1),
        ("builtin:CryptoConstants", 1),
        ("builtin:CryptoInvalidRandomInt", 2),
    ] {
        assert_eq!(
            count_hostcall_deep(&ops, capability),
            expected_count,
            "unexpected {capability} hostcall count"
        );
    }
    assert!(ops_deep_match(&ops, &|op| matches!(
        op,
        Ir1Op::HostCall {
            capability,
            arg_count: 6
        } if capability == "builtin:CryptoPbkdf2"
    )));
}

#[test]
fn crypto_inline_node_specifier_and_method_chains_preserve_provenance_bd_2z157() {
    let ops = lower_script_source_ops(
        "require('node:crypto').createHash('sha256').update('abc').digest('hex');\n\
         require('crypto').createHmac('sha1', 'key').update('data').digest();\n\
         require('node:crypto').constants.RSA_PKCS1_PADDING;\n",
        "crypto_inline_bd_2z157.js",
    );
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoCreateHash"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoCreateHmac"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoConstants"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoObjectUpdate"), 2);
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoObjectDigest"), 2);
}

#[test]
fn crypto_object_alias_provenance_reaches_dependent_copy_alias_bd_1by6p() {
    let ops = lower_script_source_ops(
        "const crypto = require('crypto');\n\
         const hash = crypto.createHash('sha256').update('partial');\n\
         const copy = hash.copy().update('-more');\n\
         const copy2 = copy.copy().update('-again');\n\
         hash.digest('hex');\n\
         copy.digest('hex');\n\
         copy2.digest('hex');\n",
        "crypto_dependent_copy_alias_bd_1by6p.js",
    );
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoCreateHash"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoObjectUpdate"), 3);
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoObjectCopy"), 2);
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoObjectDigest"), 3);
}

#[test]
fn crypto_object_copy_transfer_admitted_in_nested_control_flow_bd_5l5ye() {
    // A `const copy = hash.copy().update(...)` transfer nested inside a
    // block / if / try must lower with exactly the same finite crypto
    // provenance as the top-level form
    // (crypto_object_alias_provenance_reaches_dependent_copy_alias_bd_1by6p),
    // not fall back to ambient-denied generic scanning.
    for (label, source) in [
        (
            "block",
            "const crypto = require('crypto');\n\
             const hash = crypto.createHash('sha256').update('partial');\n\
             { const copy = hash.copy().update('-more'); copy.digest('hex'); }\n\
             hash.digest('hex');\n",
        ),
        (
            "if",
            "const crypto = require('crypto');\n\
             const hash = crypto.createHash('sha256').update('partial');\n\
             if (true) { const copy = hash.copy().update('-more'); copy.digest('hex'); }\n\
             hash.digest('hex');\n",
        ),
        (
            "try",
            "const crypto = require('crypto');\n\
             const hash = crypto.createHash('sha256').update('partial');\n\
             try { const copy = hash.copy().update('-more'); copy.digest('hex'); } catch (_e) {}\n\
             hash.digest('hex');\n",
        ),
    ] {
        let ops = lower_script_source_ops(source, "crypto_nested_copy_bd_5l5ye.js");
        assert_eq!(
            count_hostcall_deep(&ops, "builtin:CryptoCreateHash"),
            1,
            "{label}: createHash"
        );
        assert_eq!(
            count_hostcall_deep(&ops, "builtin:CryptoObjectCopy"),
            1,
            "{label}: copy"
        );
        assert_eq!(
            count_hostcall_deep(&ops, "builtin:CryptoObjectUpdate"),
            2,
            "{label}: update"
        );
        assert_eq!(
            count_hostcall_deep(&ops, "builtin:CryptoObjectDigest"),
            2,
            "{label}: digest"
        );
    }
}

#[test]
fn crypto_object_copy_transfer_rejected_in_nested_control_flow_stays_fail_closed_bd_5l5ye() {
    // The nested-scope admission must NOT relax any bd-1by6p guard. When a
    // nested `const copy = hash.copy()...` ESCAPES (here via console.log),
    // the recursion must still reject it, so the source hash never confirms
    // and NONE of its finite crypto object hostcalls are emitted -- unlike
    // the admitted positive case (which emits copy=1, update=2, digest=2).
    let escaped = lower_script_source_ops(
        "const crypto = require('crypto');\n\
         const hash = crypto.createHash('sha256').update('partial');\n\
         { const copy = hash.copy().update('-more'); console.log(copy); }\n\
         hash.digest('hex');\n",
        "crypto_nested_escaped_copy_bd_5l5ye.js",
    );
    assert_eq!(
        count_hostcall_deep(&escaped, "builtin:CryptoObjectCopy"),
        0,
        "escaped nested copy must not lower to a finite CryptoObjectCopy"
    );
    assert_eq!(
        count_hostcall_deep(&escaped, "builtin:CryptoObjectDigest"),
        0,
        "an escaped nested copy must fail the whole source hash closed"
    );
}

#[test]
fn crypto_object_alias_fluent_identity_chains_close_with_digest_bd_1by6p() {
    let ops = lower_script_source_ops(
        "const crypto = require('crypto');\n\
         const hash = crypto.createHash('sha256');\n\
         console.log(hash.update('abc').digest('hex'));\n\
         const copied = crypto.createHash('sha256');\n\
         console.log(copied.copy().update('def').digest('hex'));\n\
         const hmac = crypto.createHmac('sha256', 'public-key');\n\
         console.log(hmac.update('ghi').digest('hex'));\n",
        "crypto_alias_fluent_identity_chains_bd_1by6p.js",
    );
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoCreateHash"), 2);
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoCreateHmac"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoObjectUpdate"), 3);
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoObjectCopy"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoObjectDigest"), 3);
}

#[test]
fn crypto_asymmetric_and_untrusted_alias_uses_fail_closed_bd_2z157() {
    for (label, source) in [
        ("unused", "const crypto = require('crypto');"),
        (
            "mutable alias",
            "let crypto = require('crypto'); crypto.getHashes();",
        ),
        (
            "asymmetric",
            "const crypto = require('crypto'); crypto.generateKeyPairSync('ed25519');",
        ),
        (
            "escaped",
            "const crypto = require('crypto'); crypto.getHashes(); console.log(crypto);",
        ),
        (
            "destructured escape",
            "const crypto = require('crypto'); const { createHash } = crypto; createHash('sha256');",
        ),
        (
            "mutated member",
            "const crypto = require('crypto'); crypto.getHashes(); crypto.createHash = null;",
        ),
        (
            "mutated binding",
            "const crypto = require('crypto'); crypto.getHashes(); crypto = {};",
        ),
        (
            "computed method",
            "const crypto = require('crypto'); crypto['createHash']('sha256');",
        ),
        (
            "spread deterministic method",
            "const crypto = require('crypto'); try { crypto.createHash(...['sha256']); } catch (_error) {} console.log('continued');",
        ),
        (
            "named module alias export",
            "const crypto = require('crypto'); crypto.getHashes(); export { crypto };",
        ),
        (
            "default module alias export",
            "const crypto = require('crypto'); crypto.getHashes(); export default crypto;",
        ),
        (
            "computed constants",
            "const crypto = require('crypto'); crypto['constants'];",
        ),
        (
            "unsupported member",
            "const crypto = require('crypto'); crypto.getHashes(); crypto.webcrypto;",
        ),
        (
            "shadowed only",
            "const crypto = require('crypto'); function f(crypto) { return crypto.getHashes(); }",
        ),
        (
            "predeclaration call",
            "useCrypto(); const crypto = require('crypto'); function useCrypto() { return crypto.getHashes(); }",
        ),
    ] {
        assert_crypto_ambient_denied_bd_2z157(source, label);
    }
}

#[test]
fn crypto_authenticated_entropy_lowers_with_dedicated_capabilities_bd_opsnv() {
    let ops = lower_script_source_ops(
        "const crypto = require('crypto');\n\
         crypto.randomBytes(16);\n\
         crypto.randomBytes(8, (_error, _bytes) => {});\n\
         crypto.randomUUID();\n\
         crypto.randomInt(10);\n\
         crypto.randomInt(5, 8);\n\
         crypto.randomInt(10, (_error, _value) => {});\n\
         crypto.randomFillSync(Buffer.alloc(8));\n",
        "crypto_entropy_bd_opsnv.js",
    );
    for (capability, expected_count) in [
        ("builtin:CryptoRandomBytes", 2),
        ("builtin:CryptoRandomUUID", 1),
        ("builtin:CryptoRandomInt", 3),
        ("builtin:CryptoRandomFillSync", 1),
    ] {
        assert_eq!(
            count_hostcall_deep(&ops, capability),
            expected_count,
            "unexpected {capability} hostcall count"
        );
    }
    assert_eq!(count_hostcall_deep(&ops, "module:require"), 0);
}

#[test]
fn crypto_inline_entropy_and_forged_provenance_never_emit_crypto_hostcalls_bd_2z157() {
    assert_crypto_ambient_denied_bd_2z157(
        "require('crypto').randomInt(10);",
        "inline successful entropy",
    );

    let forged = lower_script_source_ops(
        "const crypto = {}; crypto.createHash('sha256');",
        "crypto_forged_bd_2z157.js",
    );
    for capability in [
        "builtin:CryptoCreateHash",
        "builtin:CryptoCreateHmac",
        "builtin:CryptoTimingSafeEqual",
        "builtin:CryptoPbkdf2Sync",
        "builtin:CryptoPbkdf2",
        "builtin:CryptoScryptSync",
        "builtin:CryptoCreateCipheriv",
        "builtin:CryptoCreateDecipheriv",
        "builtin:CryptoGetHashes",
        "builtin:CryptoGetCiphers",
        "builtin:CryptoConstants",
        "builtin:CryptoInvalidRandomInt",
        "builtin:CryptoRandomBytes",
        "builtin:CryptoRandomUUID",
        "builtin:CryptoRandomInt",
        "builtin:CryptoRandomFillSync",
    ] {
        assert_eq!(count_hostcall_deep(&forged, capability), 0);
    }

    let shadowed_require = lower_script_source_ops(
        "function f(require) { return require('crypto').getHashes(); }",
        "crypto_shadowed_require_bd_2z157.js",
    );
    assert_eq!(
        count_hostcall_deep(&shadowed_require, "builtin:CryptoGetHashes"),
        0
    );
}

#[test]
fn crypto_confirmed_outer_alias_never_authenticates_inner_shadow_bindings_bd_2z157() {
    let ops = lower_script_source_ops(
        "const crypto = require('crypto');\n\
         crypto.getHashes();\n\
         function parameterShadow(crypto) { return crypto.getHashes(); }\n\
         function destructuredShadow({ crypto }) { return crypto.getHashes(); }\n\
         function localShadow() {\n\
           const crypto = { getHashes() { return []; } };\n\
           return crypto.getHashes();\n\
         }\n\
         parameterShadow({ getHashes() { return []; } });\n\
         destructuredShadow({ crypto: { getHashes() { return []; } } });\n\
         localShadow();\n",
        "crypto_nested_shadow_bd_2z157.js",
    );

    assert_eq!(
        count_hostcall_deep(&ops, "builtin:CryptoGetHashes"),
        1,
        "only the confirmed outer alias may emit a crypto hostcall"
    );
}

#[test]
fn authenticated_crypto_object_aliases_lower_to_finite_hostcalls_bd_1by6p() {
    let ops = lower_script_source_ops(
        "const crypto = require('crypto');\n\
         try {\n\
           const bad = crypto.createDecipheriv('aes-256-cbc', Buffer.alloc(32, 2), Buffer.alloc(16, 2));\n\
           bad.update(Buffer.alloc(16));\n\
           bad.final();\n\
         } catch (error) { console.log(error instanceof Error); }\n",
        "crypto_object_catch_bd_1by6p.js",
    );

    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoObjectUpdate"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:CryptoObjectFinal"), 1);
    assert!(ops_deep_match(&ops, &|op| matches!(
        op,
        Ir1Op::HostCall {
            capability,
            arg_count: 2
        } if capability == "builtin:CryptoObjectUpdate"
    )));
    assert!(ops_deep_match(&ops, &|op| matches!(
        op,
        Ir1Op::HostCall {
            capability,
            arg_count: 1
        } if capability == "builtin:CryptoObjectFinal"
    )));

    let hash_ops = lower_script_source_ops(
        "const crypto = require('crypto');\n\
         const hash = crypto.createHash('sha256');\n\
         hash.update('public-input');\n\
         console.log(hash.digest('hex'));\n",
        "crypto_hash_object_discarded_update_bd_1by6p.js",
    );
    assert_eq!(
        count_hostcall_deep(&hash_ops, "builtin:CryptoObjectUpdate"),
        1
    );
    assert_eq!(
        count_hostcall_deep(&hash_ops, "builtin:CryptoObjectDigest"),
        1
    );

    let gcm_ops = lower_script_source_ops(
        "const crypto = require('crypto');\n\
         const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(12));\n\
         decipher.setAuthTag(Buffer.alloc(16));\n\
         decipher.update(Buffer.alloc(8));\n\
         decipher.final();\n",
        "crypto_gcm_set_auth_tag_bd_2z157.js",
    );
    assert!(ops_deep_match(&gcm_ops, &|op| matches!(
        op,
        Ir1Op::HostCall {
            capability,
            arg_count: 2
        } if capability == "builtin:CryptoObjectSetAuthTag"
    )));

    for (label, source) in [
        (
            "assigned",
            "const c=require('crypto'); const d=c.createDecipheriv('aes-256-gcm',Buffer.alloc(32),Buffer.alloc(12)); const x=d.setAuthTag(Buffer.alloc(16)); d.final();",
        ),
        (
            "chained",
            "const c=require('crypto'); const d=c.createDecipheriv('aes-256-gcm',Buffer.alloc(32),Buffer.alloc(12)); d.setAuthTag(Buffer.alloc(16)).final();",
        ),
        (
            "computed",
            "const c=require('crypto'); const d=c.createDecipheriv('aes-256-gcm',Buffer.alloc(32),Buffer.alloc(12)); d['setAuthTag'](Buffer.alloc(16)); d.final();",
        ),
    ] {
        let rejected = lower_script_source_ops(
            source,
            &format!("crypto_gcm_set_auth_tag_{label}_bd_2z157.js"),
        );
        assert_eq!(
            count_hostcall_deep(&rejected, "builtin:CryptoObjectSetAuthTag"),
            0,
            "{label} setAuthTag use must remain generic"
        );
    }
}

#[test]
fn finite_buffer_hostcall_catches_require_closed_argument_shapes_bd_x10yn() {
    for (
        case_name,
        before_ops,
        setup_ops,
        capability,
        arg_count,
        expected_label,
        expected_declassification,
    ) in [
        (
            "primitive_from",
            vec![],
            vec![Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-input".into()),
            }],
            "builtin:BufferFrom",
            1,
            Label::Internal,
            false,
        ),
        (
            "primitive_alloc",
            // bd-9vouw.19: the fill value is a Secret entropy read made
            // before the protected region.
            vec![
                secret_source_op(),
                Ir1Op::StoreBinding { binding_id: 77 },
                Ir1Op::Pop,
            ],
            vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Integer(16),
                },
                Ir1Op::LoadBinding { binding_id: 77 },
            ],
            "builtin:BufferAlloc",
            2,
            Label::Secret,
            true,
        ),
        (
            "primitive_alloc_unsafe",
            vec![],
            vec![Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(16),
            }],
            "builtin:BufferAllocUnsafe",
            1,
            Label::Internal,
            false,
        ),
        (
            "fresh_closed_concat",
            vec![],
            vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String("public-input".into()),
                },
                Ir1Op::NewArray { count: 1 },
            ],
            "builtin:BufferConcat",
            1,
            Label::Internal,
            false,
        ),
        (
            "fresh_closed_concat_with_primitive_length",
            vec![],
            vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String("public-input".into()),
                },
                Ir1Op::NewArray { count: 1 },
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Integer(64),
                },
            ],
            "builtin:BufferConcat",
            2,
            Label::Internal,
            false,
        ),
        (
            "object_from_fails_high",
            vec![],
            vec![Ir1Op::NewObject { count: 0 }],
            "builtin:BufferFrom",
            1,
            Label::TopSecret,
            true,
        ),
        (
            "object_fill_alloc_fails_high",
            vec![],
            vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Integer(16),
                },
                Ir1Op::NewObject { count: 0 },
            ],
            "builtin:BufferAlloc",
            2,
            Label::TopSecret,
            true,
        ),
        (
            "unknown_element_concat_fails_high",
            vec![],
            vec![
                Ir1Op::LoadBinding { binding_id: 99 },
                Ir1Op::NewArray { count: 1 },
            ],
            "builtin:BufferConcat",
            1,
            Label::TopSecret,
            true,
        ),
        (
            "escaped_then_mutated_concat_fails_high",
            vec![],
            vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String("public-input".into()),
                },
                Ir1Op::NewArray { count: 1 },
                Ir1Op::StoreBinding { binding_id: 91 },
                Ir1Op::LoadBinding { binding_id: 91 },
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Integer(0),
                },
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String("replacement".into()),
                },
                Ir1Op::SetProperty {
                    key: Ir1PropertyKey::Dynamic,
                    strict: true,
                },
                Ir1Op::Pop,
            ],
            "builtin:BufferConcat",
            1,
            Label::TopSecret,
            true,
        ),
        (
            "branch_crossing_concat_fails_high",
            vec![],
            vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String("public-input".into()),
                },
                Ir1Op::NewArray { count: 1 },
                Ir1Op::Jump { label_id: 50 },
                Ir1Op::Label { id: 50 },
            ],
            "builtin:BufferConcat",
            1,
            Label::TopSecret,
            true,
        ),
    ] {
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(case_name.as_bytes()),
            format!("buffer_exception_{case_name}_bd_x10yn.js"),
        );
        ir1.ops.extend(before_ops);
        ir1.ops.push(Ir1Op::BeginTry {
            catch_label: 41,
            finally_label: None,
        });
        ir1.ops.extend(setup_ops);
        ir1.ops.extend([
            Ir1Op::HostCall {
                capability: capability.to_string(),
                arg_count,
            },
            Ir1Op::Pop,
            Ir1Op::EndTry,
            Ir1Op::Jump { label_id: 42 },
            Ir1Op::Label { id: 41 },
            Ir1Op::HostCall {
                capability: "console:log".to_string(),
                arg_count: 1,
            },
            Ir1Op::Pop,
            Ir1Op::Label { id: 42 },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            },
            Ir1Op::Return,
        ]);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("Buffer catch flow remains representable")
            .module;
        let console_flow = ir2
            .ops
            .iter()
            .find(|op| {
                matches!(
                    &op.inner,
                    Ir1Op::HostCall { capability, .. } if capability == "console:log"
                )
            })
            .and_then(|op| op.flow.as_ref())
            .expect("catch console flow annotation");
        assert_eq!(console_flow.data_label, expected_label, "{case_name}");
        assert_eq!(
            console_flow.declassification_required, expected_declassification,
            "{case_name}"
        );
    }
}

#[test]
fn object_keys_join_keeps_finite_own_key_provenance_bd_n8eta() {
    let literal = |value: &str| Ir1Op::LoadLiteral {
        value: Ir1Literal::String(value.into()),
    };
    // Authenticate the pure native operation in IR itself. The first-class
    // querystring module is mutable across files, so reading a method from
    // its factory result cannot vouch for this native-call contract.
    for (name, object_ops) in [
        (
            "literal",
            vec![
                literal("foo"),
                literal("bar"),
                literal("baz"),
                literal("qux"),
                Ir1Op::NewObject { count: 2 },
            ],
        ),
        (
            "querystring_parse",
            vec![
                literal("foo=bar&baz=qux"),
                Ir1Op::HostCall {
                    capability: "builtin:QuerystringParse".to_string(),
                    arg_count: 1,
                },
            ],
        ),
    ] {
        let mut native = Ir1Module::new(
            ContentHash::compute(name.as_bytes()),
            format!("native_own_keys_{name}_bd_n8eta.js"),
        );
        native.ops = object_ops;
        native.ops.extend([
            Ir1Op::StoreBinding { binding_id: 0 },
            Ir1Op::Pop,
            Ir1Op::LoadBinding { binding_id: 0 },
            Ir1Op::HostCall {
                capability: "builtin:ObjectKeys".to_string(),
                arg_count: 1,
            },
            Ir1Op::StoreBinding { binding_id: 1 },
            Ir1Op::GetProperty {
                key: Ir1PropertyKey::Static("join".into()),
            },
            Ir1Op::LoadBinding { binding_id: 1 },
            literal(","),
            Ir1Op::CallMethod { arg_count: 1 },
            Ir1Op::HostCall {
                capability: "console:log".to_string(),
                arg_count: 1,
            },
            Ir1Op::Pop,
            Ir1Op::LoadBinding { binding_id: 0 },
            Ir1Op::HostCall {
                capability: "builtin:QuerystringStringify".to_string(),
                arg_count: 1,
            },
            Ir1Op::HostCall {
                capability: "console:log".to_string(),
                arg_count: 1,
            },
            Ir1Op::Return,
        ]);
        let ir2 = lower_ir1_to_ir2(&native)
            .unwrap_or_else(|error| panic!("native {name} flow: {error}"))
            .module;
        let console_flows = ir2
            .ops
            .iter()
            .filter_map(|op| match &op.inner {
                Ir1Op::HostCall { capability, .. } if capability == "console:log" => {
                    op.flow.as_ref()
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(console_flows.len(), 2, "native {name}");
        for console_flow in console_flows {
            assert_eq!(console_flow.data_label, Label::Public, "native {name}");
            assert!(!console_flow.declassification_required, "native {name}");
        }
        let context =
            LoweringContext::new("native-keys", "native-keys-decision", "native-keys-policy");
        build_ir2_flow_proof_artifact(&ir2, &context)
            .unwrap_or_else(|error| panic!("native {name} requires no declassification: {error}"));
    }

    let mut unknown_object = Ir1Module::new(
        ContentHash::compute(b"object-keys-unknown-bd-n8eta"),
        "object_keys_unknown_bd_n8eta.js",
    );
    push_opaque_ceiling_source(&mut unknown_object.ops);
    unknown_object.ops.extend([
        Ir1Op::LoadBinding { binding_id: 404 },
        Ir1Op::HostCall {
            capability: "builtin:ObjectKeys".to_string(),
            arg_count: 1,
        },
        Ir1Op::StoreBinding { binding_id: 405 },
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Static("join".into()),
        },
        Ir1Op::LoadBinding { binding_id: 405 },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String(",".into()),
        },
        Ir1Op::CallMethod { arg_count: 1 },
        Ir1Op::HostCall {
            capability: "console:log".to_string(),
            arg_count: 1,
        },
        Ir1Op::Return,
    ]);
    let unknown_ir2 = lower_ir1_to_ir2(&unknown_object)
        .expect("unknown Object.keys input remains representable")
        .module;
    let unknown_console_flow = unknown_ir2
        .ops
        .iter()
        .find(|op| {
            matches!(&op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "console:log"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("unknown Object.keys console flow");
    assert_eq!(unknown_console_flow.data_label, Label::TopSecret);
    assert!(unknown_console_flow.declassification_required);
    let unknown_context = LoweringContext::new(
        "eval-hybrid-object-keys-unknown",
        "eval-decision-object-keys-unknown",
        "eval-policy-hybrid",
    );
    assert!(
        matches!(
            build_ir2_flow_proof_artifact(&unknown_ir2, &unknown_context),
            Err(LoweringPipelineError::UnauthorizedFlow {
                source_label: Label::TopSecret,
                sink_clearance: Label::Internal,
                ..
            })
        ),
        "unknown Object.keys must keep the TopSecret→Internal fail-closed proof"
    );
}

#[test]
fn querystring_first_class_source_keeps_mutable_method_provenance_bd_305gi() {
    for (name, source, expected_querystring_method, expected_console_labels) in [
        (
            "querystring_0010",
            "const qs = require('querystring'); const value = { foo: 'bar', baz: 'qux' }; console.log(Object.keys(value).join(',')); console.log(qs.stringify(value));",
            "stringify",
            vec![Label::Internal, Label::Internal],
        ),
        (
            "querystring_0013",
            "const qs = require('querystring'); const o = qs.parse('foo=bar&abc=xyz'); console.log(Object.keys(o).join(','), o.foo, o.abc);",
            "parse",
            vec![Label::Internal],
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source)
            .unwrap_or_else(|error| panic!("parse {name}: {error}"));
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("{name}_bd_n8eta.js"));
        let ir1 = lower_ir0_to_ir1(&ir0)
            .unwrap_or_else(|error| panic!("lower {name} to IR1: {error}"))
            .module;

        assert!(
            ir1.ops.iter().any(|op| matches!(op,
                Ir1Op::GetProperty { key: Ir1PropertyKey::Static(key) }
                    if key.as_str() == Some("keys")
            )),
            "{name} must resolve the mutable Object.keys property"
        );
        assert!(
            !ir1.ops.iter().any(|op| matches!(op,
                Ir1Op::HostCall { capability, .. }
                    if capability == "builtin:ObjectKeys"
            )),
            "{name} must not authenticate a replaceable method as an intrinsic"
        );
        // bd-305gi: querystring's first-class object replaces the direct
        // call recognizer. Read the actual, potentially replaced method.
        // A sibling module may have installed a closure or getter; the
        // factory cannot authenticate immutable native members.
        assert!(
            ir1.ops.iter().any(|op| matches!(op,
                Ir1Op::HostCall { capability, arg_count: 0 }
                    if capability == "builtin:QuerystringModule"
            )),
            "{name} must materialize the querystring module"
        );
        assert!(
            ir1.ops.iter().any(|op| matches!(op,
                Ir1Op::GetProperty { key: Ir1PropertyKey::Static(key) }
                    if key.as_str() == Some(expected_querystring_method)
            )),
            "{name} must observe the querystring method property"
        );
        assert!(
            ir1.ops.iter().any(|op| matches!(op,
                Ir1Op::GetProperty { key: Ir1PropertyKey::Static(key) }
                    if key.as_str() == Some("join")
            )),
            "{name} must retain the Array.prototype.join observation"
        );

        let ir2 = lower_ir1_to_ir2(&ir1)
            .unwrap_or_else(|error| panic!("lower {name} to IR2: {error}"))
            .module;
        let console_flows = ir2
            .ops
            .iter()
            .filter_map(|op| match &op.inner {
                Ir1Op::HostCall { capability, .. } if capability == "console:log" => {
                    op.flow.as_ref()
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            console_flows.len(),
            expected_console_labels.len(),
            "{name} console flow count"
        );
        for (console_flow, expected_label) in console_flows.into_iter().zip(expected_console_labels)
        {
            assert_eq!(console_flow.data_label, expected_label, "{name}");
            assert!(
                !console_flow.declassification_required,
                "{name} must not require a TopSecret-to-Internal declassification"
            );
        }

        // These source programs introduce no confidential source. Their
        // dynamic method results remain conservatively Internal; the
        // native-call Public contract is tested separately above.
        // HybridRouter.eval denies at build_ir2_flow_proof_artifact, not
        // at IR2 annotation. Pin the live 0010/0013 sources through that
        // same lattice check under the trusted-eval grant.
        let eval_context = LoweringContext::new(
            format!("eval-hybrid-{name}"),
            format!("eval-decision-{name}"),
            "eval-policy-hybrid",
        )
        .with_ambient_authority_grant(AmbientAuthorityGrant::TrustedProcessShape);
        if let Err(error) = build_ir2_flow_proof_artifact(&ir2, &eval_context) {
            panic!("{name} must lower without UnauthorizedFlow: {error}");
        }
        lower_ir0_to_ir3(&ir0, &eval_context)
            .unwrap_or_else(|error| panic!("{name} eval-equivalent IR0→IR3 must succeed: {error}"));
    }
}

#[test]
fn object_keys_join_keeps_mutable_provenance_over_callable_aggregates_bd_lmchj() {
    // Source Object.keys resolves a mutable method even for a literal
    // aggregate. Its call can execute guest code, so retain the program's
    // Internal bound. The authenticated native Public contract is covered
    // by object_keys_join_keeps_finite_own_key_provenance_bd_n8eta.
    let callable_source = "function f() { return 5; } const o = { a: 1, g: f }; console.log(Object.keys(o).join('|'));";
    let tree = crate::parser_api_stability::parse_script(callable_source)
        .expect("callable aggregate source parses");
    let ir0 = Ir0Module::from_syntax_tree(tree, "callable_aggregate_bd_lmchj.js".to_string());
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("callable aggregate lowers to IR1")
        .module;
    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("callable aggregate lowers to IR2")
        .module;
    let console_flow = ir2
        .ops
        .iter()
        .find(|op| {
            matches!(&op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "console:log"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("callable aggregate console flow");
    assert_eq!(console_flow.data_label, Label::Internal);
    assert!(
        !console_flow.declassification_required,
        "callable aggregate keys().join must not require declassification"
    );
    let eval_context = LoweringContext::new(
        "eval-hybrid-callable-aggregate",
        "eval-decision-callable-aggregate",
        "eval-policy-hybrid",
    )
    .with_ambient_authority_grant(AmbientAuthorityGrant::TrustedProcessShape);
    if let Err(error) = build_ir2_flow_proof_artifact(&ir2, &eval_context) {
        panic!("callable aggregate must lower without UnauthorizedFlow: {error}");
    }
    lower_ir0_to_ir3(&ir0, &eval_context)
        .expect("callable aggregate lowers to IR3 under the eval grant");

    // Post-store aggregates stay fail-closed: a SetProperty may invoke a
    // guest setter, which voids closed-shape proofs, so keys().join over
    // the mutated binding keeps the TopSecret→Internal contract.
    let stored_source = format!(
        "{OPAQUE_CEILING_SOURCE}const o = {{}}; o.a = 1; console.log(Object.keys(o).join('|'));"
    );
    let stored_tree = crate::parser_api_stability::parse_script(&stored_source)
        .expect("stored aggregate source parses");
    let stored_ir0 =
        Ir0Module::from_syntax_tree(stored_tree, "stored_aggregate_bd_lmchj.js".to_string());
    let stored_ir1 = lower_ir0_to_ir1(&stored_ir0)
        .expect("stored aggregate lowers to IR1")
        .module;
    let stored_ir2 = lower_ir1_to_ir2(&stored_ir1)
        .expect("stored aggregate lowers to IR2")
        .module;
    let stored_console_flow = stored_ir2
        .ops
        .iter()
        .find(|op| {
            matches!(&op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "console:log"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("stored aggregate console flow");
    assert_eq!(stored_console_flow.data_label, Label::TopSecret);
    assert!(stored_console_flow.declassification_required);
    let stored_context = LoweringContext::new(
        "eval-hybrid-stored-aggregate",
        "eval-decision-stored-aggregate",
        "eval-policy-hybrid",
    )
    .with_ambient_authority_grant(AmbientAuthorityGrant::TrustedProcessShape);
    assert!(
        matches!(
            build_ir2_flow_proof_artifact(&stored_ir2, &stored_context),
            Err(LoweringPipelineError::UnauthorizedFlow {
                source_label: Label::TopSecret,
                sink_clearance: Label::Internal,
                ..
            })
        ),
        "post-store keys().join must keep the fail-closed proof"
    );
}

#[test]
fn eventemitter_emit_error_try_catch_message_sinks_finite_bd_kx70h() {
    fn lower_source_to_ir2(name: &str, source: &str) -> Ir2Module {
        let tree = crate::parser_api_stability::parse_script(source)
            .unwrap_or_else(|error| panic!("parse {name}: {error}"));
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("{name}_bd_kx70h.js"));
        let ir1 = lower_ir0_to_ir1(&ir0)
            .unwrap_or_else(|error| panic!("lower {name} to IR1: {error}"))
            .module;
        lower_ir1_to_ir2(&ir1)
            .unwrap_or_else(|error| panic!("lower {name} to IR2: {error}"))
            .module
    }
    // The exact compatibility-corpus shape (bd-kx70h / events::0017):
    // destructured EventEmitter constructor, emit('error', ...) inside
    // try, err.message sunk to console:log in the catch. Before the
    // fix, the `.emit` member read fail-highed the catch region as
    // TopSecret and the whole module was refused.
    let ir2 = lower_source_to_ir2(
        "emit_error_try_catch",
        "const {EventEmitter} = require('events');\n\
         const e = new EventEmitter();\n\
         try {\n\
           e.emit('error', new Error('boom'));\n\
           console.log('no-throw');\n\
         } catch (err) {\n\
           console.log('threw:' + err.message);\n\
         }\n",
    );
    let top_secret_sinks = ir2
        .ops
        .iter()
        .filter_map(|op| op.flow.as_ref())
        .any(|flow| {
            matches!(flow.data_label, Label::TopSecret)
                && matches!(flow.sink_clearance, Label::Internal)
        });
    assert!(
        !top_secret_sinks,
        "emit-in-try catch region must not poison err.message sinks"
    );
}

#[test]
fn getproperty_exception_finiteness_contract_bd_kx70h() {
    // Direct contract for the audited arm: a static read on a CLOSED
    // receiver is exception-finite (engine-owned TypeError at worst);
    // with the finiteness flag unset the read stays fail-high.
    // (Source-level dynamic-key probes fold `const k = 'a'` to a static
    // key during lowering, so the contract is pinned here on the exact
    // flag inputs instead.)
    let op = Ir1Op::GetProperty {
        key: Ir1PropertyKey::Static("emit".to_string().into()),
    };
    assert_eq!(
        ir1_exception_flow_label(&op, &Label::Public, true, false),
        Some(Label::Internal.join(&Label::Public))
    );
    assert_eq!(
        ir1_exception_flow_label(&op, &Label::Public, false, false),
        Some(Label::TopSecret),
        "flag must gate the finite-read arm"
    );
}

#[test]
fn fresh_aggregate_static_read_in_try_stays_fail_high_bd_kx70h() {
    // FreshAggregate is guest-mutable (Object.defineProperty can attach
    // accessors), so it is deliberately excluded from the finite-read
    // brand list: the try/catch read stays fail-closed.
    // Without an opaque source this exact program has nothing above
    // Internal and is admitted (bd-9vouw.1); the fail-high rule is pinned
    // under a TopSecret ceiling.
    let source = format!(
        "{OPAQUE_CEILING_SOURCE}const o = {{a: 1}};\n\
         try {{\n\
           const v = o.a;\n\
           console.log(v);\n\
         }} catch (err) {{\n\
           console.log('e:' + err.message);\n\
         }}\n"
    );
    let tree =
        crate::parser_api_stability::parse_script(&source).expect("fresh aggregate probe parses");
    let ir0 = Ir0Module::from_syntax_tree(tree, "fresh_aggregate_bd_kx70h.js".to_string());
    let ir1 = lower_ir0_to_ir1(&ir0)
        .unwrap_or_else(|error| panic!("fresh aggregate probe lowers to IR1: {error}"))
        .module;
    let ir2 = lower_ir1_to_ir2(&ir1)
        .unwrap_or_else(|error| panic!("fresh aggregate probe lowers to IR2: {error}"))
        .module;
    let context = LoweringContext::new(
        "eval-hybrid-fresh-aggregate",
        "eval-decision-fresh-aggregate",
        "eval-policy-hybrid",
    );
    let result = build_ir2_flow_proof_artifact(&ir2, &context).map(|_| ());
    assert!(
        matches!(
            result,
            Err(LoweringPipelineError::UnauthorizedFlow {
                source_label: Label::TopSecret,
                ..
            })
        ),
        "FreshAggregate reads in try must stay fail-closed, got {result:?}"
    );
}

#[test]
fn bounded_imports_contract_only_when_a_local_import_needs_it_bd_j8f7q() {
    fn lower_module(source: &str) -> Result<LoweringPipelineOutput, LoweringPipelineError> {
        let tree = crate::parser_api_stability::parse_module(source)
            .unwrap_or_else(|error| panic!("parse {source}: {error}"));
        lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "bounded_imports_bd_j8f7q.mjs"),
            &LoweringContext::new("trace-j8f7q", "decision-j8f7q", "policy-j8f7q"),
        )
    }
    let has_contract = |output: &LoweringPipelineOutput| {
        output.ir3.instructions.iter().any(|instruction| {
            matches!(instruction, Ir3Instruction::HostCall { capability, .. }
                if capability.0 == IFC_BOUNDED_IMPORTS_CONTRACT)
        })
    };

    // Printing an imported function's result is refused without the
    // contract, so the unit is lowered with it, under an Internal ceiling.
    let bounded = lower_module("import { f } from './lib.mjs';\nconsole.log(f());")
        .expect("a local import may be bounded");
    assert!(has_contract(&bounded));
    assert_eq!(
        lowered_unit_flow_label_ceiling(&bounded.ir2, HostIoExceptionProvenance::Unknown),
        Label::Internal
    );

    // A unit that passes as it is gets no contract; its ceiling stays
    // TopSecret, so no importer constraint is created.
    let plain = lower_module("import { f } from './lib.mjs';\nf();")
        .expect("calling without printing is allowed");
    assert!(!has_contract(&plain));
    assert_eq!(
        lowered_unit_flow_label_ceiling(&plain.ir2, HostIoExceptionProvenance::Unknown),
        Label::TopSecret
    );

    // A package import is bounded too (its code is checked at load);
    // a Node core module has no module code to check and stays opaque.
    let package = lower_module("import { f } from 'some-package';\nconsole.log(f());")
        .expect("a package import may be bounded");
    assert!(has_contract(&package));
    let error = lower_module("import { f } from 'node:worker_threads';\nconsole.log(f());")
        .expect_err("a core module import is not bounded");
    assert!(matches!(
        error,
        LoweringPipelineError::UnauthorizedFlow { .. }
    ));
    assert!(is_bounded_import_specifier("./a.mjs"));
    assert!(is_bounded_import_specifier("../a.mjs"));
    assert!(is_bounded_import_specifier("/abs/a.mjs"));
    assert!(is_bounded_import_specifier("pkg/sub"));
    assert!(is_bounded_import_specifier("@scope/pkg"));
    assert!(is_bounded_import_specifier("node:fs"));
    assert!(is_bounded_import_specifier("fs"));
    for name in ["node:buffer", "events", "path", "node:path/posix"] {
        let source = format!("import value from '{name}'; console.log(typeof value);");
        let tree = crate::parser_api_stability::parse_module(&source).unwrap();
        let output = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "native-bounded.mjs"),
            &LoweringContext::new("native", "native", "native")
                .with_preserved_runtime_module_loads(),
        )
        .expect("authenticated native imports have a checked runtime bound");
        assert!(has_contract(&output), "{name}");
        assert_eq!(
            lowered_unit_flow_label_ceiling(&output.ir2, HostIoExceptionProvenance::Unknown,),
            Label::Internal
        );
    }
}

#[test]
fn builtin_construct_and_catch_provenance_stays_exact_bd_zyndq() {
    fn lower_source(name: &str, source: &str) -> (Ir0Module, Ir2Module) {
        let tree = crate::parser_api_stability::parse_script(source)
            .unwrap_or_else(|error| panic!("parse {name}: {error}"));
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("{name}_bd_zyndq.js"));
        let ir1 = lower_ir0_to_ir1(&ir0)
            .unwrap_or_else(|error| panic!("lower {name} to IR1: {error}"))
            .module;
        let ir2 = lower_ir1_to_ir2(&ir1)
            .unwrap_or_else(|error| panic!("lower {name} to IR2: {error}"))
            .module;
        (ir0, ir2)
    }

    for (name, source, expected_console_count, expected_label) in [
        (
            // The source property can be replaced with a guest constructor;
            // only the explicit native factory proves callable-only shape.
            "mutable_callable_catch",
            "const probe=(Array.isArray); let outcome='unset'; try { new probe([]); outcome='constructed'; } catch (error) { outcome='caught'; } console.log(outcome); console.log('alive:' + probe([]));",
            2,
            Label::Internal,
        ),
        (
            "function_constructor",
            "const generated = new Function('return 7'); console.log('fn:' + generated());",
            1,
            Label::Internal,
        ),
    ] {
        let (ir0, ir2) = lower_source(name, source);
        let console_flows = ir2
            .ops
            .iter()
            .filter_map(|op| match &op.inner {
                Ir1Op::HostCall { capability, .. } if capability == "console:log" => {
                    op.flow.as_ref()
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(console_flows.len(), expected_console_count, "{name}");
        assert!(
            console_flows.iter().all(|flow| {
                flow.data_label == expected_label && !flow.declassification_required
            })
        );

        let context = LoweringContext::new(
            format!("eval-hybrid-{name}"),
            format!("eval-decision-{name}"),
            "eval-policy-hybrid",
        )
        .with_ambient_authority_grant(AmbientAuthorityGrant::TrustedProcessShape);
        build_ir2_flow_proof_artifact(&ir2, &context)
            .unwrap_or_else(|error| panic!("{name} flow proof: {error}"));
        lower_ir0_to_ir3(&ir0, &context)
            .unwrap_or_else(|error| panic!("{name} eval-equivalent IR0→IR3: {error}"));
    }

    // bd-kx70h refinement: `new` over a closed non-callable aggregate
    // can only raise the engine's own TypeError (fresh data objects
    // carry no guest constructors and no accessors), so the catch
    // provenance is exact Internal — not the old blanket TopSecret.
    // The guest-callable fail-high contract lives in
    // unknown_callable_construct_in_try_stays_fail_high_bd_kx70h.
    let (aggregate_ctor_ir0, aggregate_ctor_ir2) = lower_source(
        "unknown_constructor",
        "const ctor={}; try { new ctor(); } catch (error) { console.log(error); }",
    );
    let aggregate_ctor_context = LoweringContext::new(
        "eval-hybrid-unknown-constructor",
        "eval-decision-unknown-constructor",
        "eval-policy-hybrid",
    );
    build_ir2_flow_proof_artifact(&aggregate_ctor_ir2, &aggregate_ctor_context).unwrap_or_else(
        |error| panic!("closed-aggregate constructor catch must lower exactly: {error}"),
    );
    lower_ir0_to_ir3(&aggregate_ctor_ir0, &aggregate_ctor_context).unwrap_or_else(|error| {
        panic!("closed-aggregate constructor eval-equivalent IR0→IR3: {error}")
    });
}

#[test]
fn authenticated_buffer_object_calls_lower_exact_product_shapes_bd_nx5cb() {
    for (case_name, source, capability, expected_arg_count) in [
        (
            "direct_to_string",
            "try { Buffer.from('abc').toString('bogus'); } catch (error) { console.log(error); }",
            "builtin:BufferObjectToString",
            2,
        ),
        (
            "bound_read_uint32_le",
            "const b=Buffer.alloc(2); try { b.readUInt32LE(0); } catch (error) { console.log(error); }",
            "builtin:BufferObjectReadUInt32LE",
            2,
        ),
        (
            "zero_arg_read_uint32_le",
            "const b=Buffer.alloc(2); try { b.readUInt32LE(); } catch (error) { console.log(error); }",
            "builtin:BufferObjectReadUInt32LE",
            1,
        ),
        (
            "fractional_offset",
            "const b=Buffer.alloc(4); try { b.readUInt32LE(0.5); } catch (error) { console.log(error); }",
            "builtin:BufferObjectReadUInt32LE",
            2,
        ),
        (
            "float_factory_length",
            "const b=Buffer.alloc(4.0); try { b.readUInt32LE(0); } catch (error) { console.log(error); }",
            "builtin:BufferObjectReadUInt32LE",
            2,
        ),
        (
            "function_local_alias",
            "function read(){ const b=Buffer.alloc(2); try { b.readUInt32LE(0); } catch (error) { console.log(error); } } read();",
            "builtin:BufferObjectReadUInt32LE",
            2,
        ),
        (
            "function_expression_local_alias",
            "(function(){ const b=Buffer.alloc(2); try { b.readUInt32LE(0); } catch (error) { console.log(error); } }());",
            "builtin:BufferObjectReadUInt32LE",
            2,
        ),
        (
            "arrow_block_local_alias",
            "(()=>{ const b=Buffer.alloc(2); try { b.readUInt32LE(0); } catch (error) { console.log(error); } })();",
            "builtin:BufferObjectReadUInt32LE",
            2,
        ),
        (
            "class_method_local_alias",
            "class Reader { read(){ const b=Buffer.alloc(2); try { b.readUInt32LE(0); } catch (error) { console.log(error); } } } new Reader().read();",
            "builtin:BufferObjectReadUInt32LE",
            2,
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source)
            .expect("parse authenticated Buffer object source");
        let ir0 =
            Ir0Module::from_syntax_tree(tree, format!("buffer_object_{case_name}_bd_nx5cb.js"));
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("lower authenticated Buffer object source")
            .module;
        assert_eq!(
            count_hostcall_deep(&ir1.ops, capability),
            1,
            "{case_name} must emit one authenticated Buffer hostcall"
        );
        assert!(ops_deep_match(&ir1.ops, &|op| matches!(
            op,
            Ir1Op::HostCall {
                capability: observed,
                arg_count,
            } if observed == capability && *arg_count == expected_arg_count
        )));

        if matches!(
            case_name,
            "function_local_alias"
                | "function_expression_local_alias"
                | "arrow_block_local_alias"
                | "class_method_local_alias"
        ) {
            // Function bodies remain nested IR1 payloads at this stage;
            // the checks above are the relevant scope-authentication
            // proof. The top-level catch-flow assertions below exercise
            // the same capabilities without pretending nested bodies
            // carry top-level IR2 annotations.
            continue;
        }

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("authenticated Buffer catch must pass finite flow analysis")
            .module;
        let console_flow = ir2
            .ops
            .iter()
            .find(|op| {
                matches!(
                    &op.inner,
                    Ir1Op::HostCall { capability, .. } if capability == "console:log"
                )
            })
            .and_then(|op| op.flow.as_ref())
            .expect("catch console flow annotation");
        assert_eq!(console_flow.data_label, Label::Internal, "{case_name}");
        assert!(
            !console_flow.declassification_required,
            "{case_name} must keep finite exception provenance"
        );
    }

    let block_shadow = lower_script_source_ops(
        "const b=Buffer.alloc(2); b.readUInt32LE(0); { const b={readUInt32LE(){return 0;}}; b.readUInt32LE(0); } b.readUInt32LE(0);",
        "buffer_object_block_shadow_bd_nx5cb.js",
    );
    assert_eq!(
        count_hostcall_deep(&block_shadow, "builtin:BufferObjectReadUInt32LE"),
        2,
        "the outer authenticated alias must be restored after a block-local shadow"
    );
    let invocation_routes = block_shadow
        .iter()
        .filter_map(|op| match op {
            Ir1Op::HostCall { capability, .. }
                if capability == "builtin:BufferObjectReadUInt32LE" =>
            {
                Some("authenticated")
            }
            Ir1Op::CallMethod { .. } => Some("generic"),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        invocation_routes,
        ["authenticated", "generic", "authenticated"],
        "the block-local shadow must stay generic between two exact outer calls"
    );
}

#[test]
fn buffer_object_rejected_uses_stay_generic_and_fail_high_bd_nx5cb() {
    for (case_name, source) in [
        (
            "mutable_binding",
            "let b=Buffer.alloc(2); b.readUInt32LE(0);",
        ),
        (
            "computed_method",
            "const b=Buffer.alloc(2); b['readUInt32LE'](0);",
        ),
        (
            "optional_member",
            "const b=Buffer.alloc(2); b?.readUInt32LE(0);",
        ),
        (
            "optional_call",
            "const b=Buffer.alloc(2); b.readUInt32LE?.(0);",
        ),
        (
            "detached_method",
            "const b=Buffer.alloc(2); const read=b.readUInt32LE; read(0);",
        ),
        (
            "own_override",
            "const b=Buffer.alloc(2); b.readUInt32LE=()=>0; b.readUInt32LE(0);",
        ),
        (
            "indexed_mutation",
            "const b=Buffer.alloc(4); b[0]=1; b.readUInt32LE(0);",
        ),
        (
            "alias_transfer",
            "const b=Buffer.alloc(2); const other=b; other.readUInt32LE(0);",
        ),
        (
            "nested_capture",
            "const b=Buffer.alloc(2); function read(){ return b.readUInt32LE(0); } read();",
        ),
        (
            "function_local_nested_capture",
            "function outer(){ const b=Buffer.alloc(2); function read(){ return b.readUInt32LE(0); } return read(); } outer();",
        ),
        (
            "arrow_capture",
            "const b=Buffer.alloc(2); const read=()=>b.readUInt32LE(0); read();",
        ),
        (
            "class_capture",
            "const b=Buffer.alloc(2); class Reader { read(){ return b.readUInt32LE(0); } } new Reader().read();",
        ),
        (
            "predeclaration",
            "b.readUInt32LE(0); const b=Buffer.alloc(2);",
        ),
        (
            "function_local_predeclaration",
            "function read(){ b.readUInt32LE(0); const b=Buffer.alloc(2); } read();",
        ),
        (
            "self_reference",
            "const b=Buffer.from(b); b.toString('hex');",
        ),
        ("spread", "const b=Buffer.alloc(2); b.readUInt32LE(...[0]);"),
        (
            "shadowed_global",
            "const Buffer={alloc(){return {readUInt32LE(){return 0;}}}}; const b=Buffer.alloc(2); b.readUInt32LE(0);",
        ),
        (
            "function_outer_buffer_shadow",
            "const Buffer={alloc(){return {readUInt32LE(){return 0;}}}}; function read(){ const b=Buffer.alloc(2); return b.readUInt32LE(0); } read();",
        ),
        (
            "function_local_buffer_tdz_shadow",
            "function read(){ const b=Buffer.alloc(2); const Buffer={alloc(){return {readUInt32LE(){return 0;}}}}; return b.readUInt32LE(0); } read();",
        ),
        (
            "computed_factory",
            "const b=Buffer['alloc'](2); b.readUInt32LE(0);",
        ),
        (
            "factory_object_argument",
            "const b=Buffer.from({valueOf(){throw 'secret';}}); b.toString('hex');",
        ),
        (
            "forged_object",
            "const b={readUInt32LE(){return 0;}}; b.readUInt32LE(0);",
        ),
        (
            "uint8_array",
            "const b=new Uint8Array(2); b.readUInt32LE(0);",
        ),
        (
            "object_encoding",
            "const b=Buffer.from('a'); b.toString({toString(){throw 'secret';}});",
        ),
        (
            "object_offset",
            "const b=Buffer.alloc(2); b.readUInt32LE({valueOf(){throw 'secret';}});",
        ),
    ] {
        let ops = lower_script_source_ops(
            source,
            &format!("buffer_object_rejected_{case_name}_bd_nx5cb.js"),
        );
        for capability in [
            "builtin:BufferObjectToString",
            "builtin:BufferObjectReadUInt32LE",
        ] {
            assert_eq!(
                count_hostcall_deep(&ops, capability),
                0,
                "{case_name} must not authenticate {capability}"
            );
        }
        assert!(
            ops_deep_match(&ops, &|op| matches!(
                op,
                Ir1Op::Call { .. } | Ir1Op::CallMethod { .. }
            )) || count_hostcall_deep(&ops, "builtin:ReflectApply") > 0,
            "{case_name} must retain ordinary JavaScript invocation semantics"
        );
    }

    for (case_name, receiver_setup) in [
        ("forged_ir", vec![Ir1Op::NewObject { count: 0 }]),
        (
            "mutated_shape",
            vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Integer(2),
                },
                Ir1Op::HostCall {
                    capability: "builtin:BufferAlloc".to_string(),
                    arg_count: 1,
                },
                Ir1Op::StoreBinding { binding_id: 77 },
                Ir1Op::LoadBinding { binding_id: 77 },
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String("readUInt32LE".into()),
                },
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined,
                },
                Ir1Op::SetProperty {
                    key: Ir1PropertyKey::Dynamic,
                    strict: true,
                },
                Ir1Op::Pop,
                Ir1Op::LoadBinding { binding_id: 77 },
            ],
        ),
    ] {
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(case_name.as_bytes()),
            format!("buffer_object_flow_{case_name}_bd_nx5cb.js"),
        );
        push_opaque_ceiling_source(&mut ir1.ops);
        ir1.ops.push(Ir1Op::BeginTry {
            catch_label: 81,
            finally_label: None,
        });
        ir1.ops.extend(receiver_setup);
        ir1.ops.extend([
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(0),
            },
            Ir1Op::HostCall {
                capability: "builtin:BufferObjectReadUInt32LE".to_string(),
                arg_count: 2,
            },
            Ir1Op::Pop,
            Ir1Op::EndTry,
            Ir1Op::Jump { label_id: 82 },
            Ir1Op::Label { id: 81 },
            Ir1Op::HostCall {
                capability: "console:log".to_string(),
                arg_count: 1,
            },
            Ir1Op::Pop,
            Ir1Op::Label { id: 82 },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            },
            Ir1Op::Return,
        ]);
        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("forged Buffer object IR remains representable but fail-high")
            .module;
        let console_flow = ir2
            .ops
            .iter()
            .find(|op| {
                matches!(
                    &op.inner,
                    Ir1Op::HostCall { capability, .. } if capability == "console:log"
                )
            })
            .and_then(|op| op.flow.as_ref())
            .expect("forged catch console flow annotation");
        assert_eq!(console_flow.data_label, Label::TopSecret, "{case_name}");
        assert!(console_flow.declassification_required, "{case_name}");
    }
}

#[test]
fn operand_derived_nested_hostcalls_preserve_closed_stack_values_bd_1by6p() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"nested-closed-hostcalls"),
        "nested_closed_hostcalls_bd_1by6p.js",
    );
    ir1.ops.extend([
        Ir1Op::BeginTry {
            catch_label: 41,
            finally_label: None,
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("left".into()),
        },
        Ir1Op::HostCall {
            capability: "builtin:BufferFrom".to_string(),
            arg_count: 1,
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("right".into()),
        },
        Ir1Op::HostCall {
            capability: "builtin:BufferFrom".to_string(),
            arg_count: 1,
        },
        Ir1Op::HostCall {
            capability: "builtin:CryptoTimingSafeEqual".to_string(),
            arg_count: 2,
        },
        Ir1Op::Pop,
        Ir1Op::EndTry,
        Ir1Op::Jump { label_id: 42 },
        Ir1Op::Label { id: 41 },
        Ir1Op::HostCall {
            capability: "console:log".to_string(),
            arg_count: 1,
        },
        Ir1Op::Pop,
        Ir1Op::Label { id: 42 },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Return,
    ]);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("nested finite hostcalls retain closed argument provenance")
        .module;
    let console_flow = ir2
        .ops
        .iter()
        .find(|op| {
            matches!(
                &op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "console:log"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("nested hostcall catch console flow annotation");
    assert_eq!(console_flow.data_label, Label::Internal);
    assert!(!console_flow.declassification_required);
}

#[test]
fn native_binary_constructors_retain_closed_catch_provenance_bd_1by6p() {
    let tree = crate::parser_api_stability::parse_script(
        "const crypto = require('crypto');\
         const binary = new ArrayBuffer(4);\
         try {\
           const hash = crypto.createHash('sha256');\
           hash.update(binary);\
         } catch (error) {\
           console.log(error instanceof TypeError);\
         }",
    )
    .expect("parse native binary constructor catch source");
    let ir0 = Ir0Module::from_syntax_tree(tree, "binary_constructor_catch_bd_1by6p.js");
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("lower native binary constructor catch source")
        .module;
    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("native binary constructor catch remains finite")
        .module;
    let console_flow = ir2
        .ops
        .iter()
        .find(|op| {
            matches!(
                &op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "console:log"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("native binary constructor catch console flow annotation");
    assert_eq!(console_flow.data_label, Label::Internal);
    assert!(!console_flow.declassification_required);
}

#[test]
fn callback_capable_buffer_method_catch_stays_top_secret_bd_x10yn() {
    let source = format!(
        "{OPAQUE_CEILING_SOURCE}try {{ Buffer.from('x').map(value => {{ throw 'secret-token'; }}); }} \
         catch (error) {{ console.log(error); }}"
    );
    let tree = crate::parser_api_stability::parse_script(&source)
        .expect("parse callback-capable Buffer source");
    let ir0 = Ir0Module::from_syntax_tree(tree, "buffer_callback_catch_bd_x10yn.js");
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("lower callback-capable Buffer source")
        .module;
    assert!(ops_deep_match(&ir1.ops, &|op| matches!(
        op,
        Ir1Op::CallMethod { .. }
    )));

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("callback-capable Buffer catch remains representable")
        .module;
    let console_flow = ir2
        .ops
        .iter()
        .find(|op| {
            matches!(
                &op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "console:log"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("catch console flow annotation");
    assert_eq!(console_flow.data_label, Label::TopSecret);
    assert!(console_flow.declassification_required);
}

#[test]
fn crypto_object_alias_rejected_uses_never_gain_finite_dispatch_bd_1by6p() {
    for (label, source) in [
        (
            "mutated",
            "const crypto=require('crypto'); const d=crypto.createDecipheriv('aes-256-cbc',Buffer.alloc(32),Buffer.alloc(16)); d.final=()=>{}; d.final();",
        ),
        (
            "computed",
            "const crypto=require('crypto'); const d=crypto.createDecipheriv('aes-256-cbc',Buffer.alloc(32),Buffer.alloc(16)); d['final']();",
        ),
        (
            "detached",
            "const crypto=require('crypto'); const d=crypto.createDecipheriv('aes-256-cbc',Buffer.alloc(32),Buffer.alloc(16)); const f=d.final; f();",
        ),
        (
            "escaped",
            "const crypto=require('crypto'); const d=crypto.createDecipheriv('aes-256-cbc',Buffer.alloc(32),Buffer.alloc(16)); consume(d); d.final();",
        ),
        (
            "captured",
            "const crypto=require('crypto'); const d=crypto.createDecipheriv('aes-256-cbc',Buffer.alloc(32),Buffer.alloc(16)); function later(){ d.final(); } later();",
        ),
        (
            "direct_predeclaration",
            "const crypto=require('crypto'); d.final(); const d=crypto.createDecipheriv('aes-256-cbc',Buffer.alloc(32),Buffer.alloc(16));",
        ),
        (
            "hoisted_predeclaration_capture",
            "const crypto=require('crypto'); later(); const d=crypto.createDecipheriv('aes-256-cbc',Buffer.alloc(32),Buffer.alloc(16)); function later(){ d.final(); }",
        ),
        (
            "hash_result_alias",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); const x=h.update('public'); x.update('secret-token'); console.log(h.digest('hex'));",
        ),
        (
            "hash_copy_result_escape",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); const x=h.copy(); consume(x); console.log(h.digest('hex'));",
        ),
        (
            "hash_copy_argument_escape",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); const x=h.copy().update(consume(h)); console.log(h.digest('hex')); console.log(x.digest('hex'));",
        ),
        (
            "hash_copy_mutable_target",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); let x=h.copy(); console.log(h.digest('hex')); console.log(x.digest('hex'));",
        ),
        (
            "named_hash_export",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); export { h }; console.log(h.digest('hex'));",
        ),
        (
            "default_hash_export",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); export default h; console.log(h.digest('hex'));",
        ),
        (
            "hash_factory_self_reference",
            "const crypto=require('crypto'); const h=crypto.createHash(h); console.log(h.digest('hex'));",
        ),
        (
            "hash_copy_target_self_reference",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); const x=h.copy().update(x); console.log(h.digest('hex')); console.log(x.digest('hex'));",
        ),
        (
            "arrow_expression_capture",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); const mutate=()=>h.update('secret-token'); mutate(); console.log(h.digest('hex'));",
        ),
        (
            "arrow_block_capture",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); const mutate=()=>{ h.update('secret-token'); }; mutate(); console.log(h.digest('hex'));",
        ),
        (
            "default_parameter_capture",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); function mutate(value=h.update('secret-token')){} mutate(); console.log(h.digest('hex'));",
        ),
        (
            "default_parameter_body_shadow",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); function mutate(value=h.update('secret-token')){ const h=0; } mutate(); console.log(h.digest('hex'));",
        ),
        (
            "function_expression_default_body_shadow",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); const mutate=function(value=h.update('secret-token')){ const h=0; }; mutate(); console.log(h.digest('hex'));",
        ),
        (
            "class_default_body_shadow",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); class Mutator { run(value=h.update('secret-token')){ const h=0; } } new Mutator().run(); console.log(h.digest('hex'));",
        ),
        (
            "class_method_capture",
            "const crypto=require('crypto'); const h=crypto.createHash('sha256'); class Mutator { run(){ h.update('secret-token'); } } new Mutator().run(); console.log(h.digest('hex'));",
        ),
        (
            "hmac_copy",
            "const crypto=require('crypto'); const h=crypto.createHmac('sha256','key'); h.copy(); console.log(h.digest('hex'));",
        ),
        ("forged", "const d={__type:'Cipher',final(){}}; d.final();"),
    ] {
        let source_label = format!("crypto_object_{label}_bd_1by6p.js");
        let ops = if matches!(label, "named_hash_export" | "default_hash_export") {
            lower_esm_source_ops(source, &source_label)
        } else {
            lower_script_source_ops(source, &source_label)
        };
        for capability in [
            "builtin:CryptoObjectUpdate",
            "builtin:CryptoObjectDigest",
            "builtin:CryptoObjectCopy",
            "builtin:CryptoObjectFinal",
            "builtin:CryptoObjectGetAuthTag",
            "builtin:CryptoObjectSetAuthTag",
        ] {
            assert_eq!(
                count_hostcall_deep(&ops, capability),
                0,
                "{label} must not authenticate {capability}"
            );
        }
        let retains_inert_generic_invocation =
            ops_deep_match(&ops, &|op| matches!(op, Ir1Op::CallMethod { .. }))
                || (label == "detached"
                    && ops_deep_match(&ops, &|op| matches!(op, Ir1Op::Call { .. })));
        assert!(
            retains_inert_generic_invocation,
            "{label} must retain an inert generic Call/CallMethod rather than finite crypto dispatch"
        );
    }
}

#[test]
fn crypto_lifecycle_flow_persists_across_update_and_into_catch_bd_1by6p() {
    // bd-9vouw.19: the secret update input is an entropy read.
    for (update_value, expected_label, expected_declassification) in [
        ("public-input", Label::Internal, false),
        ("entropy", Label::Secret, true),
    ] {
        let update_op = if update_value == "entropy" {
            secret_source_op()
        } else {
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String(update_value.into()),
            }
        };
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(update_value.as_bytes()),
            format!("crypto_lifecycle_{update_value}_bd_1by6p.js"),
        );
        ir1.ops.extend([
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("aes-256-cbc".into()),
            },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-key".into()),
            },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-iv".into()),
            },
            Ir1Op::HostCall {
                capability: "builtin:CryptoCreateDecipheriv".to_string(),
                arg_count: 3,
            },
            Ir1Op::StoreBinding { binding_id: 7 },
            Ir1Op::Pop,
            Ir1Op::LoadBinding { binding_id: 7 },
            update_op,
            Ir1Op::HostCall {
                capability: "builtin:CryptoObjectUpdate".to_string(),
                arg_count: 2,
            },
            Ir1Op::Pop,
            Ir1Op::BeginTry {
                catch_label: 41,
                finally_label: None,
            },
            Ir1Op::LoadBinding { binding_id: 7 },
            Ir1Op::HostCall {
                capability: "builtin:CryptoObjectFinal".to_string(),
                arg_count: 1,
            },
            Ir1Op::Pop,
            Ir1Op::EndTry,
            Ir1Op::Jump { label_id: 42 },
            Ir1Op::Label { id: 41 },
            Ir1Op::HostCall {
                capability: "console:log".to_string(),
                arg_count: 1,
            },
            Ir1Op::Pop,
            Ir1Op::Label { id: 42 },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            },
            Ir1Op::Return,
        ]);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("authenticated lifecycle flow lowering")
            .module;
        let console_flow = ir2
            .ops
            .iter()
            .find(|op| {
                matches!(
                    &op.inner,
                    Ir1Op::HostCall { capability, .. } if capability == "console:log"
                )
            })
            .and_then(|op| op.flow.as_ref())
            .expect("catch console flow annotation");
        assert_eq!(console_flow.data_label, expected_label, "{update_value}");
        assert_eq!(
            console_flow.declassification_required, expected_declassification,
            "{update_value}"
        );
    }
}

#[test]
fn crypto_set_auth_tag_catch_joins_receiver_and_tag_bd_1by6p() {
    // bd-9vouw.19: the secret tag is a UUID string read before the
    // protected region, so only setAuthTag's own failure reaches the catch.
    for (tag_value, expected_label, expected_declassification) in [
        ("public-auth-tag", Label::Internal, false),
        ("entropy", Label::Secret, true),
    ] {
        let (tag_setup, tag_op) = if tag_value == "entropy" {
            (
                vec![
                    secret_string_op(),
                    Ir1Op::StoreBinding { binding_id: 9 },
                    Ir1Op::Pop,
                ],
                Ir1Op::LoadBinding { binding_id: 9 },
            )
        } else {
            (
                Vec::new(),
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String(tag_value.into()),
                },
            )
        };
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(tag_value.as_bytes()),
            format!("crypto_set_auth_tag_{tag_value}_bd_1by6p.js"),
        );
        ir1.ops.extend([
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("aes-256-gcm".into()),
            },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-key".into()),
            },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-iv".into()),
            },
            Ir1Op::HostCall {
                capability: "builtin:CryptoCreateDecipheriv".to_string(),
                arg_count: 3,
            },
            Ir1Op::StoreBinding { binding_id: 7 },
            Ir1Op::Pop,
        ]);
        ir1.ops.extend(tag_setup);
        ir1.ops.extend([
            Ir1Op::BeginTry {
                catch_label: 41,
                finally_label: None,
            },
            Ir1Op::LoadBinding { binding_id: 7 },
            tag_op,
            Ir1Op::HostCall {
                capability: "builtin:CryptoObjectSetAuthTag".to_string(),
                arg_count: 2,
            },
            Ir1Op::Pop,
            Ir1Op::EndTry,
            Ir1Op::Jump { label_id: 42 },
            Ir1Op::Label { id: 41 },
            Ir1Op::HostCall {
                capability: "console:log".to_string(),
                arg_count: 1,
            },
            Ir1Op::Pop,
            Ir1Op::Label { id: 42 },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            },
            Ir1Op::Return,
        ]);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("authenticated setAuthTag catch flow lowering")
            .module;
        let console_flow = ir2
            .ops
            .iter()
            .find(|op| {
                matches!(
                    &op.inner,
                    Ir1Op::HostCall { capability, .. } if capability == "console:log"
                )
            })
            .and_then(|op| op.flow.as_ref())
            .expect("setAuthTag catch console flow annotation");
        assert_eq!(console_flow.data_label, expected_label, "{tag_value}");
        assert_eq!(
            console_flow.declassification_required, expected_declassification,
            "{tag_value}"
        );
    }
}

#[test]
fn crypto_hostcall_catch_with_escaped_object_input_fails_high_bd_1by6p() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"crypto-escaped-tag-catch"),
        "crypto_escaped_tag_catch_bd_1by6p.js",
    );
    ir1.ops.extend([
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("public-tag".into()),
        },
        Ir1Op::HostCall {
            capability: "builtin:BufferFrom".to_string(),
            arg_count: 1,
        },
        Ir1Op::StoreBinding { binding_id: 8 },
        Ir1Op::Pop,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::LoadBinding { binding_id: 8 },
        Ir1Op::Call { arg_count: 1 },
        Ir1Op::Pop,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("aes-256-gcm".into()),
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("public-key".into()),
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("public-iv".into()),
        },
        Ir1Op::HostCall {
            capability: "builtin:CryptoCreateDecipheriv".to_string(),
            arg_count: 3,
        },
        Ir1Op::StoreBinding { binding_id: 7 },
        Ir1Op::Pop,
        Ir1Op::BeginTry {
            catch_label: 41,
            finally_label: None,
        },
        Ir1Op::LoadBinding { binding_id: 7 },
        Ir1Op::LoadBinding { binding_id: 8 },
        Ir1Op::HostCall {
            capability: "builtin:CryptoObjectSetAuthTag".to_string(),
            arg_count: 2,
        },
        Ir1Op::Pop,
        Ir1Op::EndTry,
        Ir1Op::Jump { label_id: 42 },
        Ir1Op::Label { id: 41 },
        Ir1Op::HostCall {
            capability: "console:log".to_string(),
            arg_count: 1,
        },
        Ir1Op::Pop,
        Ir1Op::Label { id: 42 },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Return,
    ]);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("escaped crypto operand stays representable but fail-high")
        .module;
    let console_flow = ir2
        .ops
        .iter()
        .find(|op| {
            matches!(
                &op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "console:log"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("escaped crypto catch console flow annotation");
    assert_eq!(console_flow.data_label, Label::TopSecret);
    assert!(console_flow.declassification_required);
}

#[test]
fn retained_crypto_buffer_shape_invalidates_on_alias_mutation_and_branch_bd_1by6p() {
    for (case_name, invalidation) in [
        ("alias_mutation", "const alias = tag; alias[0] = 1;"),
        ("branch_merge", "if (tag) {}"),
    ] {
        let source = format!(
            "const crypto = require('crypto');\n\
             const tag = Buffer.from('public-auth-tag');\n\
             {invalidation}\n\
             const decipher = crypto.createDecipheriv(\
               'aes-256-gcm', 'public-key', 'public-iv'\
             );\n\
             try {{ decipher.setAuthTag(tag); }} catch (error) {{\n\
               console.log(error instanceof Error);\n\
             }}"
        );
        let tree = crate::parser_api_stability::parse_script(&source)
            .expect("parse retained Buffer invalidation source");
        let ir0 = Ir0Module::from_syntax_tree(
            tree,
            format!("crypto_retained_buffer_{case_name}_bd_1by6p.js"),
        );
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("retained Buffer invalidation source should lower")
            .module;
        assert_eq!(
            count_hostcall_deep(&ir1.ops, "builtin:CryptoObjectSetAuthTag"),
            1,
            "{case_name} should retain finite authenticated crypto dispatch"
        );

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("retained Buffer invalidation flow should remain representable")
            .module;
        let console_flow = ir2
            .ops
            .iter()
            .find(|op| {
                matches!(
                    &op.inner,
                    Ir1Op::HostCall { capability, .. } if capability == "console:log"
                )
            })
            .and_then(|op| op.flow.as_ref())
            .expect("retained Buffer invalidation catch console flow annotation");
        assert_eq!(console_flow.data_label, Label::TopSecret, "{case_name}");
        assert!(console_flow.declassification_required, "{case_name}");
    }
}

#[test]
fn forged_crypto_lifecycle_hostcall_fails_high_bd_1by6p() {
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"forged-crypto-lifecycle"),
        "forged_crypto_lifecycle_bd_1by6p.js",
    );
    ir1.ops.extend([
        Ir1Op::BeginTry {
            catch_label: 41,
            finally_label: None,
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("public-forged-object".into()),
        },
        Ir1Op::HostCall {
            capability: "builtin:CryptoObjectFinal".to_string(),
            arg_count: 1,
        },
        Ir1Op::Pop,
        Ir1Op::EndTry,
        Ir1Op::Jump { label_id: 42 },
        Ir1Op::Label { id: 41 },
        Ir1Op::HostCall {
            capability: "console:log".to_string(),
            arg_count: 1,
        },
        Ir1Op::Pop,
        Ir1Op::Label { id: 42 },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Return,
    ]);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("malformed finite capability stays representable but fail-high")
        .module;
    let console_flow = ir2
        .ops
        .iter()
        .find(|op| {
            matches!(
                &op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "console:log"
            )
        })
        .and_then(|op| op.flow.as_ref())
        .expect("forged catch console flow annotation");
    assert_eq!(console_flow.data_label, Label::TopSecret);
    assert!(console_flow.declassification_required);
}

#[test]
fn wrong_kind_crypto_lifecycle_hostcalls_fail_high_bd_1by6p() {
    for (constructor, constructor_arg_count, lifecycle, case_name) in [
        (
            "builtin:CryptoCreateHash",
            1,
            "builtin:CryptoObjectFinal",
            "hash_final",
        ),
        (
            "builtin:CryptoCreateHmac",
            2,
            "builtin:CryptoObjectCopy",
            "hmac_copy",
        ),
        (
            "builtin:CryptoCreateCipheriv",
            3,
            "builtin:CryptoObjectDigest",
            "cipher_digest",
        ),
    ] {
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(case_name.as_bytes()),
            format!("wrong_kind_{case_name}_bd_1by6p.js"),
        );
        for _ in 0..constructor_arg_count {
            ir1.ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::String("public-constructor-argument".into()),
            });
        }
        ir1.ops.extend([
            Ir1Op::HostCall {
                capability: constructor.to_string(),
                arg_count: constructor_arg_count,
            },
            Ir1Op::StoreBinding { binding_id: 7 },
            Ir1Op::Pop,
            Ir1Op::BeginTry {
                catch_label: 41,
                finally_label: None,
            },
            Ir1Op::LoadBinding { binding_id: 7 },
            Ir1Op::HostCall {
                capability: lifecycle.to_string(),
                arg_count: 1,
            },
            Ir1Op::Pop,
            Ir1Op::EndTry,
            Ir1Op::Jump { label_id: 42 },
            Ir1Op::Label { id: 41 },
            Ir1Op::HostCall {
                capability: "console:log".to_string(),
                arg_count: 1,
            },
            Ir1Op::Pop,
            Ir1Op::Label { id: 42 },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            },
            Ir1Op::Return,
        ]);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("wrong-kind lifecycle flow remains representable")
            .module;
        let console_flow = ir2
            .ops
            .iter()
            .find(|op| {
                matches!(
                    &op.inner,
                    Ir1Op::HostCall { capability, .. } if capability == "console:log"
                )
            })
            .and_then(|op| op.flow.as_ref())
            .expect("wrong-kind catch console flow annotation");
        assert_eq!(console_flow.data_label, Label::TopSecret, "{case_name}");
        assert!(console_flow.declassification_required, "{case_name}");
    }
}

#[test]
fn object_get_own_property_symbols_lowers_to_builtin_bd_n8eta_4_2() {
    let ops = lower_script_source_ops(
        "Object.getOwnPropertySymbols({});",
        "object_get_own_property_symbols_bd_n8eta_4_2.js",
    );

    assert_eq!(
        count_hostcall_deep(&ops, "builtin:ObjectGetOwnPropertySymbols"),
        1
    );
    assert!(ops_deep_match(&ops, &|op| matches!(
        op,
        Ir1Op::HostCall {
            capability,
            arg_count: 1
        } if capability == "builtin:ObjectGetOwnPropertySymbols"
    )));
}

#[test]
fn symbol_iterator_computed_keys_lower_to_typed_builtin_bd_n8eta_4_2() {
    let ops = lower_script_source_ops(
        "const object = { [Symbol.iterator]: 1 };\n\
         object[Symbol.iterator];\n\
         object[Symbol.iterator]();",
        "symbol_iterator_computed_keys_bd_n8eta_4_2.js",
    );

    assert_eq!(count_hostcall_deep(&ops, "builtin:SymbolIterator"), 3);
    assert!(ops_deep_match(&ops, &|op| matches!(
        op,
        Ir1Op::HostCall {
            capability,
            arg_count: 0
        } if capability == "builtin:SymbolIterator"
    )));
    assert!(ops_deep_match(&ops, &|op| matches!(
        op,
        Ir1Op::CallMethod { arg_count: 0 }
    )));
    assert!(
        !ops_deep_match(&ops, &|op| matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String(value)
            } if value.as_str() == Some("@@iterator")
        )),
        "Symbol.iterator must not collapse to the legacy string key"
    );
}

#[test]
fn net_alias_calls_and_socket_constructor_lower_to_distinct_builtins_bd_7qwej() {
    let ops = lower_script_source_ops(
        "const network = require('node:net');\n\
         network.isIP('127.0.0.1');\n\
         network.isIPv4('127.0.0.1');\n\
         network.isIPv6('::1');\n\
         network.createServer(() => {});\n\
         network.connect({ port: 1 });\n\
         network.createConnection({ port: 2 });\n\
         new network.Socket({ allowHalfOpen: true });\n",
        "net_alias_builtins_bd_7qwej.js",
    );

    for capability in [
        "builtin:NetIsIP",
        "builtin:NetIsIPv4",
        "builtin:NetIsIPv6",
        "builtin:NetCreateServer",
        "builtin:NetConnect",
        "builtin:NetCreateConnection",
        "builtin:NetSocket",
    ] {
        assert_eq!(
            count_hostcall_deep(&ops, capability),
            1,
            "expected exactly one {capability} hostcall"
        );
    }
    assert!(
        !ops_deep_match(&ops, &|op| matches!(op,
            Ir1Op::HostCall { capability, .. } if capability == "module:require")),
        "a confirmed net alias must elide its ambient require initializer"
    );
}

#[test]
fn net_exact_inline_require_call_and_new_shapes_lower_bd_7qwej() {
    let ops = lower_script_source_ops(
        "require('net').isIP('x');\n\
         require('node:net').isIPv4('127.0.0.1');\n\
         require('net').isIPv6('::1');\n\
         require('node:net').createServer();\n\
         require('net').connect(1);\n\
         require('node:net').createConnection(2);\n\
         new (require('net').Socket)();\n",
        "net_inline_builtins_bd_7qwej.js",
    );

    for capability in [
        "builtin:NetIsIP",
        "builtin:NetIsIPv4",
        "builtin:NetIsIPv6",
        "builtin:NetCreateServer",
        "builtin:NetConnect",
        "builtin:NetCreateConnection",
        "builtin:NetSocket",
    ] {
        assert_eq!(count_hostcall_deep(&ops, capability), 1);
    }
}

#[test]
fn net_alias_sentinel_propagates_into_nested_functions_bd_7qwej() {
    let ops = lower_script_source_ops(
        "const net = require('net');\n\
         function makeServer() {\n\
           const probe = () => net.isIP('127.0.0.1');\n\
           return net.createServer(probe);\n\
         }\n",
        "net_nested_alias_bd_7qwej.js",
    );

    assert_eq!(count_hostcall_deep(&ops, "builtin:NetIsIP"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:NetCreateServer"), 1);
}

#[test]
fn net_alias_sentinel_does_not_cross_nested_parameter_shadow_bd_7qwej() {
    let ops = lower_script_source_ops(
        "const net = require('net');\n\
         net.isIP('127.0.0.1');\n\
         function shadowed(net) {\n\
           net.isIP('not-the-module');\n\
           return new net.Socket();\n\
         }\n",
        "net_nested_shadow_bd_7qwej.js",
    );

    assert_eq!(count_hostcall_deep(&ops, "builtin:NetIsIP"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:NetSocket"), 0);
}

#[test]
fn net_unused_dynamic_computed_and_unsupported_requires_fail_closed_bd_7qwej() {
    for (label, source) in [
        ("unused", "const net = require('net');"),
        ("bare", "require('node:net');"),
        (
            "dynamic",
            "const name = 'net'; const net = require(name); net.isIP('x');",
        ),
        (
            "computed",
            "const net = require('net'); net['isIP']('127.0.0.1');",
        ),
        (
            "unsupported",
            "const net = require('node:net'); net.lookup('localhost');",
        ),
        (
            "nested-shadow-only",
            "const net = require('net'); function f(net) { net.isIP('x'); }",
        ),
        (
            "arrow-shadow-only",
            "const net = require('net'); const f = (net) => net.isIP('x');",
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("net_{label}_bd_7qwej.js"));
        let error = lower_ir0_to_ir1(&ir0)
            .expect_err("unrecognized net possession must preserve ambient denial");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation { .. }
            ),
            "{label} should fail at the ambient-authority gate, got {error:?}"
        );
    }
}

#[test]
fn net_block_catch_loop_and_hoisted_var_shadow_only_uses_fail_closed_bd_7qwej() {
    for (label, source) in [
        (
            "block-shadow-only",
            "const net = require('net'); { const net = null; net.isIP('x'); }",
        ),
        (
            "catch-shadow-only",
            "const net = require('net'); try { throw 1; } catch (net) { net.isIP('x'); }",
        ),
        (
            "for-shadow-only",
            "const net = require('net'); for (let net = 0; net < 1; net = net + 1) { net.isIP('x'); }",
        ),
        (
            "for-of-shadow-only",
            "const net = require('net'); for (const net of [1]) { net.isIP('x'); }",
        ),
        (
            "nested-var-shadow-only",
            "const net = require('net'); function f() { if (true) { var net = null; } net.isIP('x'); }",
        ),
        (
            "arrow-hoisted-var-shadow-only",
            "const net = require('net'); const f = () => { if (true) { var net = null; } net.isIP('x'); };",
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("net_{label}_bd_7qwej.js"));
        let error = lower_ir0_to_ir1(&ir0)
            .expect_err("a shadow-only net use must not confirm the root module alias");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation { .. }
            ),
            "{label} should preserve ambient require denial, got {error:?}"
        );
    }
}

#[test]
fn net_mutable_reassigned_mutated_and_escaped_aliases_fail_closed_bd_7qwej() {
    for (label, source) in [
        (
            "mutable-reassignment",
            "let net = require('net'); net = null; net.connect(1);",
        ),
        (
            "member-mutation",
            "const net = require('net'); net.connect = () => null; net.connect(1);",
        ),
        (
            "mixed-bare-escape",
            "const net = require('net'); consume(net); net.isIP('127.0.0.1');",
        ),
        (
            "mixed-computed-read",
            "const net = require('net'); net.isIP('127.0.0.1'); net['connect'](1);",
        ),
        (
            "mixed-unsupported-read",
            "const net = require('net'); net.isIP('127.0.0.1'); consume(net.lookup);",
        ),
        (
            "mixed-object-escape",
            "const net = require('net'); const escaped = { net }; net.isIP('127.0.0.1');",
        ),
        (
            "same-declaration-tdz",
            "const probe = net.isIP('127.0.0.1'), net = require('net');",
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("net_{label}_bd_7qwej.js"));
        let error = lower_ir0_to_ir1(&ir0)
            .expect_err("untrusted net alias provenance must preserve ambient denial");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation { .. }
            ),
            "{label} should preserve ambient require denial, got {error:?}"
        );
    }
}

#[test]
fn net_supported_object_values_and_computed_keys_confirm_const_alias_bd_7qwej() {
    let ops = lower_script_source_ops(
        "const net = require('net');\n\
         const probes = { value: net.isIP('127.0.0.1'), [net.isIPv4('x')]: true };\n",
        "net_object_value_usage_bd_7qwej.js",
    );

    assert_eq!(count_hostcall_deep(&ops, "builtin:NetIsIP"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:NetIsIPv4"), 1);
}

#[test]
fn net_require_shadow_does_not_gain_builtin_provenance_bd_7qwej() {
    // Contract (aligned with the crypto bd-2z157 and http bd-d0n7u shadow
    // tests): a lexically shadowed `require` is the user's own value, so
    // the call lowers with generic call semantics. What it must NEVER do
    // is confirm a net module alias — no `builtin:Net*` hostcall may be
    // emitted, and no ambient authority is granted. This test previously
    // expected an AmbientAuthorityViolation, which contradicted the
    // shadow-aware contract that landed with bd-2z157 and had been
    // failing since (bd-vpxgj).
    let ops = lower_script_source_ops(
        "const require = () => null;\n\
         const net = require('net');\n\
         net.isIP('127.0.0.1');\n",
        "net_shadowed_require_bd_7qwej.js",
    );
    for capability in [
        "builtin:NetIsIP",
        "builtin:NetIsIPv4",
        "builtin:NetIsIPv6",
        "builtin:NetCreateServer",
        "builtin:NetConnect",
    ] {
        assert_eq!(
            count_hostcall_deep(&ops, capability),
            0,
            "a shadowed require must not acquire {capability} provenance"
        );
    }
    assert_eq!(
        count_hostcall_deep(&ops, "module:require"),
        0,
        "a shadowed require call must not lower to the module-load hostcall"
    );
    assert!(
        ops_deep_match(&ops, &|op| matches!(op, Ir1Op::CallMethod { .. })),
        "the shadowed alias must retain generic method-call semantics"
    );
}

#[test]
fn net_and_tls_static_requires_can_precede_each_other_bd_70cv1() {
    for (label, source) in [
        (
            "tls-then-net",
            "const tls = require('tls');\n\
             const net = require('net');\n\
             tls.getCiphers();\n\
             net.isIP('127.0.0.1');\n",
        ),
        (
            "net-then-tls",
            "const net = require('net');\n\
             const tls = require('tls');\n\
             net.isIP('127.0.0.1');\n\
             tls.getCiphers();\n",
        ),
    ] {
        let ops = lower_script_source_ops(source, &format!("{label}_bd_70cv1.js"));
        assert_eq!(count_hostcall_deep(&ops, "builtin:NetIsIP"), 1);
        assert_eq!(count_hostcall_deep(&ops, "builtin:TlsGetCiphers"), 1);
        assert!(
            !ops_deep_match(&ops, &|op| matches!(op,
                Ir1Op::HostCall { capability, .. } if capability == "module:require")),
            "both supported module aliases should elide their require initializers"
        );
    }
}

#[test]
fn tls_alias_provenance_reaches_only_unshadowed_nested_uses_bd_70cv1() {
    let ops = lower_script_source_ops(
        "const tls = require('tls');\n\
         function supported() { return tls.getCiphers(); }\n\
         const roots = () => tls.rootCertificates;\n\
         function shadowed(tls) { return tls.getCiphers(); }\n",
        "tls_nested_alias_bd_70cv1.js",
    );

    assert_eq!(count_hostcall_deep(&ops, "builtin:TlsGetCiphers"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:TlsRootCertificates"), 1);
    assert!(
        !ops_deep_match(&ops, &|op| matches!(op,
            Ir1Op::HostCall { capability, .. } if capability == "module:require")),
        "the supported outer TLS alias should elide its require initializer"
    );
}

#[test]
fn tls_alias_supported_unshadowed_default_expression_confirms_bd_70cv1() {
    let ops = lower_script_source_ops(
        "const tls = require('tls');\n\
         function ciphers(value = tls.getCiphers()) { return value; }\n",
        "tls_default_param_alias_bd_70cv1.js",
    );

    assert_eq!(count_hostcall_deep(&ops, "builtin:TlsGetCiphers"), 1);
    assert!(
        !ops_deep_match(&ops, &|op| matches!(op,
            Ir1Op::HostCall { capability, .. } if capability == "module:require")),
        "an unshadowed supported default expression should confirm the TLS alias"
    );
}

#[test]
fn hermetic_tls_loopback_and_primitive_string_methods_are_flow_clean_bd_jux2l() {
    fn assert_flow_clean(name: &str, source: &str) {
        let tree = crate::parser_api_stability::parse_script(source)
            .unwrap_or_else(|error| panic!("parse {name}: {error}"));
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("{name}_bd_jux2l.js"));
        let ir1 = lower_ir0_to_ir1(&ir0)
            .unwrap_or_else(|error| panic!("lower {name} to IR1: {error}"))
            .module;
        let ir2 = lower_ir1_to_ir2_with_host_io_exception_provenance(
            &ir1,
            HostIoExceptionProvenance::ProviderInternal,
        )
        .unwrap_or_else(|error| panic!("lower {name} to IR2: {error}"))
        .module;
        let context =
            LoweringContext::new("trace-bd-jux2l", "decision-bd-jux2l", "policy-bd-jux2l");
        if let Err(error) = build_ir2_flow_proof_artifact(&ir2, &context) {
            panic!("{name} must lower without UnauthorizedFlow: {error}");
        }
    }

    assert_flow_clean(
        "primitive_starts_with",
        "console.log('hello'.startsWith('h'));\n",
    );
    assert_flow_clean(
        "root_certificates_starts_with",
        "const tls = require('tls');\n\
         const roots = tls.rootCertificates;\n\
         console.log(Array.isArray(roots), roots.length >= 1);\n\
         console.log(roots[0].startsWith('-----BEGIN CERTIFICATE-----\\n'));\n\
         console.log(roots[0].endsWith('\\n-----END CERTIFICATE-----'));\n",
    );
    assert_flow_clean(
        "nested_connect_callback",
        "const tls = require('tls');\n\
         const CERT = '-----BEGIN CERTIFICATE-----\\nAQIDBA==\\n-----END CERTIFICATE-----';\n\
         const KEY = 'engine-contained-private-marker';\n\
         const server = tls.createServer({ cert: CERT, key: KEY }, socket => {\n\
           socket.on('data', chunk => socket.end('ECHO:' + chunk));\n\
         });\n\
         server.listen(0, '127.0.0.1', () => {\n\
           const port = server.address().port;\n\
           const client = tls.connect(port, '127.0.0.1', { rejectUnauthorized: false }, () => {\n\
             client.write('pos-four');\n\
           });\n\
           let body = '';\n\
           client.on('data', chunk => body += chunk);\n\
           client.on('end', () => { console.log(body); server.close(); });\n\
         });\n",
    );
    assert_flow_clean(
        "nested_get_peer_certificate",
        "const tls = require('tls');\n\
         const CERT = '-----BEGIN CERTIFICATE-----\\nAQIDBA==\\n-----END CERTIFICATE-----';\n\
         const KEY = 'engine-contained-private-marker';\n\
         const server = tls.createServer({ cert: CERT, key: KEY }, sock => { sock.end(); });\n\
         server.listen(0, '127.0.0.1', () => {\n\
           const c = tls.connect({\n\
             port: server.address().port,\n\
             host: '127.0.0.1',\n\
             rejectUnauthorized: false,\n\
           }, () => {\n\
             const p = c.getPeerCertificate();\n\
             console.log('cn:' + p.subject.CN);\n\
             c.end();\n\
           });\n\
           c.on('close', () => server.close());\n\
         });\n",
    );
    assert_flow_clean(
        "pre_handshake_get_protocol",
        "const tls = require('tls');\n\
         const client = tls.connect({ port: 65535, host: '127.0.0.1', rejectUnauthorized: false });\n\
         console.log(client.getProtocol() === undefined, client.getCipher() === undefined);\n\
         client.on('error', () => {});\n",
    );
    assert_flow_clean(
        "default_param_ciphers_and",
        "const tls = require('tls');\n\
         function hasCiphers(value = tls.getCiphers()) {\n\
           return Array.isArray(value) && value.length > 0;\n\
         }\n\
         console.log(hasCiphers());\n",
    );
    assert_flow_clean(
        "option_string_rangeerror_name",
        "const tls = require('tls');\n\
         try {\n\
           tls.createServer({ ALPNProtocols: { length: 9223372036854775807 } });\n\
         } catch (error) {\n\
           console.log(error.name);\n\
         }\n\
         try {\n\
           tls.connect({\n\
             port: 1,\n\
             host: '127.0.0.1',\n\
             servername: 'x'.repeat(254),\n\
             rejectUnauthorized: false\n\
           });\n\
         } catch (error) {\n\
           console.log(error.name);\n\
         }\n",
    );
}

#[test]
fn tls_alias_escape_mutation_shadow_and_value_reads_fail_closed_bd_70cv1() {
    for (label, source) in [
        (
            "mixed-bare-escape",
            "const tls = require('tls'); tls.getCiphers(); console.log(tls);",
        ),
        (
            "mixed-object-escape",
            "const tls = require('tls'); const escaped = { tls }; tls.getCiphers();",
        ),
        (
            "mixed-destructure",
            "const tls = require('tls'); const { connect } = tls; tls.getCiphers();",
        ),
        (
            "mixed-default-param-escape",
            "const tls = require('tls'); tls.getCiphers(); function f(value = tls) {}",
        ),
        (
            "mixed-destructure-default-escape",
            "const tls = require('tls'); tls.getCiphers(); const { value = tls } = {};",
        ),
        (
            "mixed-destructure-computed-key-escape",
            "const tls = require('tls'); tls.getCiphers(); const { [tls]: value } = {};",
        ),
        (
            "member-mutation",
            "const tls = require('tls'); tls.connect = () => null; tls.connect({ port: 1 });",
        ),
        (
            "mutable-reassignment",
            "let tls = require('tls'); tls = {}; tls.getCiphers();",
        ),
        (
            "const-reassignment",
            "const tls = require('tls'); tls = {}; tls.getCiphers();",
        ),
        (
            "method-value-read",
            "const tls = require('tls'); console.log(tls.connect);",
        ),
        (
            "nested-shadow-only",
            "const tls = require('tls'); function f(tls) { return tls.getCiphers(); }",
        ),
        (
            "default-param-shadow-only",
            "const tls = require('tls'); function f(tls = tls.getCiphers()) {}",
        ),
        (
            "mixed-dynamic-property",
            "const tls = require('tls'); tls.getCiphers(); const key = 'connect'; console.log(tls[key]);",
        ),
        (
            "mixed-unsupported-property",
            "const tls = require('tls'); tls.getCiphers(); console.log(tls.unknownExport);",
        ),
        (
            "computed-static-property",
            "const tls = require('tls'); console.log(tls['rootCertificates']);",
        ),
        (
            "same-declaration-tdz",
            "const ciphers = tls.getCiphers(), tls = require('tls');",
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("tls_{label}_bd_70cv1.js"));
        let error = lower_ir0_to_ir1(&ir0)
            .expect_err("untrusted TLS alias provenance must preserve ambient denial");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation { .. }
            ),
            "{label} should preserve ambient require denial, got {error:?}"
        );
    }
}

#[test]
fn stream_destructured_constructors_lower_to_distinct_builtins_bd_fw7zd() {
    let ops = lower_script_source_ops(
        "const { Readable, Writable, PassThrough } = require('node:stream');\n\
         const readable = new Readable({ highWaterMark: 4, read() {} });\n\
         const writable = new Writable({ highWaterMark: 8, write(c, e, cb) { cb(); } });\n\
         const passthrough = new PassThrough({ highWaterMark: 16 });\n",
        "stream_constructors_bd_fw7zd.js",
    );
    assert_eq!(count_hostcall_deep(&ops, "builtin:StreamReadable"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:StreamWritable"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:StreamPassThrough"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:StreamReadableFrom"), 0);
    assert!(
        !ops.iter()
            .any(|op| matches!(op, Ir1Op::ImportModule { .. }))
    );
}

#[test]
fn stream_transform_and_pipeline_surfaces_lower_statically_bd_fw7zd_12() {
    let source = r#"
        const { Readable, Writable, Transform, pipeline, promises } = require('stream');
        const upper = new Transform({ transform(chunk, encoding, callback) { callback(null, chunk); } });
        const sink = new Writable({ write(chunk, encoding, callback) { callback(); } });
        pipeline(Readable.from(['x']), upper, sink, () => {});
        promises.pipeline(Readable.from(['y']), sink);
    "#;
    let tree =
        crate::parser_api_stability::parse_script(source).expect("parse stream pipeline CJS");
    let ir0 = Ir0Module::from_syntax_tree(tree, "stream_pipeline_bd_fw7zd_12.js");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("lower stream pipeline CJS");
    assert_eq!(
        count_hostcall_deep(&ir1.module.ops, "builtin:StreamTransform"),
        1
    );
    assert_eq!(
        count_hostcall_deep(&ir1.module.ops, "builtin:StreamPipeline"),
        1
    );
    assert_eq!(
        count_hostcall_deep(&ir1.module.ops, "builtin:StreamPromisesPipeline"),
        1
    );
    assert_eq!(count_hostcall_deep(&ir1.module.ops, "module:require"), 0);

    let ops = lower_esm_source_ops(
        "import { Readable, Writable, Transform } from 'node:stream';\n\
         import { pipeline } from 'node:stream/promises';\n\
         const t = new Transform({ transform(c, e, cb) { cb(null, c); } });\n\
         const w = new Writable({ write(c, e, cb) { cb(); } });\n\
         await pipeline(Readable.from(['x']), t, w);",
        "stream_pipeline_bd_fw7zd_12.mjs",
    );
    assert_eq!(count_hostcall_deep(&ops, "builtin:StreamTransform"), 1);
    assert_eq!(
        count_hostcall_deep(&ops, "builtin:StreamPromisesPipeline"),
        1
    );
}

/// bd-305gi.1: a stream form the facade does not claim is never elided to
/// a stream kernel HostCall; it lowers with the engine-owned stream module
/// (whose process.nextTick HostCall marks it) instead of the ambient
/// `require` refusal it met before that module existed.
fn assert_served_by_stream_module(source: &str, label: &str) {
    let ops = lower_script_source_ops(source, label);
    for kernel in [
        "builtin:StreamReadable",
        "builtin:StreamReadableFrom",
        "builtin:StreamWritable",
        "builtin:StreamPassThrough",
        "builtin:StreamTransform",
        "builtin:StreamPipeline",
        "builtin:StreamPromisesPipeline",
    ] {
        assert_eq!(
            count_hostcall_deep(&ops, kernel),
            0,
            "{label}: {kernel} for {source}"
        );
    }
    assert!(
        count_hostcall_deep(&ops, "builtin:ProcessNextTick") > 0,
        "{label}: the stream module was not materialized for {source}"
    );
}

#[test]
fn stream_transform_pipeline_escapes_get_the_module_not_the_kernel_bd_fw7zd_12() {
    for source in [
        "const { Transform } = require('stream'); console.log(Transform);",
        "const { pipeline } = require('stream'); const escaped = pipeline;",
        "const { promises } = require('stream'); console.log(promises['pipeline']);",
    ] {
        assert_served_by_stream_module(source, "stream_escape_bd_fw7zd_12.js");
    }
}

#[test]
fn stream_passthrough_named_import_is_static_and_shadow_safe_bd_fw7zd() {
    let ops = lower_esm_source_ops(
        "import { PassThrough as Through } from 'node:stream';\n\
         new Through();\n\
         function shadowed(Through) { return new Through(); }\n",
        "stream_passthrough_import_bd_fw7zd.mjs",
    );
    assert_eq!(count_hostcall_deep(&ops, "builtin:StreamPassThrough"), 1);
    assert!(
        !ops.iter()
            .any(|op| matches!(op, Ir1Op::ImportModule { .. }))
    );
}

#[test]
fn stream_passthrough_elision_requires_every_unshadowed_use_bd_fw7zd() {
    for (label, source) in [
        (
            "shadow-only",
            "const { PassThrough: Through } = require('stream');\n\
             function nested(Through) { return new Through(); }\n",
        ),
        (
            "mixed-escape",
            "const { PassThrough: Through } = require('stream');\n\
             new Through();\n\
             const escaped = Through;\n",
        ),
        (
            "pre-declaration",
            "new Through();\n\
             const { PassThrough: Through } = require('stream');\n",
        ),
    ] {
        assert_served_by_stream_module(source, &format!("stream_{label}_bd_fw7zd.js"));
    }

    for (label, source) in [
        (
            "shadow-only",
            "import { PassThrough as Through } from 'stream';\n\
             function nested(Through) { return new Through(); }\n",
        ),
        (
            "mixed-escape",
            "import { PassThrough as Through } from 'stream';\n\
             new Through();\n\
             const escaped = Through;\n",
        ),
    ] {
        let ops = lower_esm_source_ops(source, &format!("stream_esm_{label}_bd_fw7zd.mjs"));
        assert_eq!(count_hostcall_deep(&ops, "builtin:StreamPassThrough"), 0);
        assert!(
            ops.iter()
                .any(|op| matches!(op, Ir1Op::ImportModule { .. })),
            "{label} must retain its unsupported ESM module load"
        );
    }
}

#[test]
fn stream_constructor_sentinels_do_not_cross_parameter_shadows_bd_fw7zd() {
    let ops = lower_script_source_ops(
        "const { Readable, Writable } = require('stream');\n\
         new Readable({ read() {} });\n\
         new Writable({ write(c, e, cb) { cb(); } });\n\
         function shadowed(Readable, Writable) {\n\
           new Readable();\n\
           new Writable();\n\
         }\n",
        "stream_constructor_shadows_bd_fw7zd.js",
    );
    assert_eq!(count_hostcall_deep(&ops, "builtin:StreamReadable"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:StreamWritable"), 1);
}

#[test]
fn stream_constructor_sentinels_activate_only_at_cjs_declaration_bd_fw7zd() {
    let ops = lower_script_source_ops(
        "new Readable({ read() {} });\n\
         const { Readable, Writable } = require('stream');\n\
         new Readable({ read() {} });\n\
         new Writable({ write(c, e, cb) { cb(); } });\n",
        "stream_constructor_tdz_bd_fw7zd.js",
    );
    assert_eq!(count_hostcall_deep(&ops, "builtin:StreamReadable"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:StreamWritable"), 1);
    assert!(
        ops.iter().any(|op| matches!(op, Ir1Op::Construct { .. })),
        "the pre-declaration constructor must retain ordinary TDZ-aware lowering"
    );
}

#[test]
fn stream_unsupported_or_mutable_constructor_bindings_are_not_elided_bd_fw7zd() {
    for source in [
        "let { Readable } = require('stream'); new Readable();",
        "var { Writable } = require('stream'); new Writable();",
        "const { Duplex } = require('stream'); new Duplex();",
        "const stream = require('stream'); new stream.Readable();",
    ] {
        assert_served_by_stream_module(source, "unsupported_stream_constructor.js");
    }
}

#[test]
fn events_destructured_constructor_materializes_first_class_builtin_bd_dspwz() {
    let ops = lower_script_source_ops(
        "const { EventEmitter } = require('events');\n\
         const emitter = new EventEmitter();\n",
        "events_constructor_bd_dspwz.js",
    );
    assert!(ops.iter().any(|op| matches!(op,
        Ir1Op::HostCall { capability, arg_count: 0 }
            if capability == "builtin:EventEmitterConstructorRef")));
    assert!(ops.iter().any(|op| matches!(op, Ir1Op::Construct { .. })));
}

#[test]
fn mixed_event_emitter_this_fixture_lowers_without_unauthorized_flow_bd_asw4m_3() {
    let source = r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        e.on('tick', function () { console.log('fn:' + (this === e)); });
        const holder = {
            tag: 'H',
            install(target) {
                target.on('tick', () => { console.log('arrow:' + this.tag); });
            }
        };
        holder.install(e);
        console.log('emitted:' + e.emit('tick'));
    "#;
    let tree = crate::parser_api_stability::parse_script(source).expect("parse mixed fixture");
    let ir0 = Ir0Module::from_syntax_tree(tree, "events_mixed_this_bd_asw4m_3.js");
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("lower mixed EventEmitter fixture to IR1")
        .module;
    let ir2 = lower_ir1_to_ir2_with_host_io_exception_provenance(
        &ir1,
        HostIoExceptionProvenance::ProviderInternal,
    )
    .expect("lower mixed EventEmitter fixture to IR2")
    .module;
    let final_console_flow = ir2
        .ops
        .iter()
        .find_map(|op| match &op.inner {
            Ir1Op::HostCall { capability, .. } if capability == "builtin:ConsoleLog" => {
                op.flow.as_ref()
            }
            _ => None,
        })
        .expect("mixed fixture must retain the final console flow annotation");
    assert_eq!(final_console_flow.data_label, Label::Internal);
    assert!(!final_console_flow.declassification_required);
    let context = LoweringContext::new(
        "trace-bd-asw4m-3",
        "decision-bd-asw4m-3",
        "policy-bd-asw4m-3",
    );
    build_ir2_flow_proof_artifact(&ir2, &context)
        .expect("mixed EventEmitter fixture must not produce UnauthorizedFlow");
}

#[test]
fn node_events_constructor_sentinel_reaches_nested_body_bd_2dmnn() {
    let ops = lower_script_source_ops(
        "const { EventEmitter } = require('node:events');\n\
         function makeEmitter() { return new EventEmitter(); }\n\
         makeEmitter();\n",
        "events_nested_constructor_bd_2dmnn.js",
    );
    assert!(ops_deep_match(&ops, &|op| matches!(op,
        Ir1Op::HostCall { capability, arg_count: 0 }
            if capability == "builtin:EventEmitterConstructorRef")));
    assert!(ops_deep_match(&ops, &|op| matches!(
        op,
        Ir1Op::Construct { .. }
    )));
}

#[test]
fn direct_event_emitter_member_and_cluster_instanceof_use_ordinary_values_bd_dspwz() {
    let ops = lower_script_source_ops(
        "const cluster = require('cluster');\n\
         const EventEmitter = require('events').EventEmitter;\n\
         console.log('instanceof-ee:' + (cluster instanceof EventEmitter));\n\
         console.log(typeof EventEmitter);\n\
         console.log(EventEmitter === EventEmitter);\n\
         console.log(EventEmitter.prototype);\n",
        "cluster_event_emitter_identity_bd_dspwz.js",
    );
    assert_eq!(
        count_hostcall_deep(&ops, "builtin:EventEmitterConstructorRef"),
        1
    );
    assert_eq!(count_hostcall_deep(&ops, "builtin:ClusterFacade"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:proto:EventEmitter"), 1);
    assert!(ops_deep_match(&ops, &|op| matches!(
        op,
        Ir1Op::BinaryOp {
            operator: BinaryOperator::Instanceof
        }
    )));
    assert!(!ops_deep_match(&ops, &|op| matches!(
        op,
        Ir1Op::HostCall { capability, .. } if capability == "module:require"
    )));

    let reversed_ops = lower_script_source_ops(
        "const EventEmitter = require('node:events').EventEmitter;\n\
         const cluster = require('node:cluster');\n\
         console.log(cluster instanceof EventEmitter);\n",
        "event_emitter_then_cluster_bd_dspwz.js",
    );
    assert_eq!(
        count_hostcall_deep(&reversed_ops, "builtin:EventEmitterConstructorRef"),
        1
    );
    assert_eq!(
        count_hostcall_deep(&reversed_ops, "builtin:ClusterFacade"),
        1
    );
    assert!(ops_deep_match(&reversed_ops, &|op| matches!(
        op,
        Ir1Op::BinaryOp {
            operator: BinaryOperator::Instanceof
        }
    )));
}

#[test]
fn event_emitter_member_provenance_rejects_computed_mutable_and_detached_forms_bd_dspwz() {
    for (label, source) in [
        (
            "computed",
            "const EventEmitter = require('events')['EventEmitter']; new EventEmitter();",
        ),
        (
            "mutable",
            "let EventEmitter = require('events').EventEmitter; new EventEmitter();",
        ),
        (
            "detached",
            "const EventEmitter = require('events').EventEmitter; new EventEmitter(); const Detached = EventEmitter; new Detached();",
        ),
        (
            "pre-use",
            "new EventEmitter(); const EventEmitter = require('events').EventEmitter;",
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("events_{label}_bd_dspwz.js"));
        let error = lower_ir0_to_ir1(&ir0)
            .expect_err("unsupported EventEmitter possession must remain ambient-refused");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation { .. }
            ),
            "{label} must preserve ambient require denial, got {error:?}"
        );
    }

    let shadowed_require_ops = lower_script_source_ops(
        "const require = () => ({ EventEmitter: function LocalEmitter() {} });\n\
         const EventEmitter = require('events').EventEmitter;\n\
         console.log(typeof EventEmitter);\n",
        "events_shadowed_require_bd_dspwz.js",
    );
    assert_eq!(
        count_hostcall_deep(&shadowed_require_ops, "builtin:EventEmitterConstructorRef"),
        0,
        "a lexical require shadow must never gain builtin provenance"
    );
}

#[test]
fn cluster_instanceof_requires_the_scoped_event_emitter_constructor_bd_dspwz() {
    for (label, source) in [
        (
            "arbitrary-rhs",
            "function Local() {} const cluster = require('cluster'); console.log(cluster instanceof Local);",
        ),
        (
            "shadowed-rhs",
            "const cluster = require('cluster'); const EventEmitter = require('events').EventEmitter; console.log(cluster instanceof EventEmitter); function probe(EventEmitter) { return cluster instanceof EventEmitter; }",
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 =
            Ir0Module::from_syntax_tree(tree, format!("cluster_instanceof_{label}_bd_dspwz.js"));
        let error = lower_ir0_to_ir1(&ir0)
            .expect_err("cluster instanceof must require authenticated EventEmitter RHS");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation { .. }
            ),
            "{label} must preserve ambient denial, got {error:?}"
        );
    }
}

#[test]
fn events_static_constants_fold_to_literals_bd_2dmnn() {
    let constructor_ops = lower_script_source_ops(
        "const { EventEmitter } = require('events');\n\
         console.log(EventEmitter.defaultMaxListeners);\n",
        "events_default_max_bd_2dmnn.js",
    );
    assert!(constructor_ops.iter().any(|op| matches!(
        op,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(10)
        }
    )));

    let module_ops = lower_script_source_ops(
        "const events = require('node:events');\n\
         console.log(events.captureRejections);\n",
        "events_capture_rejections_bd_2dmnn.js",
    );
    assert!(module_ops.iter().any(|op| matches!(
        op,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Boolean(false)
        }
    )));
}

#[test]
fn events_shadowed_only_uses_do_not_confirm_outer_requires_bd_2dmnn_1() {
    for (label, source) in [
        (
            "module-parameter",
            "const events = require('events');\n\
             function read(events) { return events.captureRejections; }\n\
             read({ captureRejections: 'local' });\n",
        ),
        (
            "constructor-local",
            "const { EventEmitter } = require('events');\n\
             function make() {\n\
               const EventEmitter = function LocalEmitter() {};\n\
               return new EventEmitter();\n\
             }\n\
             make();\n",
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 = Ir0Module::from_syntax_tree(
            tree,
            format!("events_shadowed_only_{label}_bd_2dmnn_1.js"),
        );
        let error = lower_ir0_to_ir1(&ir0)
            .expect_err("a shadow-only events use must not confirm the outer require");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation { .. }
            ),
            "{label} should preserve ambient require denial, got {error:?}"
        );
    }
}

#[test]
fn events_confirmed_outer_sentinels_stop_at_child_shadows_bd_2dmnn_1() {
    let ops = lower_script_source_ops(
        "const events = require('events');\n\
         const { EventEmitter } = require('events');\n\
         console.log(events.captureRejections);\n\
         new EventEmitter();\n\
         const read = (events) => events.captureRejections;\n\
         function make() {\n\
           const EventEmitter = function LocalEmitter() {};\n\
           return new EventEmitter();\n\
         }\n",
        "events_confirmed_outer_child_shadows_bd_2dmnn_1.js",
    );

    let folded_capture_rejections = count_ops_deep(&ops, &|op| {
        matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Boolean(false)
            }
        )
    });
    assert_eq!(folded_capture_rejections, 1);
    assert_eq!(
        count_hostcall_deep(&ops, "builtin:EventEmitterConstructorRef"),
        1
    );
}

#[test]
fn events_module_sentinel_reaches_unshadowed_nested_body_bd_2dmnn_1() {
    let ops = lower_script_source_ops(
        "const events = require('node:events');\n\
         function captureRejections() { return events.captureRejections; }\n\
         captureRejections();\n",
        "events_nested_module_alias_bd_2dmnn_1.js",
    );
    assert!(ops_deep_match(&ops, &|op| matches!(
        op,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Boolean(false)
        }
    )));
}

#[test]
fn callable_string_global_is_shadow_aware_bd_wgezf() {
    let global_ops = lower_script_source_ops(
        "console.log(String(true));",
        "callable_string_global_bd_wgezf.js",
    );
    assert!(global_ops.iter().any(|op| matches!(op,
        Ir1Op::HostCall { capability, arg_count: 1 }
            if capability == "builtin:String")));

    let shadowed_ops = lower_script_source_ops(
        "const String = (value) => 'local:' + value; console.log(String('x'));",
        "shadowed_string_global_bd_wgezf.js",
    );
    assert!(!ops_deep_match(&shadowed_ops, &|op| matches!(op,
        Ir1Op::HostCall { capability, .. } if capability == "builtin:String")));
}

#[test]
fn unused_and_deferred_events_requires_remain_ambient_refused_bd_2dmnn() {
    for (source, label) in [
        (
            "const { EventEmitter } = require('events');\n",
            "events_unused_destructure_bd_2dmnn.js",
        ),
        (
            "const events = require('events');\nconsole.log(events.once);\n",
            "events_once_deferred_bd_2dmnn.js",
        ),
        (
            "const { EventEmitter, once } = require('events');\n\
             new EventEmitter();\nconsole.log(once);\n",
            "events_mixed_destructure_bd_2dmnn.js",
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 = Ir0Module::from_syntax_tree(tree, label);
        assert!(
            lower_ir0_to_ir1(&ir0).is_err(),
            "unsupported or unused events require must remain ambient-refused: {label}"
        );
    }
}

#[test]
fn fs_sync_breadth_emits_operation_discriminators_bd_8u1t5() {
    let ops = lower_script_source_ops(
        "const fs = require('fs');\n\
         fs.mkdirSync('tree', { recursive: true });\n\
         fs.readdirSync('tree', { withFileTypes: true });\n\
         fs.statSync('tree');\n",
        "fs_sync_breadth_bd_8u1t5.js",
    );
    for discriminator in ["\0fsop:mkdir", "\0fsop:readdir", "\0fsop:stat"] {
        assert!(
            ops.iter().any(|op| matches!(op,
                Ir1Op::LoadLiteral { value: Ir1Literal::String(value) }
                    if value == discriminator)),
            "missing hidden operation discriminator {discriminator:?}"
        );
    }
    assert!(ops.iter().any(|op| matches!(op,
        Ir1Op::HostCall { capability, arg_count: 3 }
            if capability == "fs:write")));
    assert!(ops.iter().any(|op| matches!(op,
        Ir1Op::HostCall { capability, arg_count: 3 }
            if capability == "fs:read")));
    assert!(ops.iter().any(|op| matches!(op,
        Ir1Op::HostCall { capability, arg_count: 2 }
            if capability == "fs:read")));
}

#[test]
fn fs_promises_subobject_is_deep_scanned_and_discriminated_bd_8u1t5() {
    let ops = lower_script_source_ops(
        "const fs = require('fs');\n\
         (async () => {\n\
           await fs.promises.mkdir('tree', { recursive: true });\n\
           return fs.promises.readdir('tree');\n\
         })();\n",
        "fs_promises_deep_bd_8u1t5.js",
    );
    for discriminator in ["\0fsop:mkdir", "\0fsop:readdir"] {
        assert!(
            ops_deep_match(&ops, &|op| matches!(op,
                Ir1Op::LoadLiteral { value: Ir1Literal::String(value) }
                    if value == discriminator)),
            "deep fs.promises call must carry {discriminator:?}"
        );
    }
    assert!(ops_deep_match(&ops, &|op| matches!(op,
        Ir1Op::HostCall { capability, .. } if capability == "promise:resolve")));
}

#[test]
fn fs_access_constants_fold_to_posix_values_bd_8u1t5() {
    let ops = lower_script_source_ops(
        "const fs = require('fs');\n\
         fs.accessSync('entry', fs.constants.F_OK);\n\
         console.log(fs.constants.R_OK, fs.constants.W_OK, fs.constants.X_OK);\n",
        "fs_constants_bd_8u1t5.js",
    );
    for expected in [0, 4, 2, 1] {
        assert!(ops.iter().any(|op| matches!(op,
            Ir1Op::LoadLiteral { value: Ir1Literal::Integer(value) }
                if *value == expected)));
    }
    assert!(ops.iter().any(|op| matches!(op,
        Ir1Op::LoadLiteral { value: Ir1Literal::String(value) }
            if value == "\0fsop:access")));
}

/// bd-201vt: the inline async callback read `require('fs').readFile(path, cb)`
/// lowers to an `fs:read` HostCall carrying both the path and the callback
/// closure (arg_count == 2); dispatch detects the trailing closure and defers
/// the callback. (The `*Sync` recognizer is untouched — these are the async
/// `readFile`/`writeFile` method names.)
#[test]
fn inline_callback_read_lowers_to_fs_read_with_closure_bd_201vt() {
    let ops = lower_script_source_ops(
        "require('fs').readFile('out.txt', function (err, data) {});\n",
        "inline_cb_read_fs.js",
    );
    assert_eq!(
        fs_read_hostcall_arg_count(&ops),
        Some(2),
        "require('fs').readFile(path, cb) must lower to fs:read with path + callback"
    );
}

/// bd-201vt: the inline async callback read with an explicit encoding
/// `require('fs').readFile(path, 'utf8', cb)` lowers to an arity-3 `fs:read`
/// (path, encoding, callback).
#[test]
fn inline_callback_read_with_encoding_lowers_arity_three_bd_201vt() {
    let ops = lower_script_source_ops(
        "require('fs').readFile('out.txt', 'utf8', function (err, data) {});\n",
        "inline_cb_read_enc_fs.js",
    );
    assert_eq!(
        fs_read_hostcall_arg_count(&ops),
        Some(3),
        "require('fs').readFile(path, 'utf8', cb) must lower to fs:read with all three args"
    );
}

/// bd-201vt: the inline async callback write
/// `require('fs').writeFile(path, data, cb)` lowers to an arity-3 `fs:write`
/// (path, data, callback).
#[test]
fn inline_callback_write_lowers_to_fs_write_with_closure_bd_201vt() {
    let ops = lower_script_source_ops(
        "require('fs').writeFile('out.txt', 'bytes', function (err) {});\n",
        "inline_cb_write_fs.js",
    );
    assert_eq!(
        fs_write_hostcall_arg_count(&ops),
        Some(3),
        "require('fs').writeFile(path, data, cb) must lower to fs:write with path + data + callback"
    );
}

/// bd-201vt: the binding async callback form
/// `const fs = require('fs'); fs.readFile(path, cb)` is recognized via the
/// usage-gated alias sentinel (now also recorded for callback-method usage) and
/// lowers to an `fs:read` HostCall.
#[test]
fn binding_callback_read_lowers_to_fs_read_bd_201vt() {
    let ops = lower_script_source_ops(
        "const fs = require('fs');\n\
         fs.readFile('out.txt', function (err, data) {});\n",
        "binding_cb_read_fs.js",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "const fs = require('fs'); fs.readFile(path, cb) must lower to an fs:read hostcall"
    );
}

/// bd-201vt: a bare/unused `const fs = require('fs')` whose only fs use is an
/// async callback method still keeps the ambient-authority denial when the
/// alias is NOT actually called — fail-closed parity with the sync forms. Here
/// the alias is used, so it MUST be recognized (positive control for the
/// usage-gate extension); the negative side is covered by the existing
/// `unused_*` sync tests sharing the same gate.
#[test]
fn binding_callback_write_lowers_to_fs_write_bd_201vt() {
    let ops = lower_script_source_ops(
        "const fs = require('fs');\n\
         fs.writeFile('out.txt', 'bytes', function (err) {});\n",
        "binding_cb_write_fs.js",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:write"),
        "const fs = require('fs'); fs.writeFile(path, data, cb) must lower to an fs:write hostcall"
    );
}

/// bd-201vt: a NAMED ESM import of the async callback fns
/// (`import { readFile, writeFile } from 'node:fs'`) used as direct calls
/// lowers to fs:read/fs:write HostCalls (with the trailing callback) and elides
/// the node:fs module load.
#[test]
fn esm_named_callback_import_lowers_to_hostcalls_bd_201vt() {
    let ops = lower_esm_source_ops(
        "import { readFile, writeFile } from 'node:fs';\n\
         writeFile('out.txt', 'bytes', function (err) {});\n\
         readFile('out.txt', function (err, data) {});\n",
        "esm_named_callback_fs.mjs",
    );
    assert_eq!(
        fs_read_hostcall_arg_count(&ops),
        Some(2),
        "readFile(path, cb) named import must lower to fs:read with path + callback"
    );
    assert_eq!(
        fs_write_hostcall_arg_count(&ops),
        Some(3),
        "writeFile(path, data, cb) named import must lower to fs:write with all three args"
    );
    assert!(
        !ops_have_fs_import_module(&ops),
        "node:fs module load must be elided for the confirmed callback named import"
    );
}

/// bd-201vt: a named ESM callback read with an explicit encoding
/// (`readFile(path, 'utf8', cb)`) lowers to an arity-3 fs:read.
#[test]
fn esm_named_callback_read_with_encoding_arity_three_bd_201vt() {
    let ops = lower_esm_source_ops(
        "import { readFile } from 'node:fs';\n\
         readFile('out.txt', 'utf8', function (err, data) {});\n",
        "esm_named_cb_read_enc_fs.mjs",
    );
    assert_eq!(
        fs_read_hostcall_arg_count(&ops),
        Some(3),
        "readFile(path, 'utf8', cb) named import must lower to fs:read with all three args"
    );
}

/// bd-201vt: a NAMESPACE ESM import (`import * as fs from 'node:fs'`) used as
/// `fs.readFile(path, cb)` reuses the alias-sentinel member-call recognizer
/// (extended to the async method names) and lowers to fs:read.
#[test]
fn esm_namespace_callback_member_lowers_to_fs_read_bd_201vt() {
    let ops = lower_esm_source_ops(
        "import * as fs from 'node:fs';\n\
         fs.readFile('out.txt', function (err, data) {});\n",
        "esm_namespace_cb_read_fs.mjs",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "import * as fs; fs.readFile(path, cb) must lower to an fs:read hostcall"
    );
}

/// bd-201vt: a DEFAULT ESM import (`import fs from 'node:fs'`) used as
/// `fs.writeFile(path, data, cb)` likewise lowers to fs:write via the shared
/// alias-sentinel member-call recognizer.
#[test]
fn esm_default_callback_member_lowers_to_fs_write_bd_201vt() {
    let ops = lower_esm_source_ops(
        "import fs from 'node:fs';\n\
         fs.writeFile('out.txt', 'bytes', function (err) {});\n",
        "esm_default_cb_write_fs.mjs",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:write"),
        "import fs from 'node:fs'; fs.writeFile(path, data, cb) must lower to an fs:write hostcall"
    );
}

#[test]
fn http_facade_static_surface_lowers_to_distinct_builtins_bd_d0n7u() {
    let ops = lower_script_source_ops(
        "const http = require('node:http');\n\
         function exercise() {\n\
           http.createServer(() => {});\n\
           http.get('http://127.0.0.1:9/');\n\
           http.request('http://127.0.0.1:9/');\n\
           new http.Agent({ keepAlive: false });\n\
           return [http.STATUS_CODES, http.METHODS];\n\
         }\n",
        "http_facade_static_surface_bd_d0n7u.js",
    );

    for capability in [
        "builtin:HttpCreateServer",
        "builtin:HttpGet",
        "builtin:HttpRequest",
        "builtin:HttpAgent",
        "builtin:HttpStatusCodes",
        "builtin:HttpMethods",
    ] {
        assert_eq!(
            count_hostcall_deep(&ops, capability),
            1,
            "expected exactly one {capability} hostcall"
        );
    }
    assert!(
        !ops_have_hostcall(&ops, "module:require"),
        "a confirmed HTTP facade must elide its ambient require initializer"
    );
    assert!(
        !ops_have_hostcall(&ops, "net:request") && !ops_have_hostcall(&ops, "net:client_request"),
        "plain HTTP facade operations must not reuse external-egress capabilities"
    );
}

#[test]
fn http_inline_require_is_exact_and_lexically_shadow_aware_bd_d0n7u() {
    let ops = lower_script_source_ops(
        "require('http').createServer();\n\
         require('node:http').get('http://127.0.0.1:9/');\n\
         new (require('http').Agent)();\n\
         require('node:http').METHODS;\n",
        "http_inline_exact_bd_d0n7u.js",
    );
    assert_eq!(count_hostcall_deep(&ops, "builtin:HttpCreateServer"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:HttpGet"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:HttpAgent"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:HttpMethods"), 1);

    let shadowed = lower_script_source_ops(
        "function probe(require) {\n\
           return require('http').createServer();\n\
         }\n",
        "http_inline_require_shadow_bd_d0n7u.js",
    );
    for capability in [
        "builtin:HttpCreateServer",
        "builtin:HttpGet",
        "builtin:HttpRequest",
        "builtin:HttpAgent",
        "builtin:HttpStatusCodes",
        "builtin:HttpMethods",
    ] {
        assert_eq!(
            count_hostcall_deep(&shadowed, capability),
            0,
            "a lexical require parameter must not acquire {capability} provenance"
        );
    }
    assert!(
        ops_deep_match(&shadowed, &|op| matches!(op, Ir1Op::Call { .. }))
            && ops_deep_match(&shadowed, &|op| matches!(op, Ir1Op::CallMethod { .. })),
        "a lexical require parameter must retain generic call semantics"
    );
}

#[test]
fn http_alias_sentinel_propagates_and_nested_shadows_suppress_it_bd_d0n7u() {
    let ops = lower_script_source_ops(
        "const http = require('http');\n\
         http.get('http://127.0.0.1:9/');\n\
         function nested() { return http.createServer(); }\n\
         function parameterShadow(http) { return http.get('/local'); }\n\
         { const http = { request() {} }; http.request('/local'); }\n",
        "http_nested_provenance_bd_d0n7u.js",
    );
    assert_eq!(count_hostcall_deep(&ops, "builtin:HttpGet"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:HttpCreateServer"), 1);
    assert_eq!(count_hostcall_deep(&ops, "builtin:HttpRequest"), 0);
}

#[test]
fn http_mutable_escaped_dynamic_and_tdz_aliases_fail_closed_bd_d0n7u() {
    for (label, source) in [
        ("unused", "const http = require('http');"),
        (
            "let-alias",
            "let http = require('http'); http.get('http://127.0.0.1:9/');",
        ),
        (
            "var-alias",
            "var http = require('http'); http.get('http://127.0.0.1:9/');",
        ),
        (
            "reassigned",
            "const http = require('http'); http = null; http.createServer();",
        ),
        (
            "member-mutation",
            "const http = require('http'); http.createServer = () => null; http.createServer();",
        ),
        (
            "alias-escape",
            "const http = require('http'); consume(http); http.createServer();",
        ),
        (
            "method-escape",
            "const http = require('http'); const create = http.createServer; create();",
        ),
        (
            "computed",
            "const http = require('http'); http['get']('http://127.0.0.1:9/');",
        ),
        (
            "optional",
            "const http = require('http'); http?.get('http://127.0.0.1:9/');",
        ),
        (
            "unknown",
            "const http = require('http'); http.validateHeaderName('x');",
        ),
        (
            "same-declaration-tdz",
            "const methods = http.METHODS, http = require('http');",
        ),
        (
            "predeclaration-call-hazard",
            "probe(); const http = require('http'); function probe() { return http.METHODS; }",
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("http_{label}_bd_d0n7u.js"));
        let error = lower_ir0_to_ir1(&ir0)
            .expect_err("untrusted HTTP module provenance must preserve ambient denial");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation { .. }
            ),
            "{label} should preserve ambient require denial, got {error:?}"
        );
    }
}

#[test]
fn http_loop_assignment_targets_do_not_preserve_module_authority_bd_d0n7u() {
    for (label, source) in [
        (
            "for-of-http",
            "const http = require('http');\n\
             for (http of [null]) {}\n\
             http.get('http://127.0.0.1:9/');\n",
        ),
        (
            "for-in-https",
            "const https = require('https');\n\
             for (https in { key: true }) {}\n\
             https.get('https://127.0.0.1:9/');\n",
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("{label}_bd_d0n7u.js"));
        let error = lower_ir0_to_ir1(&ir0)
            .expect_err("a loop assignment target must invalidate module provenance");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation { .. }
            ),
            "{label} must preserve ambient require denial, got {error:?}"
        );
    }
}

#[test]
fn zero_argument_http_requests_fail_closed_before_hostcall_bd_d0n7u() {
    for (label, source) in [
        ("http-get", "require('http').get();"),
        ("http-request", "require('http').request();"),
        ("https-get", "require('https').get();"),
        ("https-request", "require('https').request();"),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("zero_arg_{label}_bd_d0n7u.js"));
        let error = lower_ir0_to_ir1(&ir0)
            .expect_err("a malformed zero-argument request must not emit a hostcall");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation { .. }
            ),
            "{label} should fail at the ambient module boundary, got {error:?}"
        );
    }

    let named = lower_esm_source_ops(
        "import { get } from 'node:http';\nget();\n",
        "zero_arg_named_http_bd_d0n7u.mjs",
    );
    assert!(ops_have_http_import_module(&named));
    assert!(!ops_have_hostcall(&named, "builtin:HttpGet"));
}

/// bd-d0n7u: authenticated plain-http calls enter the hermetic HTTP facade.
#[test]
fn http_binding_get_lowers_to_http_builtin_bd_d0n7u() {
    let ops = lower_script_source_ops(
        "const http = require('http');\n\
         http.get('http://127.0.0.1:9/');\n",
        "http_binding_get.js",
    );
    assert!(
        ops_have_hostcall(&ops, "builtin:HttpGet"),
        "const http = require('http'); http.get(url) must lower to builtin:HttpGet"
    );
}

/// bd-656a2 / bd-3894s / bd-d0n7u: the inline form
/// `require('http').request(url)` enters the hermetic HTTP facade through the
/// dedicated `builtin:HttpRequest` capability, never external egress.
#[test]
fn http_inline_request_lowers_to_http_builtin_bd_d0n7u() {
    let ops = lower_script_source_ops(
        "require('http').request('http://127.0.0.1:9/');\n",
        "http_inline_request.js",
    );
    assert!(
        ops_have_hostcall(&ops, "builtin:HttpRequest"),
        "require('http').request(url) must lower to builtin:HttpRequest"
    );
    assert!(
        !ops_have_hostcall(&ops, "net:client_request"),
        "plain http.request must not lower directly to external egress"
    );
}

/// bd-656a2 / bd-d0n7u: HTTPS remains external and lowers to `net:request`.
#[test]
fn https_binding_get_lowers_to_net_request_bd_656a2() {
    let ops = lower_script_source_ops(
        "const https = require('https');\n\
         https.get('https://127.0.0.1:9/');\n",
        "https_binding_get.js",
    );
    assert!(
        ops_have_hostcall(&ops, "net:request"),
        "const https = require('https'); https.get(url) must lower to a net:request hostcall"
    );
    assert!(
        !ops_have_hostcall(&ops, "builtin:HttpGet"),
        "HTTPS must never be silently routed through the plaintext HTTP facade"
    );
}

/// bd-656a2: `http.get(url)` with NO `const http = require('http')` binding
/// in scope is an ordinary member call — the alias sentinel was never
/// recorded, so it must NOT lower to `net:request` (the usage-gate is
/// fail-closed, exactly like the fs binding form).
#[test]
fn unbound_http_get_does_not_lower_to_http_builtin_bd_d0n7u() {
    let ops = lower_script_source_ops("http.get('http://127.0.0.1:9/');\n", "unbound_http_get.js");
    assert!(
        !ops_have_hostcall(&ops, "builtin:HttpGet"),
        "http.get(url) without module provenance must not lower to builtin:HttpGet"
    );
}

/// bd-656a2: the http recognizer is specifier-gated — a DIFFERENT recognized
/// module binding (`const fs = require('fs'); fs.readFileSync(...)`) lowers to
/// its own `fs:read` hostcall and must NOT be mis-recognized as a `net:request`
/// network egress. (A bare `require('<arbitrary-module>')` cannot be exercised
/// here: `require` itself trips the ambient-authority gate unless the module is
/// one of the recognized + usage-confirmed builtins that elide the require.)
#[test]
fn fs_binding_does_not_lower_to_http_builtin_bd_d0n7u() {
    let ops = lower_script_source_ops(
        "const fs = require('fs');\n\
         fs.readFileSync('out.txt');\n",
        "fs_binding_not_net.js",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "the fs binding form must still lower to its fs:read hostcall"
    );
    assert!(
        !ops_have_hostcall(&ops, "builtin:HttpGet"),
        "an fs binding must not be mis-recognized as an HTTP builtin"
    );
}

/// bd-3894s (http leg ESM imports): a named ESM import (`import { get,
/// request } from 'node:http'`) used as direct calls lowers to the http
/// HostCalls and elides the (fault-prone) node:http module load — the http
/// mirror of the fs named-import lowering (bd-1xl17.b). The two operations
/// retain distinct hermetic-facade capabilities.
#[test]
fn esm_named_http_import_lowers_to_http_builtins_bd_d0n7u() {
    let ops = lower_esm_source_ops(
        "import { get, request } from 'node:http';\n\
         get('http://127.0.0.1:9/');\n\
         request('http://127.0.0.1:9/');\n",
        "esm_named_http.mjs",
    );
    assert!(
        ops_have_hostcall(&ops, "builtin:HttpGet"),
        "named http import `get(url)` must lower to builtin:HttpGet"
    );
    assert!(
        ops_have_hostcall(&ops, "builtin:HttpRequest"),
        "named http import `request(url)` must lower to builtin:HttpRequest"
    );
    assert!(
        !ops_have_http_import_module(&ops),
        "node:http module load must be elided for the confirmed named import"
    );
}

/// bd-3894s: named http import recognition respects `as` renames — the local
/// name (`req`), not the imported name, is what the call site uses. `request`
/// retains its dedicated `builtin:HttpRequest` capability under a rename.
#[test]
fn esm_named_http_import_rename_lowers_to_http_builtin_bd_d0n7u() {
    let ops = lower_esm_source_ops(
        "import { request as req } from 'node:http';\n\
         req('http://127.0.0.1:9/');\n",
        "esm_named_rename_http.mjs",
    );
    assert!(
        ops_have_hostcall(&ops, "builtin:HttpRequest"),
        "a renamed http `request` named import must lower to builtin:HttpRequest"
    );
    assert!(
        !ops_have_http_import_module(&ops),
        "node:http module load must be elided"
    );
}

#[test]
fn esm_named_http_import_mutation_and_escape_fail_closed_bd_d0n7u() {
    for (label, source) in [
        (
            "http-reassigned",
            "import { get } from 'node:http';\n\
             get = localGet;\n\
             get('http://127.0.0.1:9/');\n",
        ),
        (
            "http-escaped",
            "import { request } from 'node:http';\n\
             consume(request);\n\
             request('http://127.0.0.1:9/');\n",
        ),
    ] {
        let ops = lower_esm_source_ops(source, &format!("esm_named_{label}_bd_d0n7u.mjs"));
        assert!(
            ops_have_http_import_module(&ops),
            "{label} must preserve the real module load after provenance rejection"
        );
        for capability in [
            "builtin:HttpCreateServer",
            "builtin:HttpGet",
            "builtin:HttpRequest",
            "net:request",
            "net:client_request",
        ] {
            assert!(
                !ops_have_hostcall(&ops, capability),
                "{label} must not retain {capability} authority"
            );
        }
    }
}

#[test]
fn esm_named_https_import_mutation_and_happy_path_split_bd_d0n7u() {
    let rejected = lower_esm_source_ops(
        "import { get } from 'node:https';\n\
         get = localGet;\n\
         get('https://127.0.0.1:9/');\n",
        "esm_named_https_mutation_bd_d0n7u.mjs",
    );
    assert!(
        ops_have_https_import_module(&rejected),
        "a reassigned HTTPS import must preserve the module load"
    );
    assert!(!ops_have_hostcall(&rejected, "net:request"));
    assert!(!ops_have_hostcall(&rejected, "builtin:HttpGet"));

    let accepted = lower_esm_source_ops(
        "import { get } from 'node:https';\n\
         get('https://127.0.0.1:9/');\n",
        "esm_named_https_happy_bd_d0n7u.mjs",
    );
    assert!(ops_have_hostcall(&accepted, "net:request"));
    assert!(!ops_have_hostcall(&accepted, "builtin:HttpGet"));
    assert!(!ops_have_https_import_module(&accepted));
}

#[test]
fn esm_http_namespace_mutation_and_escape_fail_closed_bd_d0n7u() {
    for (label, source) in [
        (
            "namespace-mutation",
            "import * as http from 'node:http';\n\
             http.get = localGet;\n\
             http.get('http://127.0.0.1:9/');\n",
        ),
        (
            "namespace-escape",
            "import * as http from 'node:http';\n\
             consume(http);\n\
             http.get('http://127.0.0.1:9/');\n",
        ),
    ] {
        let ops = lower_esm_source_ops(source, &format!("esm_{label}_bd_d0n7u.mjs"));
        assert!(ops_have_http_import_module(&ops));
        assert!(!ops_have_hostcall(&ops, "builtin:HttpGet"));
        assert!(!ops_have_hostcall(&ops, "net:request"));
    }
}

/// bd-3894s: a namespace ESM import (`import * as http from 'node:http'`)
/// used as `http.get/request(...)` lowers via the shared member-call
/// recognizer + module-alias sentinel (mirror of the fs namespace form).
#[test]
fn esm_namespace_http_import_lowers_to_http_builtin_bd_d0n7u() {
    let ops = lower_esm_source_ops(
        "import * as http from 'node:http';\n\
         http.get('http://127.0.0.1:9/');\n",
        "esm_namespace_http.mjs",
    );
    assert!(
        ops_have_hostcall(&ops, "builtin:HttpGet"),
        "namespace http.get(url) must lower to builtin:HttpGet"
    );
    assert!(
        !ops_have_http_import_module(&ops),
        "node:http module load must be elided"
    );
}

/// bd-3894s: a default ESM import (`import http from 'node:http'`) used as
/// `http.request(...)` lowers via the shared member-call recognizer to the
/// dedicated `builtin:HttpRequest` HostCall.
#[test]
fn esm_default_http_import_lowers_to_http_builtin_bd_d0n7u() {
    let ops = lower_esm_source_ops(
        "import http from 'node:http';\n\
         http.request('http://127.0.0.1:9/');\n",
        "esm_default_http.mjs",
    );
    assert!(
        ops_have_hostcall(&ops, "builtin:HttpRequest"),
        "default-imported http.request(url) must lower to builtin:HttpRequest"
    );
    assert!(
        !ops_have_http_import_module(&ops),
        "node:http module load must be elided"
    );
}

/// bd-3894s fail-closed: a bare/UNUSED http import is NOT recognized — the
/// node:http module load is preserved and no network HostCall is emitted, so
/// the import keeps its current (runtime module-load) behavior. The ESM
/// analogue of the require-binding usage-gating that preserves the
/// ambient-authority denial of bare/unused requires.
#[test]
fn esm_unused_http_import_is_not_recognized_bd_3894s() {
    let ops = lower_esm_source_ops("import { get } from 'node:http';\n", "esm_unused_http.mjs");
    assert!(
        ops_have_http_import_module(&ops),
        "an unused http named import must keep its module load (no recognition)"
    );
    assert!(
        !ops_have_hostcall(&ops, "builtin:HttpGet"),
        "an unused http named import must not emit an HTTP builtin"
    );
}

/// bd-3894s specifier-gating: `get` is a common identifier — a named import
/// of `get` from a NON-http module (`import { get } from 'lodash'`) must NOT
/// be mis-recognized as an http egress. Only `node:http`/`node:https` (and
/// the bare `http`/`https`) specifiers register the http named sentinel, so
/// the direct call stays an ordinary call with no `net:request` hostcall.
#[test]
fn esm_named_get_from_non_http_module_does_not_lower_bd_3894s() {
    let ops = lower_esm_source_ops(
        "import { get } from 'lodash';\n\
         get({}, 'k');\n",
        "esm_named_get_lodash.mjs",
    );
    assert!(
        !ops_have_hostcall(&ops, "builtin:HttpGet"),
        "a `get` imported from a non-http module must not lower to builtin:HttpGet"
    );
}

/// bd-3894s (http leg, fetch global): the bare `fetch(url)` global lowers to
/// a `net:request` HostCall — the egress proof for the dominant modern HTTP
/// idiom. It remains external while plain `http` uses hermetic builtins.
#[test]
fn fetch_global_lowers_to_net_request_bd_3894s() {
    let ops = lower_script_source_ops("fetch('http://127.0.0.1:9/');\n", "fetch_global.js");
    assert!(
        ops_have_hostcall(&ops, "net:request"),
        "fetch(url) must lower to a net:request hostcall"
    );
}

/// bd-3894s slice (2): `fetch(url, init)` forwards the request-`init` object
/// as arg[1] (arg_count == 2) so the interpreter frames the real
/// method/headers/body from it. A bare `fetch(url)` forwards only the URL
/// (arg_count == 1), leaving the unchanged slice-1 GET egress.
#[test]
fn fetch_global_with_init_forwards_options_arg_bd_3894s() {
    let ops = lower_script_source_ops(
        "fetch('http://127.0.0.1:9/', { method: 'POST' });\n",
        "fetch_global_init.js",
    );
    assert!(
        ops_have_hostcall(&ops, "net:request"),
        "fetch(url, init) must lower to a net:request hostcall"
    );
    assert_eq!(
        net_request_arg_count(&ops),
        Some(2),
        "fetch(url, init) must forward the init object as arg[1] (arg_count == 2)"
    );

    let bare = lower_script_source_ops("fetch('http://127.0.0.1:9/');\n", "fetch_bare.js");
    assert_eq!(
        net_request_arg_count(&bare),
        Some(1),
        "a bare fetch(url) forwards only the URL (arg_count == 1)"
    );
}

/// bd-3894s slice (2)+(2b): `http.request(url, { method, headers })` forwards
/// the options object as arg[1] (arg_count == 2) on the dedicated hermetic
/// `builtin:HttpRequest` lowering; a bare `http.get(url)` stays at arg_count
/// == 1 on `builtin:HttpGet`.
#[test]
fn http_request_with_options_forwards_options_arg_bd_3894s() {
    let ops = lower_script_source_ops(
        "const http = require('http');\n\
         http.request('http://127.0.0.1:9/', { method: 'PUT' });\n",
        "http_request_options.js",
    );
    assert!(
        ops_have_hostcall(&ops, "builtin:HttpRequest"),
        "http.request(url, options) must lower to builtin:HttpRequest"
    );
    assert_eq!(
        first_hostcall_arg_count(&ops, "builtin:HttpRequest"),
        Some(2),
        "http.request(url, options) must forward the options object as arg[1]"
    );

    let bare = lower_script_source_ops(
        "const http = require('http');\n\
         http.get('http://127.0.0.1:9/');\n",
        "http_get_bare.js",
    );
    assert_eq!(
        first_hostcall_arg_count(&bare, "builtin:HttpGet"),
        Some(1),
        "a bare http.get(url) forwards only the URL (arg_count == 1)"
    );
}

/// bd-3894s slice (2c): `http.get(url, cb)` — the Node response-callback form —
/// forwards the trailing callback closure as arg[1] (`net:request` arg_count ==
/// 2), so the interpreter can detect the trailing `Value::Closure` and deliver
/// `cb(res)` after the egress. (Previously the callback was dropped: the lowering
/// capped `net:request` at arg_count 2 but treated arg[1] purely as options.)
#[test]
fn http_get_with_callback_forwards_callback_arg_bd_3894s() {
    let ops = lower_script_source_ops(
        "require('http').get('http://127.0.0.1:9/', (res) => {});\n",
        "http_get_callback.js",
    );
    assert!(
        ops_have_hostcall(&ops, "builtin:HttpGet"),
        "http.get(url, cb) must lower to builtin:HttpGet"
    );
    assert_eq!(
        first_hostcall_arg_count(&ops, "builtin:HttpGet"),
        Some(2),
        "http.get(url, cb) must forward the trailing callback closure as arg[1]"
    );
}

/// bd-3894s slice (2c): `http.get(url, options, cb)` — options AND a response
/// callback — forwards all THREE arguments (`net:request` arg_count == 3). The
/// interpreter frames the request from the arg[1] options object and delivers
/// `cb(res)` to the trailing closure at arg[2]. (Previously arg[2] was dropped —
/// the lowering capped `net:request` at arg_count 2.)
#[test]
fn http_get_with_options_and_callback_forwards_three_args_bd_3894s() {
    let ops = lower_script_source_ops(
        "const http = require('http');\n\
         http.get('http://127.0.0.1:9/', { method: 'GET' }, (res) => {});\n",
        "http_get_options_callback.js",
    );
    assert_eq!(
        first_hostcall_arg_count(&ops, "builtin:HttpGet"),
        Some(3),
        "http.get(url, options, cb) must forward url + options + callback"
    );
}

/// bd-3894s slice (2c): `http.request(url, options, cb)` forwards all three
/// arguments on the `net:client_request` lowering (arg_count == 3). The
/// interpreter captures the trailing callback as the ClientRequest's response
/// callback and delivers `cb(res)` from the deferred `.end()` egress.
#[test]
fn http_request_with_callback_forwards_to_net_client_request_bd_3894s() {
    let ops = lower_script_source_ops(
        "const http = require('http');\n\
         http.request('http://127.0.0.1:9/', { method: 'POST' }, (res) => {});\n",
        "http_request_callback.js",
    );
    assert!(
        ops_have_hostcall(&ops, "builtin:HttpRequest"),
        "http.request(url, options, cb) must lower to builtin:HttpRequest"
    );
    assert_eq!(
        first_hostcall_arg_count(&ops, "builtin:HttpRequest"),
        Some(3),
        "http.request(url, options, cb) must forward url + options + callback"
    );
}

/// bd-3894s: `fetch` returns a Promise, so the lowering wraps the egress
/// result in `promise:resolve` — `fetch(url)` evaluates to a Promise (mirror
/// of the fs/promises named-import lowering). The resolved value is undefined
/// until response modeling lands.
#[test]
fn fetch_global_returns_promise_bd_3894s() {
    let ops = lower_script_source_ops("fetch('http://127.0.0.1:9/');\n", "fetch_global_promise.js");
    assert!(
        ops_have_hostcall(&ops, "net:request"),
        "fetch must emit the net:request egress"
    );
    assert!(
        ops_have_hostcall(&ops, "promise:resolve"),
        "fetch must wrap its result in promise:resolve so fetch(url) is a Promise"
    );
}

/// bd-3894s fail-closed: a user-shadowed `fetch` (`const fetch = ...`) is a
/// local function, NOT the host global, so the recognizer must NOT report it
/// as the host egress (the shadowing gate shared with the timer/global-
/// function builtins). This is checked directly on the recognizer rather
/// than end-to-end because `fetch` is ALSO ambient-authority-gated at the
/// identifier level (a bare `fetch` reference trips a NetConnect ambient
/// violation, line ~7257), so a shadowed `fetch(url)` fail-closes at the
/// ambient gate before emitting ops — it can never be observed as a stray
/// net:request. The recognizer gate is what defends against the engine
/// mis-lowering the user's own `fetch` to a FALSE egress proof.
#[test]
fn shadowed_fetch_does_not_lower_bd_3894s() {
    let callee = Expression::Identifier("fetch".to_string());

    // Unshadowed: the bare global is recognized as the net:request egress.
    let unshadowed: BTreeMap<String, BindingId> = BTreeMap::new();
    assert_eq!(
        fetch_builtin_call_capability(&callee, &unshadowed),
        Some("net:request"),
        "an unshadowed bare `fetch` must be recognized as a net:request egress"
    );

    // Shadowed by a user binding in scope: NOT recognized — this is the gate
    // that prevents a false egress proof for the user's own `fetch`.
    let mut shadowed: BTreeMap<String, BindingId> = BTreeMap::new();
    shadowed.insert("fetch".to_string(), 0);
    assert_eq!(
        fetch_builtin_call_capability(&callee, &shadowed),
        None,
        "a user-shadowed `fetch` binding must not be recognized as a network egress"
    );
}

/// bd-1xl17.d: the inline `require('fs').readFileSync(path, 'utf8')` form
/// (arity 2) is recognized and lowers to an `fs:read` HostCall carrying BOTH
/// the path and the encoding (arg_count == 2); the encoding selects the JS
/// return shape at dispatch. Before the arity relaxation an arity-2 read fell
/// through the fs recognizer and faulted as an ordinary call.
#[test]
fn inline_read_with_encoding_lowers_to_arity_two_hostcall_bd_1xl17_d() {
    let ops = lower_script_source_ops(
        "require('fs').readFileSync('out.txt', 'utf8');\n",
        "inline_read_encoding_fs.js",
    );
    assert_eq!(
        fs_read_hostcall_arg_count(&ops),
        Some(2),
        "require('fs').readFileSync(path, 'utf8') must lower to fs:read with both args"
    );
}

/// bd-1xl17.d: the inline arity-1 (no-encoding) read still lowers to a
/// single-arg `fs:read` — the relaxation widened the read to accept an
/// optional encoding without changing the bare form.
#[test]
fn inline_read_without_encoding_stays_arity_one_bd_1xl17_d() {
    let ops = lower_script_source_ops(
        "require('fs').readFileSync('out.txt');\n",
        "inline_read_noenc_fs.js",
    );
    assert_eq!(
        fs_read_hostcall_arg_count(&ops),
        Some(1),
        "require('fs').readFileSync(path) must still lower to fs:read with one arg"
    );
}

/// bd-1xl17.d: a named ESM import read with an encoding
/// (`readFileSync(path, 'utf8')`) lowers to an `fs:read` HostCall with both
/// args (arg_count == 2) and still elides the node:fs module load.
#[test]
fn esm_read_with_encoding_lowers_to_arity_two_hostcall_bd_1xl17_d() {
    let ops = lower_esm_source_ops(
        "import { readFileSync } from 'node:fs';\n\
         readFileSync('out.txt', 'utf8');\n",
        "esm_read_encoding_fs.mjs",
    );
    assert_eq!(
        fs_read_hostcall_arg_count(&ops),
        Some(2),
        "readFileSync(path, 'utf8') must lower to an fs:read HostCall with both args"
    );
    assert!(
        !ops_have_fs_import_module(&ops),
        "node:fs module load must be elided for the confirmed encoding read"
    );
}

/// bd-1xl17.c helper: true when the op stream still loads the fs/promises
/// module (i.e. the import was NOT recognized/elided).
fn ops_have_fs_promises_import_module(ops: &[Ir1Op]) -> bool {
    ops.iter().any(|op| {
        matches!(op, Ir1Op::ImportModule { specifier, .. }
            if module_source_matches(specifier, is_fs_promises_module_specifier))
    })
}

/// bd-1xl17.c: a named import from 'node:fs/promises' used as a direct call —
/// `readFile(path)` — lowers to an `fs:read` HostCall WRAPPED in a
/// `promise:resolve` HostCall (so the call evaluates to a Promise), and elides
/// the fs/promises module load. The async analogue of bd-1xl17.b/.d.
#[test]
fn esm_fs_promises_read_lowers_to_promise_wrapped_hostcall_bd_1xl17_c() {
    let ops = lower_esm_source_ops(
        "import { readFile } from 'node:fs/promises';\n\
         readFile('out.txt');\n",
        "esm_fs_promises_read.mjs",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "fs/promises readFile must lower to an fs:read host effect"
    );
    assert!(
        ops_have_hostcall(&ops, "promise:resolve"),
        "fs/promises readFile must wrap its result in promise:resolve"
    );
    assert!(
        !ops_have_fs_promises_import_module(&ops),
        "a confirmed fs/promises import must elide the module load"
    );
}

/// bd-1xl17.c: `writeFile(path, data)` from 'fs/promises' lowers to an
/// fs:write host effect wrapped in promise:resolve.
#[test]
fn esm_fs_promises_write_lowers_to_promise_wrapped_hostcall_bd_1xl17_c() {
    let ops = lower_esm_source_ops(
        "import { writeFile } from 'fs/promises';\n\
         writeFile('out.txt', 'bytes');\n",
        "esm_fs_promises_write.mjs",
    );
    assert!(ops_have_hostcall(&ops, "fs:write"));
    assert!(
        ops_have_hostcall(&ops, "promise:resolve"),
        "fs/promises writeFile must wrap its result in promise:resolve"
    );
    assert!(!ops_have_fs_promises_import_module(&ops));
}

/// bd-1xl17.c + .d: `readFile(path, 'utf8')` from fs/promises threads the
/// encoding (arg_count == 2 on the fs:read) and still wraps in promise:resolve.
#[test]
fn esm_fs_promises_read_with_encoding_lowers_arity_two_bd_1xl17_c() {
    let ops = lower_esm_source_ops(
        "import { readFile } from 'node:fs/promises';\n\
         readFile('out.txt', 'utf8');\n",
        "esm_fs_promises_read_enc.mjs",
    );
    assert_eq!(fs_read_hostcall_arg_count(&ops), Some(2));
    assert!(ops_have_hostcall(&ops, "promise:resolve"));
}

/// bd-1xl17.c fail-closed: a bare/UNUSED fs/promises import is NOT recognized —
/// the module load is preserved and no fs HostCall is emitted, so the import
/// keeps its current (runtime module-load) behavior. The async analogue of the
/// bd-1xl17.b unused-import gating.
#[test]
fn unused_fs_promises_import_is_not_recognized_bd_1xl17_c() {
    let ops = lower_esm_source_ops(
        "import { readFile } from 'node:fs/promises';\n",
        "esm_fs_promises_unused.mjs",
    );
    assert!(
        ops_have_fs_promises_import_module(&ops),
        "an unused fs/promises import must keep its module load"
    );
    assert!(!ops_have_hostcall(&ops, "fs:read"));
}

/// bd-1xl17.c (CJS binding): `const fsp = require('fs/promises');
/// fsp.readFile(path)` lowers to an fs:read host effect wrapped in
/// promise:resolve (the require-binding analogue of bd-1xl17.a, async).
#[test]
fn cjs_fs_promises_binding_lowers_to_promise_wrapped_hostcall_bd_1xl17_c() {
    let ops = lower_script_source_ops(
        "const fsp = require('fs/promises');\n\
         fsp.readFile('out.txt');\n",
        "cjs_fs_promises_binding.js",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "fs/promises binding readFile must lower to an fs:read host effect"
    );
    assert!(
        ops_have_hostcall(&ops, "promise:resolve"),
        "fs/promises binding readFile must wrap its result in promise:resolve"
    );
}

/// bd-1xl17.c (CJS inline): `require('fs/promises').writeFile(path, data)`
/// lowers to an fs:write host effect wrapped in promise:resolve.
#[test]
fn cjs_fs_promises_inline_lowers_to_promise_wrapped_hostcall_bd_1xl17_c() {
    let ops = lower_script_source_ops(
        "require('fs/promises').writeFile('out.txt', 'bytes');\n",
        "cjs_fs_promises_inline.js",
    );
    assert!(ops_have_hostcall(&ops, "fs:write"));
    assert!(
        ops_have_hostcall(&ops, "promise:resolve"),
        "fs/promises inline writeFile must wrap its result in promise:resolve"
    );
}

/// bd-1xl17.c fail-closed: an fs/promises require alias used only as an
/// UNrecognized method (`fsp.statSync`) is NOT confirmed, so it is not elided —
/// the `require('fs/promises')` keeps hitting the always-deny ambient-authority
/// gate (lowering rejects), exactly like any other un-recognized `require`.
/// Only confirmed `fsp.readFile/writeFile` usage opts into the fs: lowering, so
/// the require-rejection contract is preserved without any authority widening.
#[test]
fn unused_fs_promises_require_binding_is_not_recognized_bd_1xl17_c() {
    let tree = crate::parser_api_stability::parse_script(
        "const fsp = require('fs/promises');\n\
         fsp.statSync('out.txt');\n",
    )
    .expect("parse script");
    let ir0 = Ir0Module::from_syntax_tree(tree, "cjs_fs_promises_unused.js");
    assert!(
        lower_ir0_to_ir1(&ir0).is_err(),
        "an unconfirmed fs/promises require alias must keep the ambient-authority denial"
    );
}

/// bd-1xl17.c (CJS destructure): `const { readFile } = require('fs/promises');
/// readFile(path)` lowers to an fs:read host effect wrapped in promise:resolve.
/// The destructured local reuses the ESM named-import direct-call recognizer;
/// successful lowering (no ambient-denial panic) also proves the require load
/// was elided.
#[test]
fn cjs_fs_promises_destructured_read_lowers_to_promise_wrapped_hostcall_bd_1xl17_c() {
    let ops = lower_script_source_ops(
        "const { readFile } = require('fs/promises');\n\
         readFile('out.txt');\n",
        "cjs_fs_promises_destructured_read.js",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "destructured fs/promises readFile must lower to an fs:read host effect"
    );
    assert!(
        ops_have_hostcall(&ops, "promise:resolve"),
        "destructured fs/promises readFile must wrap its result in promise:resolve"
    );
}

/// bd-1xl17.c (CJS destructure): `const { writeFile } = require('fs/promises');
/// writeFile(path, data)` lowers to an fs:write host effect wrapped in
/// promise:resolve.
#[test]
fn cjs_fs_promises_destructured_write_lowers_to_promise_wrapped_hostcall_bd_1xl17_c() {
    let ops = lower_script_source_ops(
        "const { writeFile } = require('fs/promises');\n\
         writeFile('out.txt', 'bytes');\n",
        "cjs_fs_promises_destructured_write.js",
    );
    assert!(ops_have_hostcall(&ops, "fs:write"));
    assert!(
        ops_have_hostcall(&ops, "promise:resolve"),
        "destructured fs/promises writeFile must wrap its result in promise:resolve"
    );
}

/// bd-1xl17.c (CJS destructure rename): `const { readFile: rf } =
/// require('fs/promises'); rf(path)` — the renamed local `rf` is the bound name
/// recognized at the call site, the property key `readFile` selects the
/// capability. Lowers to a promise-wrapped fs:read.
#[test]
fn cjs_fs_promises_destructured_rename_lowers_bd_1xl17_c() {
    let ops = lower_script_source_ops(
        "const { readFile: rf } = require('fs/promises');\n\
         rf('out.txt');\n",
        "cjs_fs_promises_destructured_rename.js",
    );
    assert!(ops_have_hostcall(&ops, "fs:read"));
    assert!(ops_have_hostcall(&ops, "promise:resolve"));
}

/// bd-1xl17.c + .d (CJS destructure): `const { readFile } =
/// require('fs/promises'); readFile(path, 'utf8')` threads the encoding
/// (arg_count == 2 on the fs:read) and still wraps in promise:resolve.
#[test]
fn cjs_fs_promises_destructured_read_with_encoding_arity_two_bd_1xl17_c() {
    let ops = lower_script_source_ops(
        "const { readFile } = require('fs/promises');\n\
         readFile('out.txt', 'utf8');\n",
        "cjs_fs_promises_destructured_read_enc.js",
    );
    assert_eq!(fs_read_hostcall_arg_count(&ops), Some(2));
    assert!(ops_have_hostcall(&ops, "promise:resolve"));
}

/// bd-1xl17.c fail-closed: an unused destructured fs/promises require
/// (`const { readFile } = require('fs/promises')` with no recognized call) is
/// NOT confirmed, so it is not elided and the `require('fs/promises')` keeps
/// hitting the always-deny ambient-authority gate (lowering rejects). The
/// destructure analogue of the require-binding unused gating.
#[test]
fn unused_fs_promises_destructured_require_is_not_recognized_bd_1xl17_c() {
    let tree = crate::parser_api_stability::parse_script(
        "const { readFile } = require('fs/promises');\n\
         readFile.toString();\n",
    )
    .expect("parse script");
    let ir0 = Ir0Module::from_syntax_tree(tree, "cjs_fs_promises_destructured_unused.js");
    assert!(
        lower_ir0_to_ir1(&ir0).is_err(),
        "an unconfirmed destructured fs/promises require must keep the ambient-authority denial"
    );
}

/// bd-rmaze (CJS destructured sync fs): `const { readFileSync } =
/// require('fs'); readFileSync(path)` lowers to an fs:read host effect. The
/// destructured local reuses the named-import direct-call recognizer;
/// successful lowering (no ambient-denial panic) also proves the
/// `require('fs')` load was elided.
#[test]
fn cjs_fs_destructured_readsync_lowers_bd_rmaze() {
    let ops = lower_script_source_ops(
        "const { readFileSync } = require('fs');\n\
         readFileSync('out.txt');\n",
        "cjs_fs_destructured_readsync.js",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "destructured sync readFileSync must lower to an fs:read host effect"
    );
}

/// bd-rmaze: `const { writeFileSync } = require('fs'); writeFileSync(path,
/// data)` lowers to an fs:write host effect.
#[test]
fn cjs_fs_destructured_writesync_lowers_bd_rmaze() {
    let ops = lower_script_source_ops(
        "const { writeFileSync } = require('fs');\n\
         writeFileSync('out.txt', 'bytes');\n",
        "cjs_fs_destructured_writesync.js",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:write"),
        "destructured sync writeFileSync must lower to an fs:write host effect"
    );
}

/// bd-rmaze (CJS destructured ASYNC callback fs): `const { readFile } =
/// require('fs'); readFile(path, cb)` reuses the same fs:read host effect as
/// the sync form — the trailing callback closure is detected at dispatch. This
/// is the destructured-require gap that was unhandled for BOTH sync and async
/// before bd-rmaze.
#[test]
fn cjs_fs_destructured_readfile_callback_lowers_bd_rmaze() {
    let ops = lower_script_source_ops(
        "const { readFile } = require('fs');\n\
         readFile('out.txt', function (err, data) {});\n",
        "cjs_fs_destructured_readfile_cb.js",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "destructured async readFile(path, cb) must lower to an fs:read host effect"
    );
}

/// bd-rmaze (CJS destructure rename): `const { readFileSync: rd } =
/// require('fs'); rd(path)` — the renamed local `rd` is the bound name
/// recognized at the call site; the property key `readFileSync` selects the
/// capability.
#[test]
fn cjs_fs_destructured_rename_lowers_bd_rmaze() {
    let ops = lower_script_source_ops(
        "const { readFileSync: rd } = require('fs');\n\
         rd('out.txt');\n",
        "cjs_fs_destructured_rename.js",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "a renamed destructured readFileSync must still lower to fs:read"
    );
}

/// bd-rmaze fail-closed: an unused destructured sync-fs require (`const {
/// readFileSync } = require('fs')` with no recognized call) is NOT confirmed,
/// so it is not elided and the `require('fs')` keeps hitting the always-deny
/// ambient-authority gate (lowering rejects). The synchronous analogue of the
/// fs/promises destructured unused gating.
#[test]
fn unused_fs_destructured_require_is_not_recognized_bd_rmaze() {
    let tree = crate::parser_api_stability::parse_script(
        "const { readFileSync } = require('fs');\n\
         readFileSync.toString();\n",
    )
    .expect("parse script");
    let ir0 = Ir0Module::from_syntax_tree(tree, "cjs_fs_destructured_unused.js");
    assert!(
        lower_ir0_to_ir1(&ir0).is_err(),
        "an unconfirmed destructured sync-fs require must keep the ambient-authority denial"
    );
}

/// bd-1xl17.c (sub-object inline): `require('fs').promises.readFile(path)` — the
/// promises API hung off the synchronous fs module — lowers to a promise-wrapped
/// fs:read.
#[test]
fn inline_require_fs_dot_promises_read_lowers_bd_1xl17_c() {
    let ops = lower_script_source_ops(
        "require('fs').promises.readFile('out.txt');\n",
        "inline_require_fs_dot_promises_read.js",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "require('fs').promises.readFile must lower to an fs:read host effect"
    );
    assert!(
        ops_have_hostcall(&ops, "promise:resolve"),
        "require('fs').promises.readFile must wrap its result in promise:resolve"
    );
}

/// bd-1xl17.c (sub-object inline write): `require('fs').promises.writeFile(path,
/// data)` lowers to a promise-wrapped fs:write.
#[test]
fn inline_require_fs_dot_promises_write_lowers_bd_1xl17_c() {
    let ops = lower_script_source_ops(
        "require('fs').promises.writeFile('out.txt', 'bytes');\n",
        "inline_require_fs_dot_promises_write.js",
    );
    assert!(ops_have_hostcall(&ops, "fs:write"));
    assert!(ops_have_hostcall(&ops, "promise:resolve"));
}

/// bd-1xl17.c (sub-object binding): `const fsp = require('fs').promises;
/// fsp.readFile(path)` — `fsp` aliases the promises sub-object — lowers to a
/// promise-wrapped fs:read (the `require('fs').promises` analogue of the
/// `const fsp = require('fs/promises')` binding form).
#[test]
fn cjs_require_fs_dot_promises_binding_lowers_bd_1xl17_c() {
    let ops = lower_script_source_ops(
        "const fsp = require('fs').promises;\n\
         fsp.readFile('out.txt');\n",
        "cjs_require_fs_dot_promises_binding.js",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "fsp.readFile (fsp = require('fs').promises) must lower to an fs:read host effect"
    );
    assert!(ops_have_hostcall(&ops, "promise:resolve"));
}

/// bd-1xl17.c (sub-object destructure): `const { promises } = require('fs');
/// promises.readFile(path)` — destructure the promises sub-object off the
/// synchronous fs module — lowers to a promise-wrapped fs:read.
#[test]
fn cjs_destructured_promises_off_fs_lowers_bd_1xl17_c() {
    let ops = lower_script_source_ops(
        "const { promises } = require('fs');\n\
         promises.readFile('out.txt');\n",
        "cjs_destructured_promises_off_fs.js",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "promises destructured off require('fs'): promises.readFile must lower to fs:read"
    );
    assert!(ops_have_hostcall(&ops, "promise:resolve"));
}

/// bd-1xl17.c fail-closed: a `require('fs').promises` binding used only as an
/// UNrecognized method (`fsp.stat`) is NOT confirmed, so it is not elided and
/// the inner `require('fs')` keeps hitting the ambient-authority denial
/// (lowering rejects). Preserves the require-rejection contract without
/// widening authority.
#[test]
fn unused_require_fs_dot_promises_binding_is_not_recognized_bd_1xl17_c() {
    let tree = crate::parser_api_stability::parse_script(
        "const fsp = require('fs').promises;\n\
         fsp.stat('out.txt');\n",
    )
    .expect("parse script");
    let ir0 = Ir0Module::from_syntax_tree(tree, "cjs_require_fs_dot_promises_unused.js");
    assert!(
        lower_ir0_to_ir1(&ir0).is_err(),
        "an unconfirmed require('fs').promises binding must keep the ambient-authority denial"
    );
}

/// bd-1xl17.c (ESM namespace): `import * as fsp from 'node:fs/promises';
/// fsp.readFile(path)` lowers to a promise-wrapped fs:read and elides the
/// fs/promises module load (the namespace analogue of the require-binding form).
#[test]
fn esm_namespace_fs_promises_lowers_to_promise_wrapped_hostcall_bd_1xl17_c() {
    let ops = lower_esm_source_ops(
        "import * as fsp from 'node:fs/promises';\n\
         fsp.readFile('out.txt');\n",
        "esm_namespace_fs_promises.mjs",
    );
    assert!(
        ops_have_hostcall(&ops, "fs:read"),
        "namespace fs/promises readFile must lower to an fs:read host effect"
    );
    assert!(
        ops_have_hostcall(&ops, "promise:resolve"),
        "namespace fs/promises readFile must wrap its result in promise:resolve"
    );
    assert!(
        !ops_have_fs_promises_import_module(&ops),
        "a confirmed fs/promises namespace import must elide the module load"
    );
}

/// bd-1xl17.c (ESM default): `import fsp from 'node:fs/promises';
/// fsp.writeFile(path, data)` lowers to a promise-wrapped fs:write and elides
/// both the module load and the `default` extraction.
#[test]
fn esm_default_fs_promises_lowers_to_promise_wrapped_hostcall_bd_1xl17_c() {
    let ops = lower_esm_source_ops(
        "import fsp from 'fs/promises';\n\
         fsp.writeFile('out.txt', 'bytes');\n",
        "esm_default_fs_promises.mjs",
    );
    assert!(ops_have_hostcall(&ops, "fs:write"));
    assert!(
        ops_have_hostcall(&ops, "promise:resolve"),
        "default fs/promises writeFile must wrap its result in promise:resolve"
    );
    assert!(
        !ops_have_fs_promises_import_module(&ops),
        "a confirmed fs/promises default import must elide the module load"
    );
}

/// bd-1xl17.c fail-closed: a bare/UNUSED fs/promises namespace import is NOT
/// recognized — the module load is preserved and no fs HostCall is emitted.
#[test]
fn unused_fs_promises_namespace_import_is_not_recognized_bd_1xl17_c() {
    let ops = lower_esm_source_ops(
        "import * as fsp from 'node:fs/promises';\n",
        "esm_namespace_fs_promises_unused.mjs",
    );
    assert!(
        ops_have_fs_promises_import_module(&ops),
        "an unused fs/promises namespace import must keep its module load"
    );
    assert!(!ops_have_hostcall(&ops, "fs:read"));
}

#[test]
fn lower_module_with_default_export() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Const,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("__default_export_0".to_string()),
                    initializer: Some(Expression::NumericLiteral(7)),
                    span: span(),
                }],
                span: span(),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::Default(Expression::NumericLiteral(42)),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "default_export.mjs");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_export = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "default"));
    assert!(has_export);
}

#[test]
fn lower_module_with_named_export() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Const,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("foo".to_string()),
                    initializer: Some(Expression::NumericLiteral(1)),
                    span: span(),
                }],
                span: span(),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("{ foo as published }".into()),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "named_export.mjs");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_export = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "published"));
    assert!(has_export);
}

#[test]
fn lower_module_with_reexport_named_clause() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause("{ foo as bar } from \"./dep.js\"".into()),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "named_reexport.mjs");
    let result = lower_ir0_to_ir1(&ir0).expect("re-export should lower");

    let has_import =
        result.module.ops.iter().any(
            |op| matches!(op, Ir1Op::ImportModule { specifier, .. } if specifier == "./dep.js"),
        );
    assert!(has_import);
    let has_export = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "bar"));
    assert!(has_export);
}

#[test]
fn lower_module_with_named_export_unknown_binding() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause("{ bar }".into()),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "named_unknown.mjs");
    let err = lower_ir0_to_ir1(&ir0).expect_err("undeclared export should fail");
    assert!(matches!(
        err,
        LoweringPipelineError::SemanticViolation(SemanticError {
            code: SemanticErrorCode::UndeclaredExportBinding,
            ..
        })
    ));
}

#[test]
fn lower_module_with_named_export_before_declaration() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("{ foo }".into()),
                span: span(),
            }),
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Const,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("foo".to_string()),
                    initializer: Some(Expression::NumericLiteral(3)),
                    span: span(),
                }],
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "named_export_before_decl.mjs");
    let result = lower_ir0_to_ir1(&ir0).expect("forward export should lower");

    let has_export = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "foo"));
    assert!(has_export);
}

#[test]
fn lower_switch_discriminant_internal_binding_avoids_user_name_collision() {
    let ir0 = stmt_ir0(vec![
        Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Let,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier("__franken_switch_discriminant_1".to_string()),
                initializer: Some(Expression::NumericLiteral(0)),
                span: span(),
            }],
            span: span(),
        }),
        Statement::Switch(SwitchStatement {
            discriminant: Expression::Identifier("x".into()),
            cases: vec![SwitchCase {
                test: Some(Expression::NumericLiteral(1)),
                consequent: vec![Statement::Break(BreakStatement {
                    label: None,
                    span: span(),
                })],
                span: span(),
            }],
            span: span(),
        }),
    ]);
    let result = lower_ir0_to_ir1(&ir0).expect("internal switch temp should stay hidden");
    assert!(
        result
            .module
            .scopes
            .first()
            .expect("root scope")
            .bindings
            .iter()
            .any(|binding| binding.name == "__franken_switch_discriminant_1")
    );
}

// -- Module lowering with await --

#[test]
fn lower_await_expression() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Await(Box::new(Expression::Identifier("promise".to_string()))),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "await.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let has_await = result
        .module
        .ops
        .iter()
        .any(|op| matches!(op, Ir1Op::Await));
    assert!(has_await);
}

/// `var counter;` declares (hoists) the binding but stores nothing: the
/// hoisted binding already holds undefined and a redeclaration keeps the
/// value (ES2020 13.3.2.4). This test asserted the old lowering, which
/// stored undefined and so reset `n = 4; var n;`.
#[test]
fn lower_var_declaration_without_initializer_keeps_the_binding() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Var,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier("counter".to_string()),
                initializer: None,
                span: span(),
            }],
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "var_undefined.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let counter_binding = result.module.scopes[0]
        .bindings
        .iter()
        .find(|binding| binding.name == "counter")
        .expect("counter binding must exist");
    assert_eq!(counter_binding.kind, BindingKind::Var);
    assert!(!result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::StoreBinding { binding_id } if *binding_id == counter_binding.binding_id
    )));
}

#[test]
fn lower_var_declaration_hoists_bindings_before_initializers() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Var,
            declarations: vec![
                VariableDeclarator {
                    pattern: BindingPattern::Identifier("y".to_string()),
                    initializer: Some(Expression::Identifier("x".to_string())),
                    span: span(),
                },
                VariableDeclarator {
                    pattern: BindingPattern::Identifier("x".to_string()),
                    initializer: Some(Expression::NumericLiteral(1)),
                    span: span(),
                },
            ],
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "var_hoist.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let scope = &result.module.scopes[0];
    let y_binding = scope
        .bindings
        .iter()
        .find(|binding| binding.name == "y")
        .expect("y binding must exist");
    let x_binding = scope
        .bindings
        .iter()
        .find(|binding| binding.name == "x")
        .expect("x binding must exist");
    assert_eq!(y_binding.kind, BindingKind::Var);
    assert_eq!(x_binding.kind, BindingKind::Var);

    assert!(matches!(
        result.module.ops.as_slice(),
        [
            Ir1Op::LoadBinding {
                binding_id: load_x_binding_id
            },
            Ir1Op::StoreBinding {
                binding_id: store_y_binding_id
            },
            Ir1Op::Discard,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(1)
            },
            Ir1Op::StoreBinding {
                binding_id: store_x_binding_id
            },
            Ir1Op::Discard,
            Ir1Op::Return
        ] if *load_x_binding_id == x_binding.binding_id
            && *store_y_binding_id == y_binding.binding_id
            && *store_x_binding_id == x_binding.binding_id
    ));
}

#[test]
fn lower_let_declaration_uses_let_binding_kind() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Let,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier("value".to_string()),
                initializer: Some(Expression::NumericLiteral(7)),
                span: span(),
            }],
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "let_binding.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let binding = result.module.scopes[0]
        .bindings
        .iter()
        .find(|binding| binding.name == "value")
        .expect("value binding must exist");
    assert_eq!(binding.kind, BindingKind::Let);
}

#[test]
fn lower_const_declaration_uses_const_binding_kind() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier("answer".to_string()),
                initializer: Some(Expression::NumericLiteral(42)),
                span: span(),
            }],
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "const_binding.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

    let binding = result.module.scopes[0]
        .bindings
        .iter()
        .find(|binding| binding.name == "answer")
        .expect("answer binding must exist");
    assert_eq!(binding.kind, BindingKind::Const);
}

// -- Raw (unrecognised) expressions fail closed --
//
// These two tests used to pin the old lowering: the source text became a
// string literal, called with no arguments when it contained `(`. That
// silently turned unsupported syntax into wrong values (`this.#p` was the
// string "this.#p"). Raw now lowers to a thrown SyntaxError and never to a
// call or a value derived from source text.

fn assert_raw_lowers_to_syntax_error_throw(raw: &str) {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Raw(raw.to_string()),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "raw.js");
    let result = lower_ir0_to_ir1(&ir0).expect("should succeed");
    let ops = &result.module.ops;

    assert!(
        !ops.iter().any(|op| matches!(op, Ir1Op::Call { .. })),
        "raw `{raw}` must not be called"
    );
    assert!(
        !ops.iter().any(|op| matches!(
            op,
            Ir1Op::LoadLiteral { value: Ir1Literal::String(text) } if *text == raw
        )),
        "raw `{raw}` must not become a value"
    );
    let throw_at = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::Throw))
        .expect("raw expression must throw");
    assert!(
        matches!(
            &ops[throw_at - 1],
            Ir1Op::HostCall { capability, arg_count: 1 } if capability == "builtin:SyntaxError"
        ),
        "the thrown value must be a SyntaxError"
    );
    assert!(matches!(
        &ops[throw_at - 2],
        Ir1Op::LoadLiteral { value: Ir1Literal::String(text) }
            if *text == format!("unsupported expression syntax: {raw}").as_str()
    ));
}

#[test]
fn raw_expression_with_call_text_throws_instead_of_calling() {
    assert_raw_lowers_to_syntax_error_throw("console.log(42)");
}

#[test]
fn raw_expression_throws_instead_of_yielding_its_source_text() {
    assert_raw_lowers_to_syntax_error_throw("console");
}

fn raw_fail_closed_eval(source: &str) -> String {
    let mut engine = crate::HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn unrecognised_expression_throws_a_catchable_syntax_error() {
    // `a::b` (the bind-operator proposal) is not JavaScript, and the
    // parser leaves it as `Expression::Raw`. Such text used to evaluate
    // to the string "a::b"; it must throw when it runs. Node rejects the
    // program before running it, so this pins the refusal, not parity.
    // (The example was `this.#p` until private names were implemented.)
    assert_eq!(
        raw_fail_closed_eval(
            "class A { get p() { return a::b; } } \
             let r; try { r = new A().p; } catch (e) { r = e.name + ':' + e.message; } r"
        ),
        "SyntaxError:unsupported expression syntax: a::b"
    );
}

#[test]
fn unevaluated_unsupported_expression_does_not_fail_the_program() {
    assert_eq!(
        raw_fail_closed_eval("function never() { return a::b; } 'ok'"),
        "ok"
    );
}

// -- Full pipeline with imports/exports --

#[test]
fn full_pipeline_module_with_import_and_export() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            Statement::Import(ImportDeclaration {
                import_attributes: Default::default(),
                clause: ImportClause::Default {
                    local: "_".to_string(),
                },
                source: "lodash".into(),
                binding: Some("_".to_string()),
                span: span(),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::Default(Expression::Identifier("_".to_string())),
                span: span(),
            }),
        ],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "full_pipeline.mjs");
    let context = LoweringContext::new("trace-fp", "decision-fp", "policy-fp");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("full pipeline should succeed");

    assert_eq!(output.witnesses.len(), 3);
    assert_eq!(output.isomorphism_ledger.len(), 3);
    assert_eq!(output.events.len(), 4);
    assert!(
        output
            .events
            .iter()
            .all(|e| e.outcome == "pass" && e.component == "lowering_pipeline")
    );
    assert!(matches!(
        output.ir3.instructions.last(),
        Some(Ir3Instruction::Halt)
    ));
}

// -- Pipeline with string literal --

#[test]
fn full_pipeline_string_literal() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::StringLiteral("hello world".into()),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "string_lit.js");
    let context = LoweringContext::new("trace-sl", "decision-sl", "policy-sl");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

    assert!(
        output
            .ir3
            .constant_pool
            .iter()
            .any(|value| value == "hello world")
    );
}

#[test]
fn full_pipeline_preserves_exact_string_literal_units_bd_vltnh() {
    let exact = JsString::from_code_units(&[0x0061, 0xD800, 0x0062]);
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::StringLiteral(exact.clone()),
            span: span(),
        })],
        span: span(),
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "exact-string-literal.js");
    let context = LoweringContext::new("trace-exact", "decision-exact", "policy-exact");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("exact literal should lower");

    assert!(output.ir3.constant_pool.contains(&exact));
}

// -- scope_binding_ids_are_unique --

#[test]
fn scope_binding_ids_unique_empty() {
    assert!(scope_binding_ids_are_unique(&[]));
}

#[test]
fn scope_binding_ids_unique_single_scope() {
    let scope = ScopeNode {
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
                kind: BindingKind::Let,
            },
        ],
    };
    assert!(scope_binding_ids_are_unique(&[scope]));
}

#[test]
fn scope_binding_ids_duplicate_detected() {
    let scope = ScopeNode {
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
                binding_id: 0, // duplicate
                scope: ScopeId { depth: 0, index: 0 },
                kind: BindingKind::Let,
            },
        ],
    };
    assert!(!scope_binding_ids_are_unique(&[scope]));
}

// -- infer_data_label_for_op --

/// bd-9vouw.19: a string literal's text is not a source label, so
/// literals naming secrets, tokens, keys, passwords or credentials are
/// Public like any other literal (this test pinned the removed heuristic,
/// which labelled all five Secret). Only a legacy hostcall marker's
/// payload still models a labeled argument.
#[test]
fn infer_data_label_keyword_literals_are_public_bd_9vouw_19() {
    let labels = BTreeMap::new();
    for text in [
        "my_secret_key",
        "AUTH_TOKEN",
        "my_api_key_here",
        "user_password",
        "credential_store",
        "Unexpected token",
    ] {
        let label = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String(text.into()),
            },
            &labels,
            Label::Secret,
        );
        assert_eq!(label, Label::Public, "{text}");
    }
    // The legacy `hostcall<"cap"> payload` marker keeps modeling a secret
    // argument through its payload text.
    for (marker, expected) in [
        ("hostcall<\"declassify.audit\"> secret_token", Label::Secret),
        ("hostcall<\"declassify.audit\"> audit-record", Label::Public),
    ] {
        let label = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String(marker.into()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(label, expected, "{marker}");
    }
}

#[test]
fn infer_data_label_public_string() {
    let labels = BTreeMap::new();
    let public = infer_data_label_for_op(
        &Ir1Op::LoadLiteral {
            value: Ir1Literal::String("hello world".into()),
        },
        &labels,
        Label::Public,
    );
    assert_eq!(public, Label::Public);
}

#[test]
fn infer_data_label_numeric_literal() {
    let labels = BTreeMap::new();
    let label = infer_data_label_for_op(
        &Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(42),
        },
        &labels,
        Label::Secret,
    );
    assert_eq!(label, Label::Public);
}

#[test]
fn infer_data_label_load_binding_known() {
    let mut labels = BTreeMap::new();
    labels.insert(5u32, Label::Confidential);
    let label = infer_data_label_for_op(
        &Ir1Op::LoadBinding { binding_id: 5 },
        &labels,
        Label::Public,
    );
    assert_eq!(label, Label::Confidential);
}

#[test]
fn infer_data_label_load_binding_unknown() {
    let labels = BTreeMap::new();
    let label = infer_data_label_for_op(
        &Ir1Op::LoadBinding { binding_id: 99 },
        &labels,
        Label::Public,
    );
    assert_eq!(label, Label::Internal);
}

#[test]
fn infer_data_label_import_is_internal() {
    let labels = BTreeMap::new();
    let label = infer_data_label_for_op(
        &Ir1Op::ImportModule {
            import_attributes: Default::default(),
            specifier: "lodash".into(),
        },
        &labels,
        Label::Public,
    );
    assert_eq!(label, Label::Internal);
}

#[test]
fn infer_data_label_return_uses_last_label() {
    let labels = BTreeMap::new();
    let label = infer_data_label_for_op(&Ir1Op::Return, &labels, Label::Confidential);
    assert_eq!(label, Label::Confidential);
}

// -- success_event / failure_event --

#[test]
fn success_event_fields() {
    let ctx = LoweringContext::new("t", "d", "p");
    let event = success_event(&ctx, "test_pass");
    assert_eq!(event.trace_id, "t");
    assert_eq!(event.decision_id, "d");
    assert_eq!(event.policy_id, "p");
    assert_eq!(event.component, "lowering_pipeline");
    assert_eq!(event.event, "test_pass");
    assert_eq!(event.outcome, "pass");
    assert!(event.error_code.is_none());
}

#[test]
fn failure_event_fields() {
    let ctx = LoweringContext::new("t", "d", "p");
    let event = failure_event(&ctx, "test_fail", "FE-LOWER-9999");
    assert_eq!(event.outcome, "fail");
    assert_eq!(event.error_code, Some("FE-LOWER-9999".to_string()));
}

// -- infer_sink_clearance --

#[test]
fn infer_sink_clearance_network_effect() {
    let label = infer_sink_clearance(&EffectBoundary::NetworkEffect, None, &Label::Secret);
    assert_eq!(label, Label::Public);
}

#[test]
fn infer_sink_clearance_fs_effect() {
    let label = infer_sink_clearance(&EffectBoundary::FsEffect, None, &Label::Secret);
    assert_eq!(label, Label::Internal);
}

#[test]
fn infer_sink_clearance_read_effect() {
    let label = infer_sink_clearance(&EffectBoundary::ReadEffect, None, &Label::Secret);
    assert_eq!(label, Label::Internal);
}

#[test]
fn infer_sink_clearance_write_effect() {
    let label = infer_sink_clearance(&EffectBoundary::WriteEffect, None, &Label::Secret);
    assert_eq!(label, Label::Internal);
}

#[test]
fn infer_sink_clearance_hostcall_effect() {
    let label = infer_sink_clearance(&EffectBoundary::HostcallEffect, None, &Label::Secret);
    assert_eq!(label, Label::Internal);
}

#[test]
fn infer_sink_clearance_pure_uses_data_label() {
    let label = infer_sink_clearance(&EffectBoundary::Pure, None, &Label::Secret);
    assert_eq!(label, Label::Secret);
}

#[test]
fn infer_sink_clearance_with_capability_overrides() {
    let cap = CapabilityTag("net.write".to_string());
    let label = infer_sink_clearance(&EffectBoundary::Pure, Some(&cap), &Label::Secret);
    assert_eq!(label, Label::Public);
}

#[test]
fn hermetic_net_builtin_sink_is_not_public_egress_bd_bscab_bd_oardi() {
    for capability in [
        "builtin:NetCreateServer",
        "builtin:NetConnect",
        "builtin:NetSocket",
    ] {
        let capability = CapabilityTag(capability.to_string());
        let clearance = infer_sink_clearance(
            &EffectBoundary::HostcallEffect,
            Some(&capability),
            &Label::TopSecret,
        );
        assert_eq!(clearance, Label::TopSecret);
    }

    for host_egress in ["net.write", "net:request", "net:client_request"] {
        let host_egress = CapabilityTag(host_egress.to_string());
        assert_eq!(
            infer_sink_clearance(
                &EffectBoundary::NetworkEffect,
                Some(&host_egress),
                &Label::TopSecret,
            ),
            Label::Public,
            "real host-network authority must remain a public sink"
        );
    }
}

#[test]
fn recognized_forward_capture_uses_internal_fixed_point_seed_bd_bscab_bd_oardi() {
    let labels = BTreeMap::new();
    let body = vec![
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Return,
    ];
    assert_eq!(
        infer_function_capture_label(
            &[capture_cell_name("server", 73)],
            &[9],
            &body,
            &labels,
            HostIoExceptionProvenance::Unknown,
            0,
        ),
        Label::Internal,
        "a recognized capture preceding its store must converge from the runtime floor"
    );
    assert_eq!(
        infer_function_capture_label(
            &["unrecognized-capture".to_string()],
            &[9],
            &body,
            &labels,
            HostIoExceptionProvenance::Unknown,
            0,
        ),
        Label::TopSecret,
        "an unauthenticated capture identity must still fail high"
    );
}

// -- alloc_register --

#[test]
fn alloc_register_increments() {
    let mut cursor: Reg = 0;
    let r0 = alloc_register(&mut cursor);
    let r1 = alloc_register(&mut cursor);
    let r2 = alloc_register(&mut cursor);
    assert_eq!(r0, 0);
    assert_eq!(r1, 1);
    assert_eq!(r2, 2);
    assert_eq!(cursor, 3);
}

// -- hash_string --

#[test]
fn hash_string_format() {
    let hash = ContentHash::compute(b"test");
    let s = hash_string(&hash);
    assert!(s.starts_with("sha256:"));
    assert_eq!(s.len(), 7 + 64); // "sha256:" + 64 hex chars
}

/// bd-9vouw.382: a pass's output hash string reads back as the hash, and
/// nothing else does.
#[test]
fn hash_string_reads_back_as_its_hash_bd_9vouw_382() {
    let hash = ContentHash::compute(b"module");
    assert_eq!(
        content_hash_from_hash_string(&hash_string(&hash)),
        Some(hash)
    );
    let hex = hex::encode(hash.as_bytes());
    for text in [
        hex.clone(),
        format!("sha1:{hex}"),
        format!("sha256:{}", &hex[..62]),
        format!("sha256:{hex}00"),
        format!("sha256:{}zz", &hex[..62]),
    ] {
        assert_eq!(content_hash_from_hash_string(&text), None, "{text}");
    }
}

// -- ensure_checks_pass --

#[test]
fn ensure_checks_pass_all_pass() {
    let checks = vec![
        InvariantCheck {
            name: "a".to_string(),
            passed: true,
            detail: "ok".to_string(),
        },
        InvariantCheck {
            name: "b".to_string(),
            passed: true,
            detail: "ok".to_string(),
        },
    ];
    assert!(ensure_checks_pass(&checks, "should not fail").is_ok());
}

#[test]
fn ensure_checks_pass_one_fails() {
    let checks = vec![
        InvariantCheck {
            name: "a".to_string(),
            passed: true,
            detail: "ok".to_string(),
        },
        InvariantCheck {
            name: "b".to_string(),
            passed: false,
            detail: "bad".to_string(),
        },
    ];
    let err = ensure_checks_pass(&checks, "test failure").unwrap_err();
    assert!(matches!(
        err,
        LoweringPipelineError::InvariantViolation {
            detail: "test failure"
        }
    ));
}

// -- Enrichment: PearlTower 2026-02-26 --

#[test]
fn lowering_pipeline_error_display_distinct() {
    use crate::ifc_artifacts::Label;
    use crate::ir_contract::IrLevel;
    let variants: Vec<LoweringPipelineError> = vec![
        LoweringPipelineError::EmptyIr0Body,
        LoweringPipelineError::IrContractValidation {
            code: "E001".into(),
            level: IrLevel::Ir1,
            message: "msg".into(),
        },
        LoweringPipelineError::InvariantViolation { detail: "bad" },
        LoweringPipelineError::FlowLatticeFailure {
            detail: "fail".into(),
        },
        LoweringPipelineError::UnauthorizedFlow {
            op_index: 0,
            source_label: Label::Public,
            sink_clearance: Label::Public,
            detail: "x".into(),
        },
        LoweringPipelineError::UnsupportedSyntax(Box::new(UnsupportedSyntaxDiagnostic::from_site(
            ParserGapSiteId::TemplateLiteralRawPlaceholder,
            "ir0",
            None,
        ))),
    ];
    let set: std::collections::BTreeSet<String> = variants.iter().map(|e| format!("{e}")).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn lowering_pipeline_error_is_std_error() {
    let e = LoweringPipelineError::EmptyIr0Body;
    let _: &dyn std::error::Error = &e;
}

#[test]
fn ir2_flow_proof_artifact_serde_roundtrip() {
    let artifact = Ir2FlowProofArtifact {
        schema_version: "1.0".into(),
        artifact_id: "art-1".into(),
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        module_id: "m-1".into(),
        proved_flows: vec![],
        denied_flows: vec![],
        required_declassifications: vec![],
        runtime_checkpoints: vec![],
    };
    let json = serde_json::to_string(&artifact).expect("serialize derived Serialize");
    let back: Ir2FlowProofArtifact =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(artifact, back);
}

#[test]
fn lowering_pipeline_output_serde_roundtrip() {
    let ctx = LoweringContext::new("t", "d", "p");
    let ir0 = script_ir0();
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("operation should succeed for valid inputs");
    let json = serde_json::to_string(&output).expect("serialize derived Serialize");
    let back: LoweringPipelineOutput =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(output, back);
}

#[test]
fn lowering_pass_result_serde_roundtrip() {
    let result = LoweringPassResult {
        module: "test_module".to_string(),
        witness: PassWitness {
            pass_id: "p1".into(),
            input_hash: "ih".into(),
            output_hash: "oh".into(),
            rollback_token: "rt".into(),
            invariant_checks: vec![InvariantCheck {
                name: "check1".into(),
                passed: true,
                detail: "ok".into(),
            }],
        },
        ledger_entry: IsomorphismLedgerEntry {
            pass_id: "p1".into(),
            input_hash: "ih".into(),
            output_hash: "oh".into(),
            input_op_count: 5,
            output_op_count: 4,
        },
    };
    let json = serde_json::to_string(&result).expect("serialize derived Serialize");
    let back: LoweringPassResult<String> =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(result, back);
}

// ================================================================
// Expression lowering enrichment
// ================================================================

fn expr_ir0(expression: Expression) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression,
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "expr_fixture.js")
}

fn stmt_ir0(stmts: Vec<Statement>) -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: stmts,
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "stmt_fixture.js")
}

#[test]
fn lower_binary_expression() {
    let ir0 = expr_ir0(Expression::Binary {
        operator: BinaryOperator::Add,
        left: Box::new(Expression::NumericLiteral(1)),
        right: Box::new(Expression::NumericLiteral(2)),
    });
    let result = lower_ir0_to_ir1(&ir0).expect("binary should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::BinaryOp {
            operator: BinaryOperator::Add
        }
    )));
}

#[test]
fn lower_unary_expression() {
    let ir0 = expr_ir0(Expression::Unary {
        operator: UnaryOperator::Typeof,
        argument: Box::new(Expression::Identifier("x".into())),
    });
    let result = lower_ir0_to_ir1(&ir0).expect("unary should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::UnaryOp {
            operator: UnaryOperator::Typeof
        }
    )));
}

#[test]
fn lower_assignment_to_unresolved_identifier_uses_sloppy_put_bd_0k19b() {
    let ir0 = expr_ir0(Expression::Assignment {
        operator: AssignmentOperator::Assign,
        left: Box::new(Expression::Identifier("x".into())),
        right: Box::new(Expression::NumericLiteral(42)),
        assignment_strictness: AssignmentStrictness::Sloppy,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("assignment should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ResolveNameStatus { name, .. } if name == "x"))
    );
    assert!(result.module.ops.iter().any(
        |op| matches!(op, Ir1Op::PutNameWithStatus { name, strict: false, .. } if name == "x")
    ));
}

#[test]
fn unresolved_assignment_rejects_legacy_unknown_strictness_bd_0k19b() {
    let ir0 = expr_ir0(Expression::Assignment {
        operator: AssignmentOperator::Assign,
        left: Box::new(Expression::Identifier("legacy_missing".into())),
        right: Box::new(Expression::NumericLiteral(1)),
        assignment_strictness: AssignmentStrictness::Unknown,
    });
    let error = lower_ir0_to_ir1(&ir0)
        .expect_err("legacy unresolved target must not guess strictness semantics");
    assert!(matches!(
        error,
        LoweringPipelineError::InvariantViolation { detail }
            if detail.contains("unknown strictness provenance")
    ));
}

#[test]
fn lower_assignment_to_member_emits_set_property() {
    let ir0 = expr_ir0(Expression::Assignment {
        operator: AssignmentOperator::Assign,
        left: Box::new(Expression::Member {
            object: Box::new(Expression::Identifier("obj".into())),
            property: Box::new(Expression::Identifier("prop".into())),
            computed: false,
            span: None,
        }),
        right: Box::new(Expression::NumericLiteral(1)),
        assignment_strictness: AssignmentStrictness::Sloppy,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("member assignment should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static(key),
            strict: false,
        } if key == "prop"
    )));
}

#[test]
fn member_assignment_strictness_reaches_set_property_bd_9vouw_146() {
    // A strict write, and a legacy AST of unknown strictness, keep the
    // throwing SetProperty; only a known-sloppy write is lenient.
    for (assignment_strictness, strict) in [
        (AssignmentStrictness::Strict, true),
        (AssignmentStrictness::Unknown, true),
        (AssignmentStrictness::Sloppy, false),
    ] {
        let ir0 = expr_ir0(Expression::Assignment {
            operator: AssignmentOperator::AddAssign,
            left: Box::new(Expression::Member {
                object: Box::new(Expression::Identifier("obj".into())),
                property: Box::new(Expression::Identifier("prop".into())),
                computed: false,
                span: None,
            }),
            right: Box::new(Expression::NumericLiteral(1)),
            assignment_strictness,
        });
        let result = lower_ir0_to_ir1(&ir0).expect("member assignment should lower");
        let writes: Vec<bool> = result
            .module
            .ops
            .iter()
            .filter_map(|op| match op {
                Ir1Op::SetProperty { strict, .. } => Some(*strict),
                _ => None,
            })
            .collect();
        assert_eq!(writes, vec![strict], "{assignment_strictness:?}");
    }
}

#[test]
fn lower_conditional_expression() {
    let ir0 = expr_ir0(Expression::Conditional {
        test: Box::new(Expression::BooleanLiteral(true)),
        consequent: Box::new(Expression::NumericLiteral(1)),
        alternate: Box::new(Expression::NumericLiteral(2)),
    });
    let result = lower_ir0_to_ir1(&ir0).expect("conditional should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::JumpIfFalsy { .. }))
    );
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Jump { .. }))
    );
    // The current lowering emits additional cleanup Pops for branch
    // balancing alongside the test-value and statement-result Pops.
    let pop_count = result
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::Pop))
        .count();
    assert_eq!(
        pop_count, 4,
        "conditional lowering should clean up both branches"
    );
    let label_count = result
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::Label { .. }))
        .count();
    assert_eq!(label_count, 2);
    let lit_count = result
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::LoadLiteral { .. }))
        .count();
    assert!(lit_count >= 3); // true, 1, 2
}

#[test]
fn lower_call_expression() {
    let ir0 = expr_ir0(Expression::Call {
        callee: Box::new(Expression::Identifier("fn".into())),
        arguments: vec![
            Expression::NumericLiteral(1),
            Expression::StringLiteral("a".into()),
        ],
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("call should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Call { arg_count: 2 }))
    );
}

#[test]
fn lower_member_expression() {
    let ir0 = expr_ir0(Expression::Member {
        object: Box::new(Expression::Identifier("obj".into())),
        property: Box::new(Expression::Identifier("key".into())),
        computed: false,
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("member should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Static(key)
        } if key == "key"
    )));
}

#[test]
fn lower_static_member_preserves_exact_property_key_units_bd_b12xs_6() {
    let exact = JsString::from_code_units(&[0xD800]);
    let ir0 = expr_ir0(Expression::Member {
        object: Box::new(Expression::Identifier("obj".into())),
        property: Box::new(Expression::StringLiteral(exact.clone())),
        computed: false,
        span: None,
    });

    let ir1 = lower_ir0_to_ir1(&ir0).expect("exact static member key should lower");
    assert!(ir1.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Static(key)
        } if key == &exact
    )));

    let context = LoweringContext::new(
        "trace-exact-static-key",
        "decision-exact-static-key",
        "policy-exact-static-key",
    );
    let output = lower_ir0_to_ir3(&ir0, &context)
        .expect("exact static member key should reach the IR3 constant pool");
    assert!(output.ir3.constant_pool.contains(&exact));
}

#[test]
fn lower_computed_member_expression_uses_dynamic_key() {
    let ir0 = expr_ir0(Expression::Member {
        object: Box::new(Expression::Identifier("obj".into())),
        property: Box::new(Expression::Identifier("key".into())),
        computed: true,
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("computed member should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Dynamic
        }
    )));
}

#[test]
fn lower_computed_member_preserves_exact_dynamic_literal_bd_b12xs_6() {
    let exact = JsString::from_code_units(&[0xD801]);
    let ir0 = expr_ir0(Expression::Member {
        object: Box::new(Expression::Identifier("obj".into())),
        property: Box::new(Expression::StringLiteral(exact.clone())),
        computed: true,
        span: None,
    });

    let result = lower_ir0_to_ir1(&ir0).expect("exact computed member key should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String(value)
        } if value == &exact
    )));
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Dynamic
        }
    )));
}

#[test]
fn lower_optional_member_expression_uses_nullish_short_circuit() {
    let ir0 = expr_ir0(Expression::OptionalMember {
        object: Box::new(Expression::Identifier("obj".into())),
        property: Box::new(Expression::Identifier("key".into())),
        computed: false,
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("optional member should lower");

    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::JumpIfNullish { .. })),
        "optional member should branch on nullish bases"
    );
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Static(key)
        } if key == "key"
    )));
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined
        }
    )));
}

#[test]
fn lower_optional_member_base_expression_is_evaluated_once() {
    let ir0 = expr_ir0(Expression::OptionalMember {
        object: Box::new(Expression::Call {
            callee: Box::new(Expression::Identifier("make_obj".into())),
            arguments: vec![],
            span: None,
        }),
        property: Box::new(Expression::Identifier("value".into())),
        computed: false,
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("optional member should lower");

    let call_count = result
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::Call { arg_count: 0 }))
        .count();
    assert_eq!(
        call_count, 1,
        "optional member lowering must evaluate the base expression exactly once"
    );
}

#[test]
fn lower_optional_computed_member_checks_nullish_before_key_evaluation() {
    let ir0 = expr_ir0(Expression::OptionalMember {
        object: Box::new(Expression::Identifier("obj".into())),
        property: Box::new(Expression::NumericLiteral(7)),
        computed: true,
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("computed optional member should lower");

    let jump_index = result
        .module
        .ops
        .iter()
        .position(|op| matches!(op, Ir1Op::JumpIfNullish { .. }))
        .expect("optional member should emit JumpIfNullish");
    let key_eval_index = result
        .module
        .ops
        .iter()
        .position(|op| {
            matches!(
                op,
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Integer(7)
                }
            )
        })
        .expect("computed key should still be lowered");
    let get_property_index = result
        .module
        .ops
        .iter()
        .position(|op| {
            matches!(
                op,
                Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Dynamic
                }
            )
        })
        .expect("computed optional member should use dynamic key access");

    assert!(
        jump_index < key_eval_index,
        "computed key evaluation must happen after the nullish short-circuit guard"
    );
    assert!(
        key_eval_index < get_property_index,
        "computed key must still feed the property read on the non-nullish path"
    );
}

#[test]
fn lower_nested_optional_member_expression_emits_two_nullish_checks() {
    let ir0 = expr_ir0(Expression::OptionalMember {
        object: Box::new(Expression::OptionalMember {
            object: Box::new(Expression::Identifier("obj".into())),
            property: Box::new(Expression::Identifier("nested".into())),
            computed: false,
            span: None,
        }),
        property: Box::new(Expression::Identifier("value".into())),
        computed: false,
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("nested optional member should lower");

    let jump_count = result
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::JumpIfNullish { .. }))
        .count();
    assert_eq!(
        jump_count, 2,
        "nested optional member should guard each optional segment"
    );
}

#[test]
fn lower_grouped_optional_member_only_guards_the_grouped_segment() {
    let ir0 = expr_ir0(Expression::Member {
        object: Box::new(Expression::OptionalMember {
            object: Box::new(Expression::Identifier("obj".into())),
            property: Box::new(Expression::Identifier("nested".into())),
            computed: false,
            span: None,
        }),
        property: Box::new(Expression::Identifier("value".into())),
        computed: false,
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("grouped optional member should lower");

    let jump_count = result
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::JumpIfNullish { .. }))
        .count();
    assert_eq!(
        jump_count, 1,
        "grouped follow-on member access should not widen the optional short-circuit scope"
    );
    assert_eq!(
        result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::GetProperty { .. }))
            .count(),
        2,
        "grouped optional member lowering should preserve both the inner and follow-on property reads"
    );
}

#[test]
fn lower_this_expression() {
    let ir0 = expr_ir0(Expression::This);
    let result = lower_ir0_to_ir1(&ir0).expect("this should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::LoadThis))
    );
}

#[test]
fn lower_array_literal() {
    let ir0 = expr_ir0(Expression::ArrayLiteral(vec![
        Some(Expression::NumericLiteral(1)),
        None,
        Some(Expression::NumericLiteral(3)),
    ]));
    let result = lower_ir0_to_ir1(&ir0).expect("array should lower");
    // Holes are lowered as LoadLiteral { Undefined }, so count
    // reflects total slots including holes.
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::NewArray { count: 3 }))
    );
}

#[test]
fn lower_object_literal() {
    let ir0 = expr_ir0(Expression::ObjectLiteral(vec![ObjectProperty {
        key: Expression::Identifier("a".into()),
        value: Expression::NumericLiteral(1),
        computed: false,
        shorthand: false,
        kind: ObjectPropertyKind::Data,
    }]));
    let result = lower_ir0_to_ir1(&ir0).expect("object should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::NewObject { count: 1 }))
    );
}

#[test]
fn lower_object_literal_accessor_emits_define_accessor() {
    let getter = Expression::Function {
        name: None,
        params: Vec::new(),
        body: BlockStatement {
            body: vec![Statement::Return(ReturnStatement {
                argument: Some(Expression::NumericLiteral(11)),
                span: span(),
            })],
            span: span(),
        },
        is_async: false,
        is_generator: false,
        source_text: None,
        strict: false,
    };
    let ir0 = expr_ir0(Expression::ObjectLiteral(vec![ObjectProperty {
        key: Expression::Identifier("v".into()),
        value: getter,
        computed: false,
        shorthand: false,
        kind: ObjectPropertyKind::Get,
    }]));
    let result = lower_ir0_to_ir1(&ir0).expect("object getter should lower");
    assert!(
        result.module.ops.iter().any(|op| {
            matches!(
                op,
                Ir1Op::DefineAccessor {
                    key: Ir1PropertyKey::Static(key),
                    kind: AccessorKind::Get,
                } if key == "v"
            )
        }),
        "object getter literal must lower to DefineAccessor"
    );
}

#[test]
fn lower_object_literal_method_emits_define_method_bd_gqaa4() {
    let method = Expression::Function {
        name: None,
        params: Vec::new(),
        body: BlockStatement {
            body: vec![Statement::Return(ReturnStatement {
                argument: Some(Expression::NumericLiteral(11)),
                span: span(),
            })],
            span: span(),
        },
        is_async: false,
        is_generator: false,
        source_text: None,
        strict: false,
    };
    let ir0 = expr_ir0(Expression::ObjectLiteral(vec![ObjectProperty {
        key: Expression::Identifier("value".into()),
        value: method,
        computed: false,
        shorthand: false,
        kind: ObjectPropertyKind::Method,
    }]));
    let result = lower_ir0_to_ir1(&ir0).expect("object method should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::NewObject { count: 0 }))
    );
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::DefineMethod {
            key: Ir1PropertyKey::Static(key)
        } if key == "value"
    )));
}

#[test]
fn lower_object_method_super_call_keeps_dynamic_this_bd_gqaa4() {
    let ops = lower_script_source_ops(
        "let owner={value(){return super.value();}};",
        "object_method_super.js",
    );
    let body_ops = ops
        .iter()
        .find_map(|op| match op {
            Ir1Op::CreateFunction { body_ops, .. } => Some(body_ops),
            _ => None,
        })
        .expect("method closure body should be retained in IR1");
    let load_super = body_ops
        .iter()
        .position(|op| matches!(op, Ir1Op::LoadSuper))
        .expect("super lookup base must be loaded");
    let get_property = body_ops
        .iter()
        .position(|op| matches!(op, Ir1Op::GetProperty { .. }))
        .expect("super property must be resolved");
    let load_this = body_ops
        .iter()
        .position(|op| matches!(op, Ir1Op::LoadThis))
        .expect("dynamic receiver must be loaded separately");
    let call_method = body_ops
        .iter()
        .position(|op| matches!(op, Ir1Op::CallMethod { .. }))
        .expect("super property must be invoked as a method");
    assert!(load_super < get_property && get_property < load_this && load_this < call_method);
}

#[test]
fn lower_object_literal_accessor_preserves_exact_static_key_bd_b12xs_6() {
    let exact = JsString::from_code_units(&[0xD800]);
    let getter = Expression::Function {
        name: None,
        params: Vec::new(),
        body: BlockStatement {
            body: vec![Statement::Return(ReturnStatement {
                argument: Some(Expression::NumericLiteral(11)),
                span: span(),
            })],
            span: span(),
        },
        is_async: false,
        is_generator: false,
        source_text: None,
        strict: false,
    };
    let ir0 = expr_ir0(Expression::ObjectLiteral(vec![ObjectProperty {
        key: Expression::StringLiteral(exact.clone()),
        value: getter,
        computed: false,
        shorthand: false,
        kind: ObjectPropertyKind::Get,
    }]));

    let result = lower_ir0_to_ir1(&ir0).expect("exact object accessor key should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::DefineAccessor {
            key: Ir1PropertyKey::Static(key),
            kind: AccessorKind::Get,
        } if key == &exact
    )));
}

#[test]
fn lower_computed_object_accessor_preserves_exact_dynamic_key_bd_b12xs_6() {
    let exact = JsString::from_code_units(&[0xD801]);
    let getter = Expression::Function {
        name: None,
        params: Vec::new(),
        body: BlockStatement {
            body: Vec::new(),
            span: span(),
        },
        is_async: false,
        is_generator: false,
        source_text: None,
        strict: false,
    };
    let ir0 = expr_ir0(Expression::ObjectLiteral(vec![ObjectProperty {
        key: Expression::StringLiteral(exact.clone()),
        value: getter,
        computed: true,
        shorthand: false,
        kind: ObjectPropertyKind::Get,
    }]));

    let result = lower_ir0_to_ir1(&ir0).expect("exact computed accessor key should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String(value)
        } if value == &exact
    )));
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::DefineAccessor {
            key: Ir1PropertyKey::Dynamic,
            kind: AccessorKind::Get,
        }
    )));
}

#[test]
fn lower_arrow_function_expression_body() {
    let ir0 = expr_ir0(Expression::ArrowFunction {
        params: vec![FunctionParam {
            pattern: BindingPattern::Identifier("x".into()),
            span: span(),
        }],
        body: ArrowBody::Expression(Box::new(Expression::Identifier("x".into()))),
        is_async: false,
        source_text: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("arrow should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Return))
    );
}

#[test]
fn lower_arrow_function_block_body() {
    let ir0 = expr_ir0(Expression::ArrowFunction {
        params: vec![],
        body: ArrowBody::Block(BlockStatement {
            body: vec![Statement::Return(ReturnStatement {
                argument: Some(Expression::NumericLiteral(99)),
                span: span(),
            })],
            span: span(),
        }),
        is_async: false,
        source_text: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("arrow block should lower");
    let return_count = result
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::Return))
        .count();
    assert!(return_count >= 1);
}

#[test]
fn lower_arrow_function_block_reuses_outer_label_counter() {
    let ir0 = stmt_ir0(vec![
        Statement::If(IfStatement {
            condition: Expression::BooleanLiteral(true),
            consequent: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })),
            alternate: None,
            span: span(),
        }),
        Statement::Expression(ExpressionStatement {
            expression: Expression::ArrowFunction {
                params: vec![],
                body: ArrowBody::Block(BlockStatement {
                    body: vec![Statement::If(IfStatement {
                        condition: Expression::BooleanLiteral(false),
                        consequent: Box::new(Statement::Return(ReturnStatement {
                            argument: Some(Expression::NumericLiteral(2)),
                            span: span(),
                        })),
                        alternate: None,
                        span: span(),
                    })],
                    span: span(),
                }),
                is_async: false,
                source_text: None,
            },
            span: span(),
        }),
    ]);
    let result = lower_ir0_to_ir1(&ir0).expect("arrow block labels should stay unique");
    let label_ids: Vec<u32> = result
        .module
        .ops
        .iter()
        .filter_map(|op| match op {
            Ir1Op::Label { id } => Some(*id),
            _ => None,
        })
        .collect();
    let unique_label_count = label_ids.iter().copied().collect::<BTreeSet<_>>().len();
    assert_eq!(label_ids.len(), unique_label_count);
}

#[test]
fn lower_arrow_function_template_literal_body_to_ir3() {
    let ir0 = expr_ir0(Expression::ArrowFunction {
        params: vec![FunctionParam {
            pattern: BindingPattern::Identifier("name".into()),
            span: span(),
        }],
        body: ArrowBody::Expression(Box::new(Expression::TemplateLiteral {
            quasis: vec!["Hello, ".into(), "!".into()],
            expressions: vec![Expression::Identifier("name".into())],
        })),
        is_async: false,
        source_text: None,
    });
    let ctx = LoweringContext::new("trace-gap", "decision-gap", "policy-gap");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("arrow template literal should lower to IR3");

    let (function_index, function_desc) = output
        .ir3
        .instructions
        .iter()
        .find_map(|instruction| match instruction {
            Ir3Instruction::CreateArrowClosure { function_index, .. } => output
                .ir3
                .function_table
                .get(function_index.to_owned() as usize)
                .map(|desc| (*function_index, desc)),
            _ => None,
        })
        .expect("arrow function should create a deferred closure body");

    assert_eq!(function_index, 1);
    assert!(
        output.ir3.instructions[function_desc.entry as usize..]
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::TemplateLiteral { .. })),
        "arrow function body should retain TemplateLiteral lowering"
    );
}

#[test]
fn lower_empty_template_literal_to_ir3_loads_empty_string() {
    let ir0 = expr_ir0(Expression::TemplateLiteral {
        quasis: Vec::new(),
        expressions: Vec::new(),
    });
    let ctx = LoweringContext::new("trace-gap", "decision-gap", "policy-gap");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("empty template literal should lower to IR3");

    let empty_pool_index = output
        .ir3
        .constant_pool
        .iter()
        .position(|value| value.is_empty())
        .expect("empty template literal should load an empty string constant");
    let empty_pool_index =
        u32::try_from(empty_pool_index).expect("constant pool index should fit in u32");

    assert!(
        output.ir3.instructions.iter().any(|instruction| {
            matches!(
                instruction,
                Ir3Instruction::LoadStr { pool_index, .. } if *pool_index == empty_pool_index
            )
        }),
        "empty template literal must emit a real empty string load"
    );
    assert!(
        !output.ir3.instructions.iter().any(
            |instruction| matches!(instruction, Ir3Instruction::Move { dst, src } if dst == src),
        ),
        "empty template literal must not lower to a self-move"
    );
}

#[test]
fn lower_arrow_function_empty_template_literal_body_to_ir3_loads_empty_string() {
    let ir0 = expr_ir0(Expression::ArrowFunction {
        params: vec![],
        body: ArrowBody::Expression(Box::new(Expression::TemplateLiteral {
            quasis: Vec::new(),
            expressions: Vec::new(),
        })),
        is_async: false,
        source_text: None,
    });
    let ctx = LoweringContext::new("trace-gap", "decision-gap", "policy-gap");
    let output = lower_ir0_to_ir3(&ir0, &ctx)
        .expect("arrow function empty template literal should lower to IR3");

    let function_desc = output
        .ir3
        .instructions
        .iter()
        .find_map(|instruction| match instruction {
            Ir3Instruction::CreateArrowClosure { function_index, .. } => {
                output.ir3.function_table.get(*function_index as usize)
            }
            _ => None,
        })
        .expect("arrow function should create a deferred closure body");
    let body = &output.ir3.instructions[function_desc.entry as usize..];
    let empty_pool_index = output
        .ir3
        .constant_pool
        .iter()
        .position(|value| value.is_empty())
        .expect("empty template literal should load an empty string constant");
    let empty_pool_index =
        u32::try_from(empty_pool_index).expect("constant pool index should fit in u32");

    assert!(
        body.iter().any(|instruction| {
            matches!(
                instruction,
                Ir3Instruction::LoadStr { pool_index, .. } if *pool_index == empty_pool_index
            )
        }),
        "empty template literal in function body must emit a real empty string load"
    );
    assert!(
        !body.iter().any(
            |instruction| matches!(instruction, Ir3Instruction::Move { dst, src } if dst == src),
        ),
        "empty template literal in function body must not lower to a self-move"
    );
}

#[test]
fn lower_arrow_function_for_of_body_to_ir3() {
    let ir0 = expr_ir0(Expression::ArrowFunction {
        params: vec![],
        body: ArrowBody::Block(BlockStatement {
            body: vec![Statement::ForOf(ForOfStatement {
                binding: BindingPattern::Identifier("value".into()),
                binding_kind: Some(VariableDeclarationKind::Const),
                assignment_strictness: AssignmentStrictness::Sloppy,
                iterable: Expression::ArrayLiteral(vec![Some(Expression::NumericLiteral(1))]),
                body: Box::new(Statement::Expression(ExpressionStatement {
                    expression: Expression::Identifier("value".into()),
                    span: span(),
                })),
                span: span(),
            })],
            span: span(),
        }),
        is_async: false,
        source_text: None,
    });
    let ctx = LoweringContext::new("trace-for-of-fn", "decision-for-of-fn", "policy-for-of-fn");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("function body for-of should lower to IR3");

    let function_desc = output
        .ir3
        .instructions
        .iter()
        .find_map(|instruction| match instruction {
            Ir3Instruction::CreateArrowClosure { function_index, .. } => output
                .ir3
                .function_table
                .get(function_index.to_owned() as usize),
            _ => None,
        })
        .expect("arrow function should create a deferred closure body");

    let function_body = &output.ir3.instructions[function_desc.entry as usize..];
    assert!(
        function_body
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::ForOfInit { .. })),
        "function body should retain ForOfInit lowering"
    );
    assert!(
        function_body
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::ForOfNext { .. })),
        "function body should retain ForOfNext lowering"
    );
    assert!(
        function_body
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::IteratorClose { .. })),
        "function body should retain IteratorClose lowering"
    );
}

#[test]
fn lower_class_expression_uses_constructor_instead_of_undefined_placeholder() {
    let ir0 = expr_ir0(Expression::ClassExpression {
        name: Some("Widget".to_string()),
        super_class: None,
        body: vec![
            MethodDefinition {
                key: Expression::Identifier("constructor".to_string()),
                kind: MethodKind::Constructor,
                params: vec![FunctionParam {
                    pattern: BindingPattern::Identifier("value".to_string()),
                    span: span(),
                }],
                body: BlockStatement {
                    body: vec![Statement::Return(ReturnStatement {
                        argument: Some(Expression::Identifier("value".to_string())),
                        span: span(),
                    })],
                    span: span(),
                },
                is_static: false,
                computed: false,
                span: span(),
                is_async: false,
                is_generator: false,
                source_text: None,
            },
            MethodDefinition {
                key: Expression::Identifier("render".to_string()),
                kind: MethodKind::Method,
                params: Vec::new(),
                body: BlockStatement {
                    body: vec![Statement::Return(ReturnStatement {
                        argument: Some(Expression::StringLiteral("ok".into())),
                        span: span(),
                    })],
                    span: span(),
                },
                is_static: false,
                computed: false,
                span: span(),
                is_async: false,
                is_generator: false,
                source_text: None,
            },
        ],
        source_text: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("class expression should lower");

    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::DeclareFunction {
            name,
            param_names,
            ..
        } if name == "Widget" && param_names == &vec!["value".to_string()]
    )));
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::CreateFunction {
            name: Some(name), ..
        } if name == "render"
    )));
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static(name),
            ..
        } if name == "render"
    )));

    let scope = result.module.scopes.first().expect("root scope");
    assert!(
        scope
            .bindings
            .iter()
            .any(|binding| binding.name.contains("class_expression")),
        "class expression should use an internal binding for method setup"
    );
    assert!(
        !scope
            .bindings
            .iter()
            .any(|binding| binding.name == "Widget"),
        "named class expressions must not leak their name into outer scope"
    );
}

#[test]
fn lower_class_method_separates_exact_key_from_function_display_name_bd_b12xs_6() {
    let exact = JsString::from_code_units(&[0xD800]);
    let ir0 = expr_ir0(Expression::ClassExpression {
        name: None,
        super_class: None,
        body: vec![MethodDefinition {
            key: Expression::StringLiteral(exact.clone()),
            kind: MethodKind::Method,
            params: Vec::new(),
            body: BlockStatement {
                body: Vec::new(),
                span: span(),
            },
            is_static: false,
            computed: false,
            span: span(),
            is_async: false,
            is_generator: false,
            source_text: None,
        }],
        source_text: None,
    });

    let result = lower_ir0_to_ir1(&ir0).expect("exact class method key should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::CreateFunction {
            name: Some(name), ..
        } if name == "[property:D800]"
    )));
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static(key),
            ..
        } if key == &exact
    )));
    assert_ne!(
        property_key_function_display_name(&exact),
        property_key_function_display_name(&JsString::from_code_units(&[0xD801]))
    );
}

#[test]
fn lower_new_expression_emits_construct() {
    let ir0 = expr_ir0(Expression::New {
        callee: Box::new(Expression::Identifier("Foo".into())),
        arguments: vec![Expression::NumericLiteral(1)],
    });
    let result = lower_ir0_to_ir1(&ir0).expect("new expression should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Construct { .. }))
    );
}

#[test]
fn lower_template_literal_emits_template_op() {
    let ir0 = expr_ir0(Expression::TemplateLiteral {
        quasis: vec!["hello ".into(), " world".into()],
        expressions: vec![Expression::Identifier("name".into())],
    });
    let result = lower_ir0_to_ir1(&ir0).expect("template literal should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::TemplateLiteral { .. }))
    );
}

#[test]
fn lower_computed_member_assignment_uses_dynamic_key_without_nop() {
    let ir0 = expr_ir0(Expression::Assignment {
        operator: AssignmentOperator::Assign,
        left: Box::new(Expression::Member {
            object: Box::new(Expression::Identifier("obj".into())),
            property: Box::new(Expression::Identifier("field".into())),
            computed: true,
            span: None,
        }),
        right: Box::new(Expression::NumericLiteral(7)),
        assignment_strictness: AssignmentStrictness::Sloppy,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("computed member assignment should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::SetProperty {
            key: Ir1PropertyKey::Dynamic,
            strict: false,
        }
    )));
    assert!(!result.module.ops.iter().any(|op| matches!(op, Ir1Op::Nop)));
}

#[test]
fn lower_non_arithmetic_binary_emits_typed_instruction() {
    let ir0 = expr_ir0(Expression::Binary {
        operator: BinaryOperator::LessThan,
        left: Box::new(Expression::NumericLiteral(1)),
        right: Box::new(Expression::NumericLiteral(2)),
    });
    let ctx = LoweringContext::new("trace-gap", "decision-gap", "policy-gap");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("comparison currently lowers");
    assert!(
        output.ir3.instructions.iter().any(|instruction| matches!(
            instruction,
            crate::ir_contract::Ir3Instruction::Lt { .. }
        ))
    );
}

// ================================================================
// Statement lowering enrichment
// ================================================================

#[test]
fn lower_block_statement() {
    let ir0 = stmt_ir0(vec![Statement::Block(BlockStatement {
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(1),
            span: span(),
        })],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("block should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::LoadLiteral { .. }))
    );
}

#[test]
fn lower_if_statement_with_else() {
    let ir0 = stmt_ir0(vec![Statement::If(IfStatement {
        condition: Expression::BooleanLiteral(true),
        consequent: Box::new(Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(1),
            span: span(),
        })),
        alternate: Some(Box::new(Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(2),
            span: span(),
        }))),
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("if-else should lower");
    let label_count = result
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::Label { .. }))
        .count();
    assert_eq!(label_count, 2); // else label + end label
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::JumpIfFalsy { .. }))
    );
}

#[test]
fn lower_if_statement_without_else() {
    let ir0 = stmt_ir0(vec![Statement::If(IfStatement {
        condition: Expression::BooleanLiteral(false),
        consequent: Box::new(Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(1),
            span: span(),
        })),
        alternate: None,
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("if-only should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::JumpIfFalsy { .. }))
    );
}

#[test]
fn lower_for_statement() {
    let ir0 = stmt_ir0(vec![Statement::For(ForStatement {
        init: Some(Box::new(Statement::VariableDeclaration(
            VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("i".into()),
                    initializer: Some(Expression::NumericLiteral(0)),
                    span: span(),
                }],
                span: span(),
            },
        ))),
        condition: Some(Expression::BooleanLiteral(true)),
        update: Some(Expression::NumericLiteral(1)),
        body: Box::new(Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(99),
            span: span(),
        })),
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("for should lower");
    let jump_count = result
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::Jump { .. }))
        .count();
    assert!(jump_count >= 1); // back-edge

    let markers: Vec<(BindingId, BindingKind, bool)> = result
        .module
        .ops
        .iter()
        .filter_map(|op| match op {
            Ir1Op::CreatePerIterationBinding {
                binding_id,
                kind,
                preserve_state,
            } => Some((*binding_id, *kind, *preserve_state)),
            _ => None,
        })
        .collect();
    assert_eq!(markers.len(), 2);
    assert_eq!(markers[0], markers[1]);
    assert_eq!(markers[0].1, BindingKind::Let);
    assert!(markers[0].2);

    let mut const_ir0 = ir0.clone();
    let Statement::For(const_for) = &mut const_ir0.tree.body[0] else {
        panic!("expected for statement");
    };
    let Some(Statement::VariableDeclaration(declaration)) = const_for.init.as_deref_mut() else {
        panic!("expected declaration initializer");
    };
    declaration.kind = VariableDeclarationKind::Const;
    let const_result = lower_ir0_to_ir1(&const_ir0).expect("const for should lower");
    assert!(
        !const_result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::CreatePerIterationBinding { .. }))
    );
}

#[test]
fn lower_for_in_statement_produces_ir1_ops() {
    let ir0 = stmt_ir0(vec![Statement::ForIn(ForInStatement {
        binding: BindingPattern::Identifier("k".into()),
        binding_kind: Some(VariableDeclarationKind::Let),
        assignment_strictness: AssignmentStrictness::Sloppy,
        object: Expression::Identifier("obj".into()),
        body: Box::new(Statement::Expression(ExpressionStatement {
            expression: Expression::Identifier("k".into()),
            span: span(),
        })),
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("for-in lowering should succeed");
    let ops = &result.module.ops;
    // Must contain ForInInit and ForInNext opcodes.
    assert!(
        ops.iter().any(|op| matches!(op, Ir1Op::ForInInit)),
        "missing ForInInit"
    );
    assert!(
        ops.iter().any(|op| matches!(op, Ir1Op::ForInNext { .. })),
        "missing ForInNext"
    );
}

#[test]
fn lower_for_of_statement_produces_ir1_ops() {
    let ir0 = stmt_ir0(vec![Statement::ForOf(ForOfStatement {
        binding: BindingPattern::Identifier("v".into()),
        binding_kind: Some(VariableDeclarationKind::Const),
        assignment_strictness: AssignmentStrictness::Sloppy,
        iterable: Expression::Identifier("arr".into()),
        body: Box::new(Statement::Expression(ExpressionStatement {
            expression: Expression::Identifier("v".into()),
            span: span(),
        })),
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("for-of lowering should succeed");
    let ops = &result.module.ops;
    // Must contain ForOfInit, ForOfNext, and IteratorClose opcodes.
    assert!(
        ops.iter().any(|op| matches!(op, Ir1Op::ForOfInit)),
        "missing ForOfInit"
    );
    assert!(
        ops.iter().any(|op| matches!(op, Ir1Op::ForOfNext { .. })),
        "missing ForOfNext"
    );
    assert!(
        ops.iter()
            .any(|op| matches!(op, Ir1Op::IteratorClose { .. })),
        "missing IteratorClose"
    );
    let markers: Vec<_> = ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::CreatePerIterationBinding { .. }))
        .collect();
    assert_eq!(markers.len(), 1);
    assert!(matches!(
        markers[0],
        Ir1Op::CreatePerIterationBinding {
            kind: BindingKind::Const,
            preserve_state: false,
            ..
        }
    ));
}

#[test]
fn lower_for_of_head_assignment_has_throw_close_path_bd_cu3sz() {
    let ir0 = stmt_ir0(vec![Statement::ForOf(ForOfStatement {
        binding: BindingPattern::Identifier("v".into()),
        binding_kind: None,
        assignment_strictness: AssignmentStrictness::Strict,
        iterable: Expression::Identifier("arr".into()),
        body: Box::new(Statement::Block(BlockStatement {
            body: Vec::new(),
            span: span(),
        })),
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("for-of lowering should succeed");
    let ops = &result.module.ops;
    let next_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::ForOfNext { .. }))
        .expect("missing ForOfNext");
    let init_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::ForOfInit))
        .expect("missing ForOfInit");
    let iterator_binding_id = match ops.get(init_pos + 1) {
        Some(Ir1Op::StoreBinding { binding_id }) => *binding_id,
        _ => panic!("ForOfInit must preserve its iterator in an internal register"),
    };
    assert!(init_pos < next_pos);
    let done_label = match ops[next_pos] {
        Ir1Op::ForOfNext { done_label } => done_label,
        _ => unreachable!(),
    };
    let begin_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::BeginTry { .. }))
        .expect("missing loop-head handler");
    assert_eq!(
        ops.iter()
            .filter(|op| matches!(op, Ir1Op::BeginTry { .. }))
            .count(),
        2,
        "empty-body for-of needs synthetic head and body handlers"
    );
    let throw_close_label = match ops[begin_pos] {
        Ir1Op::BeginTry {
            catch_label,
            finally_label: Some(finally_label),
        } if catch_label == finally_label => catch_label,
        Ir1Op::BeginTry { .. } => {
            panic!("loop-head errors must route through a finally-style handler")
        }
        _ => unreachable!(),
    };
    let assign_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::PutName { name, strict: true } if name == "v"))
        .expect("missing bare-target assignment");
    let end_try_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::EndTry))
        .expect("missing loop-head EndTry");
    assert!(
        next_pos < begin_pos && begin_pos < assign_pos && assign_pos < end_try_pos,
        "only the loop-head assignment belongs inside the protected region"
    );

    let closes: Vec<_> = ops
        .iter()
        .enumerate()
        .filter_map(|(position, op)| match op {
            Ir1Op::IteratorClose { reason } => Some((position, *reason)),
            _ => None,
        })
        .collect();
    assert_eq!(
        closes.len(),
        3,
        "for-of must have exactly three close paths"
    );
    assert_eq!(closes[0].1, IteratorCloseReason::Break);
    assert_eq!(closes[1].1, IteratorCloseReason::Return);
    assert_eq!(closes[2].1, IteratorCloseReason::Throw);
    let break_close_pos = closes[0].0;
    let return_close_pos = closes[1].0;
    let throw_close_pos = closes[2].0;
    let throw_close_label_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::Label { id } if *id == throw_close_label))
        .expect("missing loop-head/body throw-close label");
    let end_pos = ops
        .iter()
        .position(|op| matches!(op, Ir1Op::Label { id } if *id == done_label))
        .expect("missing normal exhaustion label");
    assert!(matches!(
        ops.get(break_close_pos + 1),
        Some(Ir1Op::Jump { label_id }) if *label_id == done_label
    ));
    assert!(matches!(
        ops.get(throw_close_label_pos + 1),
        Some(Ir1Op::EnterFinally)
    ));
    assert!(matches!(
        ops.get(throw_close_label_pos + 2),
        Some(Ir1Op::LoadBinding { binding_id }) if *binding_id == iterator_binding_id
    ));
    assert!(matches!(
        ops.get(throw_close_label_pos + 3),
        Some(Ir1Op::IteratorClose {
            reason: IteratorCloseReason::Throw
        })
    ));
    assert!(matches!(
        ops.get(throw_close_label_pos + 4),
        Some(Ir1Op::EndFinally)
    ));
    let end_finally_pos = throw_close_label_pos + 4;
    assert!(
        break_close_pos < return_close_pos
            && return_close_pos < throw_close_label_pos
            && throw_close_label_pos < throw_close_pos
            && throw_close_pos < end_finally_pos
            && end_finally_pos < end_pos,
        "break and return must skip the shared throw-close handler"
    );
}

#[test]
fn lower_for_of_body_preserves_throw_and_return_close_kinds_bd_g73mg() {
    // A fresh `const value` head cannot throw, so only the body runs in a
    // close region (bd-9vouw.486); an assignment head (`value` undeclared,
    // a PutName) keeps the head region the body's throw target shares.
    for (binding_kind, guards) in [(Some(VariableDeclarationKind::Const), 1), (None, 2)] {
        let ir0 = stmt_ir0(vec![Statement::ForOf(ForOfStatement {
            binding: BindingPattern::Identifier("value".into()),
            binding_kind,
            assignment_strictness: AssignmentStrictness::Sloppy,
            iterable: Expression::Identifier("values".into()),
            body: Box::new(Statement::Return(ReturnStatement {
                argument: Some(Expression::Identifier("value".into())),
                span: span(),
            })),
            span: span(),
        })]);
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("for-of return lowering")
            .module;
        let begin_tries: Vec<_> = ir1
            .ops
            .iter()
            .filter_map(|op| match op {
                Ir1Op::BeginTry {
                    catch_label,
                    finally_label,
                } => Some((*catch_label, *finally_label)),
                _ => None,
            })
            .collect();
        assert_eq!(
            begin_tries.len(),
            guards,
            "head and body guards ({binding_kind:?})"
        );
        let (throw_close_label, return_close_label) = begin_tries[guards - 1];
        let return_close_label = return_close_label.expect("body return target");
        if guards == 2 {
            assert_eq!(begin_tries[0].1, Some(begin_tries[0].0));
            assert_eq!(throw_close_label, begin_tries[0].0);
        }
        assert_ne!(throw_close_label, return_close_label);

        let return_handler = ir1
            .ops
            .iter()
            .position(|op| matches!(op, Ir1Op::Label { id } if *id == return_close_label))
            .expect("return close handler");
        // EnterFinally must sit exactly at the return-close target: the
        // pending-completion ownership check compares the unwind target to
        // the EnterFinally ip, so a close emitted before EnterFinally
        // silently drops the suspended return value (bd-s94p8).
        assert!(matches!(
            ir1.ops.get(return_handler + 1),
            Some(Ir1Op::EnterFinally)
        ));
        assert!(matches!(
            ir1.ops.get(return_handler + 3),
            Some(Ir1Op::IteratorClose {
                reason: IteratorCloseReason::Return
            })
        ));
        assert!(matches!(
            ir1.ops.get(return_handler + 4),
            Some(Ir1Op::EndFinally)
        ));

        let throw_handler = ir1
            .ops
            .iter()
            .position(|op| matches!(op, Ir1Op::Label { id } if *id == throw_close_label))
            .expect("throw close handler");
        assert!(matches!(
            ir1.ops.get(throw_handler + 1),
            Some(Ir1Op::EnterFinally)
        ));
        assert!(matches!(
            ir1.ops.get(throw_handler + 3),
            Some(Ir1Op::IteratorClose {
                reason: IteratorCloseReason::Throw
            })
        ));

        let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
        let ir3 = lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module;
        assert_eq!(
            ir3.instructions
                .iter()
                .filter(|instruction| matches!(instruction, Ir3Instruction::EnterCatch { .. }))
                .count(),
            0,
            "the distinct body Throw target is finally-style and must retain its exception"
        );
        assert!(ir3.instructions.iter().any(|instruction| matches!(
            instruction,
            Ir3Instruction::IteratorClose {
                reason: IteratorCloseReason::Return,
                ..
            }
        )));
    }
}

#[test]
fn lower_for_of_outer_continue_preserves_continue_close_kind_bd_g73mg() {
    let inner = Statement::ForOf(ForOfStatement {
        binding: BindingPattern::Identifier("value".into()),
        binding_kind: Some(VariableDeclarationKind::Const),
        assignment_strictness: AssignmentStrictness::Sloppy,
        iterable: Expression::Identifier("values".into()),
        body: Box::new(Statement::Continue(ContinueStatement {
            label: Some("outer".into()),
            span: span(),
        })),
        span: span(),
    });
    let ir0 = stmt_ir0(vec![Statement::Labeled(LabeledStatement {
        label: "outer".into(),
        body: Box::new(Statement::While(WhileStatement {
            condition: Expression::BooleanLiteral(true),
            body: Box::new(Statement::Block(BlockStatement {
                body: vec![inner],
                span: span(),
            })),
            span: span(),
        })),
        span: span(),
    })]);

    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("outer labelled continue lowering")
        .module;
    assert_eq!(
        ir1.ops
            .iter()
            .filter(|op| matches!(
                op,
                Ir1Op::IteratorClose {
                    reason: IteratorCloseReason::Continue
                }
            ))
            .count(),
        1,
        "the crossed iterator must retain Continue in replay-visible IR"
    );

    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    let ir3 = lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module;
    assert!(ir3.instructions.iter().any(|instruction| matches!(
        instruction,
        Ir3Instruction::IteratorClose {
            reason: IteratorCloseReason::Continue,
            ..
        }
    )));
}

#[test]
fn lower_while_statement() {
    let ir0 = stmt_ir0(vec![Statement::While(WhileStatement {
        condition: Expression::BooleanLiteral(true),
        body: Box::new(Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(1),
            span: span(),
        })),
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("while should lower");
    let labels: Vec<u32> = result
        .module
        .ops
        .iter()
        .filter_map(|op| match op {
            Ir1Op::Label { id } => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(labels.len(), 3); // body + test + end
    // The test runs at the bottom (bd-9vouw.486): entry jumps to it, and
    // a truthy test is the back edge to the body.
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::Jump { label_id } if *label_id == labels[1]
    )));
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::JumpIfTruthy { label_id } if *label_id == labels[0]
    )));
}

#[test]
fn lower_do_while_statement() {
    let ir0 = stmt_ir0(vec![Statement::DoWhile(DoWhileStatement {
        condition: Expression::BooleanLiteral(false),
        body: Box::new(Statement::Continue(ContinueStatement {
            label: None,
            span: span(),
        })),
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("do-while should lower");
    let labels: Vec<u32> = result
        .module
        .ops
        .iter()
        .filter_map(|op| match op {
            Ir1Op::Label { id } => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(labels.len(), 3); // loop + continue-to-condition + end

    let jumps: Vec<u32> = result
        .module
        .ops
        .iter()
        .filter_map(|op| match op {
            Ir1Op::Jump { label_id } => Some(*label_id),
            _ => None,
        })
        .collect();
    assert!(
        jumps.contains(&labels[1]),
        "continue in do-while must jump to the condition-check label"
    );
    // A truthy test is the back edge to the loop label, in one
    // conditional jump (bd-9vouw.486).
    assert!(
        result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::JumpIfTruthy { label_id } if *label_id == labels[0]
        )),
        "do-while must retain a back edge to the loop label"
    );
}

#[test]
fn lower_return_with_argument() {
    let ir0 = stmt_ir0(vec![Statement::Return(ReturnStatement {
        argument: Some(Expression::NumericLiteral(42)),
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("return should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Return))
    );
}

#[test]
fn lower_return_without_argument() {
    let ir0 = stmt_ir0(vec![Statement::Return(ReturnStatement {
        argument: None,
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("bare return should lower");
    // Should push undefined then return.
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined
        }
    )));
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Return))
    );
}

#[test]
fn lower_throw_statement() {
    let ir0 = stmt_ir0(vec![Statement::Throw(ThrowStatement {
        argument: Expression::StringLiteral("err".into()),
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("throw should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Throw))
    );
}

#[test]
fn lower_try_catch_with_param() {
    let ir0 = stmt_ir0(vec![Statement::TryCatch(TryCatchStatement {
        block: BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })],
            span: span(),
        },
        handler: Some(CatchClause {
            parameter: Some("e".into()),
            body: BlockStatement {
                body: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::Identifier("e".into()),
                    span: span(),
                })],
                span: span(),
            },
            span: span(),
        }),
        finalizer: None,
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("try-catch should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::BeginTry { .. }))
    );
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::EndTry))
    );
    let binding = result
        .module
        .scopes
        .first()
        .expect("scope")
        .bindings
        .iter()
        .find(|b| b.name == "e");
    assert!(binding.is_some());
}

#[test]
fn lower_try_catch_with_finalizer() {
    let ir0 = stmt_ir0(vec![Statement::TryCatch(TryCatchStatement {
        block: BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })],
            span: span(),
        },
        handler: None,
        finalizer: Some(BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(99),
                span: span(),
            })],
            span: span(),
        }),
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("try-finally should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::BeginTry { .. }))
    );
    // Finally block must have EnterFinally/EndFinally markers
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::EnterFinally)),
        "try/finally must emit EnterFinally IR1 op"
    );
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::EndFinally)),
        "try/finally must emit EndFinally IR1 op"
    );
    // BeginTry must carry a finally_label
    let begin_try = result
        .module
        .ops
        .iter()
        .find(|op| matches!(op, Ir1Op::BeginTry { .. }));
    assert!(
        matches!(
            begin_try,
            Some(Ir1Op::BeginTry {
                finally_label: Some(_),
                ..
            })
        ),
        "BeginTry must include finally_label when finalizer is present"
    );
}

#[test]
fn try_finally_emits_ir3_finally_instructions() {
    let ir0 = stmt_ir0(vec![Statement::TryCatch(TryCatchStatement {
        block: BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })],
            span: span(),
        },
        handler: None,
        finalizer: Some(BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(99),
                span: span(),
            })],
            span: span(),
        }),
        span: span(),
    })]);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("try-finally IR0->IR1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    let ir3 = lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module;
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::BeginTry { .. })),
        "IR3 must contain BeginTry"
    );
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::EnterFinally)),
        "IR3 must contain EnterFinally"
    );
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::EndFinally)),
        "IR3 must contain EndFinally"
    );
    // BeginTry must have a non-None finally_target
    let begin_try = ir3
        .instructions
        .iter()
        .find(|i| matches!(i, Ir3Instruction::BeginTry { .. }));
    assert!(
        matches!(
            begin_try,
            Some(Ir3Instruction::BeginTry {
                finally_target: Some(_),
                ..
            })
        ),
        "IR3 BeginTry must have finally_target set when finalizer is present"
    );
}

#[test]
fn try_catch_finally_emits_all_ir3_exception_instructions() {
    let ir0 = stmt_ir0(vec![Statement::TryCatch(TryCatchStatement {
        block: BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })],
            span: span(),
        },
        handler: Some(CatchClause {
            parameter: Some("e".into()),
            body: BlockStatement {
                body: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::Identifier("e".into()),
                    span: span(),
                })],
                span: span(),
            },
            span: span(),
        }),
        finalizer: Some(BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(42),
                span: span(),
            })],
            span: span(),
        }),
        span: span(),
    })]);
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("try-catch-finally IR0->IR1")
        .module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    let ir3 = lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module;
    // All exception IR3 instructions must be present
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::BeginTry { .. }))
    );
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::EndTry))
    );
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::EnterCatch { .. }))
    );
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::EnterFinally))
    );
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::EndFinally))
    );
    // BeginTry must have both catch_target and finally_target
    let begin_try = ir3
        .instructions
        .iter()
        .find(|i| matches!(i, Ir3Instruction::BeginTry { .. }));
    if let Some(Ir3Instruction::BeginTry {
        catch_target,
        finally_target,
    }) = begin_try
    {
        assert!(*catch_target > 0, "catch_target must be resolved");
        assert!(
            finally_target.is_some(),
            "finally_target must be set for try/catch/finally"
        );
    } else {
        // SAFETY: Test validates IR3 lowering includes expected BeginTry instruction
        panic!("BeginTry not found in IR3 output");
    }
}

#[test]
fn nested_try_catch_lowers_to_ir3() {
    // try { try { throw 1; } catch (inner) { } } catch (outer) { }
    let inner_try = Statement::TryCatch(TryCatchStatement {
        block: BlockStatement {
            body: vec![Statement::Throw(ThrowStatement {
                argument: Expression::NumericLiteral(1),
                span: span(),
            })],
            span: span(),
        },
        handler: Some(CatchClause {
            parameter: Some("inner".into()),
            body: BlockStatement {
                body: vec![],
                span: span(),
            },
            span: span(),
        }),
        finalizer: None,
        span: span(),
    });
    let ir0 = stmt_ir0(vec![Statement::TryCatch(TryCatchStatement {
        block: BlockStatement {
            body: vec![inner_try],
            span: span(),
        },
        handler: Some(CatchClause {
            parameter: Some("outer".into()),
            body: BlockStatement {
                body: vec![],
                span: span(),
            },
            span: span(),
        }),
        finalizer: None,
        span: span(),
    })]);
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("nested try-catch IR0->IR1")
        .module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    let ir3 = lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module;
    // Must have two BeginTry instructions for nested try blocks
    let begin_try_count = ir3
        .instructions
        .iter()
        .filter(|i| matches!(i, Ir3Instruction::BeginTry { .. }))
        .count();
    assert_eq!(begin_try_count, 2, "nested try must produce 2 BeginTry");
    // Must have a Throw instruction
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::Throw { .. }))
    );
}

#[test]
fn throw_statement_emits_ir3_throw() {
    let ir0 = stmt_ir0(vec![Statement::Throw(ThrowStatement {
        argument: Expression::StringLiteral("err".into()),
        span: span(),
    })]);
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("throw should lower to IR1")
        .module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    let ir3 = lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module;
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::Throw { .. }))
    );
}

#[test]
fn try_catch_emits_ir3_exception_instructions() {
    let ir0 = stmt_ir0(vec![Statement::TryCatch(TryCatchStatement {
        block: BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })],
            span: span(),
        },
        handler: Some(CatchClause {
            parameter: Some("e".into()),
            body: BlockStatement {
                body: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::Identifier("e".into()),
                    span: span(),
                })],
                span: span(),
            },
            span: span(),
        }),
        finalizer: None,
        span: span(),
    })]);
    let ir1 = lower_ir0_to_ir1(&ir0).expect("try-catch IR0->IR1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    let ir3 = lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module;
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::BeginTry { .. }))
    );
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::EndTry))
    );
    assert!(
        ir3.instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::EnterCatch { .. }))
    );
}

#[test]
fn lower_switch_statement() {
    let ir0 = stmt_ir0(vec![Statement::Switch(SwitchStatement {
        discriminant: Expression::Identifier("x".into()),
        cases: vec![
            SwitchCase {
                test: Some(Expression::NumericLiteral(1)),
                consequent: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::StringLiteral("one".into()),
                    span: span(),
                })],
                span: span(),
            },
            SwitchCase {
                test: None,
                consequent: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::StringLiteral("default".into()),
                    span: span(),
                })],
                span: span(),
            },
        ],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("switch should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::BinaryOp {
            operator: BinaryOperator::StrictEqual
        }
    )));
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::LoadBinding { .. }))
    );
}

#[test]
fn lower_break_outside_control_flow_is_error() {
    let ir0 = stmt_ir0(vec![Statement::Break(BreakStatement {
        label: None,
        span: span(),
    })]);
    let err = lower_ir0_to_ir1(&ir0).expect_err("top-level break should fail");
    assert!(matches!(
        err,
        LoweringPipelineError::SemanticViolation(SemanticError {
            code: SemanticErrorCode::IllegalBreak,
            ..
        })
    ));
}

#[test]
fn lower_continue_outside_loop_is_error() {
    let ir0 = stmt_ir0(vec![Statement::Continue(ContinueStatement {
        label: None,
        span: span(),
    })]);
    let err = lower_ir0_to_ir1(&ir0).expect_err("top-level continue should fail");
    assert!(matches!(
        err,
        LoweringPipelineError::SemanticViolation(SemanticError {
            code: SemanticErrorCode::IllegalContinue,
            ..
        })
    ));
}

#[test]
fn lower_break_inside_switch_emits_jump() {
    let ir0 = stmt_ir0(vec![Statement::Switch(SwitchStatement {
        discriminant: Expression::Identifier("x".into()),
        cases: vec![SwitchCase {
            test: Some(Expression::NumericLiteral(1)),
            consequent: vec![Statement::Break(BreakStatement {
                label: None,
                span: span(),
            })],
            span: span(),
        }],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("break in switch should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Jump { .. }))
    );
    assert!(!result.module.ops.iter().any(|op| matches!(op, Ir1Op::Nop)));
}

#[test]
fn lower_continue_inside_for_emits_jump() {
    let ir0 = stmt_ir0(vec![Statement::For(ForStatement {
        init: None,
        condition: Some(Expression::BooleanLiteral(true)),
        update: Some(Expression::NumericLiteral(1)),
        body: Box::new(Statement::Continue(ContinueStatement {
            label: None,
            span: span(),
        })),
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("continue in for should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Jump { .. }))
    );
    assert!(!result.module.ops.iter().any(|op| matches!(op, Ir1Op::Nop)));
}

#[test]
fn lower_block_destructuring_allocates_all_bindings() {
    let ir0 = stmt_ir0(vec![Statement::Block(BlockStatement {
        body: vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Let,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::ObjectPattern(vec![
                    ObjectPatternProperty {
                        key: Expression::Identifier("a".into()),
                        value: BindingPattern::Identifier("a".into()),
                        computed: false,
                        shorthand: true,
                    },
                    ObjectPatternProperty {
                        key: Expression::Identifier("b".into()),
                        value: BindingPattern::Identifier("renamed".into()),
                        computed: false,
                        shorthand: false,
                    },
                ]),
                initializer: Some(Expression::Identifier("source".into())),
                span: span(),
            }],
            span: span(),
        })],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("destructuring block should lower");
    let scope = result.module.scopes.first().expect("root scope");
    assert!(scope.bindings.iter().any(|binding| binding.name == "a"));
    assert!(
        scope
            .bindings
            .iter()
            .any(|binding| binding.name == "renamed")
    );
}

#[test]
fn lower_function_declaration() {
    let ir0 = stmt_ir0(vec![Statement::FunctionDeclaration(FunctionDeclaration {
        name: Some("myFunc".into()),
        params: vec![FunctionParam {
            pattern: BindingPattern::Identifier("a".into()),
            span: span(),
        }],
        body: BlockStatement {
            body: vec![],
            span: span(),
        },
        is_async: false,
        is_generator: false,
        span: span(),
        source_text: None,
        strict: false,
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("function should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::DeclareFunction { name, .. } if name == "myFunc"
    )));
}

#[test]
fn lower_anonymous_function_declaration() {
    let ir0 = stmt_ir0(vec![Statement::FunctionDeclaration(FunctionDeclaration {
        name: None,
        params: vec![],
        body: BlockStatement {
            body: vec![],
            span: span(),
        },
        is_async: false,
        is_generator: false,
        span: span(),
        source_text: None,
        strict: false,
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("anon function should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::DeclareFunction { name, .. } if name == "anonymous"
    )));
}

#[test]
fn function_declaration_with_body_emits_create_closure() {
    let ir0 = stmt_ir0(vec![Statement::FunctionDeclaration(FunctionDeclaration {
        name: Some("answer".into()),
        params: vec![FunctionParam {
            pattern: BindingPattern::Identifier("x".into()),
            span: span(),
        }],
        body: BlockStatement {
            body: vec![Statement::Return(ReturnStatement {
                argument: Some(Expression::Identifier("x".into())),
                span: span(),
            })],
            span: span(),
        },
        is_async: false,
        is_generator: false,
        span: span(),
        source_text: None,
        strict: false,
    })]);

    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("function declaration should lower to IR1")
        .module;
    let (param_names, body_ops, free_vars, is_generator) = ir1
        .ops
        .iter()
        .find_map(|op| match op {
            Ir1Op::DeclareFunction {
                name,
                param_names,
                body_ops,
                free_vars,
                is_generator,
                ..
            } if name == "answer" => Some((param_names, body_ops, free_vars, is_generator)),
            _ => None,
        })
        .expect("IR1 should retain the lowered function body");
    assert_eq!(param_names, &vec!["x".to_string()]);
    assert!(
        body_ops
            .iter()
            .any(|op| matches!(op, Ir1Op::LoadBinding { .. })),
        "function body should load its parameter"
    );
    assert!(
        body_ops.iter().any(|op| matches!(op, Ir1Op::Return)),
        "function body should retain an explicit return"
    );
    assert!(free_vars.is_empty());
    assert!(!*is_generator);

    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("function declaration should lower to IR2")
        .module;
    let ir3 = lower_ir2_to_ir3(&ir2)
        .expect("function declaration should lower to IR3")
        .module;

    let (function_index, capture_count) = ir3
        .instructions
        .iter()
        .find_map(|instruction| match instruction {
            Ir3Instruction::CreateClosure {
                function_index,
                capture_count,
                ..
            } => Some((*function_index, *capture_count)),
            _ => None,
        })
        .expect("IR3 should create a closure for the function declaration");
    assert_eq!(function_index, 1);
    assert_eq!(capture_count, 0);

    let main_halt_index = ir3
        .instructions
        .iter()
        .position(|instruction| matches!(instruction, Ir3Instruction::Halt))
        .expect("main instruction stream should terminate with Halt");
    let function_desc = ir3
        .function_table
        .get(function_index as usize)
        .expect("function table should include the deferred body");
    assert_eq!(function_desc.name.as_deref(), Some("answer"));
    assert_eq!(function_desc.arity, 1);
    assert!(
        function_desc.entry as usize > main_halt_index,
        "function body should be appended after the main instruction stream"
    );
    assert!(
        ir3.instructions[function_desc.entry as usize..]
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Return { .. })),
        "deferred function body should lower to executable IR3"
    );
}

#[test]
fn function_returning_react_create_element_call_lowers_without_underflow() {
    let create_element_call = Expression::Call {
        callee: Box::new(Expression::Member {
            object: Box::new(Expression::Identifier("React".into())),
            property: Box::new(Expression::Identifier("createElement".into())),
            computed: false,
            span: None,
        }),
        arguments: vec![
            Expression::StringLiteral("h1".into()),
            Expression::NullLiteral,
            Expression::StringLiteral("React DOM Client Test".into()),
        ],
        span: None,
    };
    let ir0 = stmt_ir0(vec![Statement::FunctionDeclaration(FunctionDeclaration {
        name: Some("App".into()),
        params: vec![],
        body: BlockStatement {
            body: vec![Statement::Return(ReturnStatement {
                argument: Some(create_element_call),
                span: span(),
            })],
            span: span(),
        },
        is_async: false,
        is_generator: false,
        span: span(),
        source_text: None,
        strict: false,
    })]);

    let context = LoweringContext::new("trace-react-return", "decision-react-return", "policy");
    lower_ir0_to_ir3(&ir0, &context).expect("React createElement return should lower");
}

// ================================================================
// Additional edge cases
// ================================================================

#[test]
fn lower_nested_binary_expressions() {
    let ir0 = expr_ir0(Expression::Binary {
        operator: BinaryOperator::Multiply,
        left: Box::new(Expression::Binary {
            operator: BinaryOperator::Add,
            left: Box::new(Expression::NumericLiteral(1)),
            right: Box::new(Expression::NumericLiteral(2)),
        }),
        right: Box::new(Expression::NumericLiteral(3)),
    });
    let result = lower_ir0_to_ir1(&ir0).expect("nested binary should lower");
    let op_count = result
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::BinaryOp { .. }))
        .count();
    assert_eq!(op_count, 2);
}

#[test]
fn lower_call_with_no_args() {
    let ir0 = expr_ir0(Expression::Call {
        callee: Box::new(Expression::Identifier("f".into())),
        arguments: vec![],
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("0-arg call should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Call { arg_count: 0 }))
    );
}

#[test]
fn lower_empty_array_literal() {
    let ir0 = expr_ir0(Expression::ArrayLiteral(vec![]));
    let result = lower_ir0_to_ir1(&ir0).expect("empty array should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::NewArray { count: 0 }))
    );
}

#[test]
fn lower_empty_object_literal() {
    let ir0 = expr_ir0(Expression::ObjectLiteral(vec![]));
    let result = lower_ir0_to_ir1(&ir0).expect("empty object should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::NewObject { count: 0 }))
    );
}

#[test]
fn lower_null_literal_expression() {
    let ir0 = expr_ir0(Expression::NullLiteral);
    let result = lower_ir0_to_ir1(&ir0).expect("null should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Null
        }
    )));
}

#[test]
fn immutable_global_references_keep_the_literal_fast_path() {
    let ops = lower_script_source_ops("undefined; NaN; Infinity;", "global-values.js");
    let literals = ops
        .iter()
        .filter_map(|op| match op {
            Ir1Op::LoadLiteral { value } => Some(value.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        literals,
        vec![
            Ir1Literal::Undefined,
            Ir1Literal::Float(f64::NAN.to_bits()),
            Ir1Literal::Float(f64::INFINITY.to_bits()),
        ]
    );
    assert!(!ops.iter().any(|op| matches!(op, Ir1Op::LoadName { .. })));
}

fn lower_preserving_runtime_loads(source: &str, commonjs: bool) -> LoweringPipelineOutput {
    let tree = if commonjs {
        crate::parser_api_stability::parse_script(source)
    } else {
        crate::parser_api_stability::parse_module(source)
    }
    .expect("parse source module");
    let ir0 = Ir0Module::from_syntax_tree(tree, "delivered:module");
    let mut context =
        LoweringContext::new("trace", "decision", "policy").with_preserved_runtime_module_loads();
    if commonjs {
        context = context.with_authenticated_commonjs_runtime_bindings();
    }
    lower_ir0_to_ir3(&ir0, &context).expect("lower through the real runtime load boundary")
}

#[test]
fn authenticated_crypto_and_zlib_calls_preserve_runtime_module_objects() {
    for (name, method, argument, capability) in [
        ("crypto", "createHash", "sha256", "builtin:CryptoCreateHash"),
        ("zlib", "gzipSync", "payload", "builtin:ZlibGzipSync"),
    ] {
        let source = format!(
            "const builtin = require('{name}');\n\
             builtin.{method}('{argument}');\n\
             require('node:{name}').{method}('{argument}');"
        );
        let tree = crate::parser_api_stability::parse_script(&source)
            .expect("parse CommonJS native module calls");
        let ir0 = Ir0Module::from_syntax_tree(tree, "native-module-values.cjs");
        // Ordinary CommonJS, without the external resolver's separate
        // preserve-loads flag, must retain mutable module properties too.
        let output = lower_ir0_to_ir3(
            &ir0,
            &LoweringContext::new("native-module-values", "cjs", "policy")
                .with_authenticated_commonjs_runtime_bindings(),
        )
        .expect("lower runtime module methods");
        assert_eq!(count_hostcall_deep(&output.ir1.ops, capability), 0);
        assert_eq!(
            count_ops_deep(&output.ir1.ops, &|op| matches!(
                op,
                Ir1Op::Call { arg_count: 1 }
            )),
            2,
            "both {name} aliases must reach the authenticated runtime require"
        );
    }
}

#[test]
fn authenticated_child_process_calls_preserve_runtime_module_objects() {
    for name in ["child_process", "node:child_process"] {
        let source = format!(
            "const cp = require('{name}');\n\
             cp.spawnSync('program');\n\
             function later() {{ return cp.execFileSync('program'); }}\n\
             require('{name}').execSync('program');"
        );
        let tree = crate::parser_api_stability::parse_script(&source)
            .expect("parse CommonJS child-process exports");
        let ir0 = Ir0Module::from_syntax_tree(tree, "native-child-process.cjs");
        for preserve_loads in [false, true] {
            let mut context = LoweringContext::new("native-child-process", "cjs", "policy")
                .with_authenticated_commonjs_runtime_bindings();
            if preserve_loads {
                context = context.with_preserved_runtime_module_loads();
            }
            let output = lower_ir0_to_ir3(&ir0, &context)
                .expect("child-process methods retain runtime receiver semantics");
            assert_eq!(count_hostcall_deep(&output.ir1.ops, "process_spawn"), 0);
            assert_eq!(
                count_ops_deep(&output.ir1.ops, &|op| matches!(
                    op,
                    Ir1Op::Call { arg_count: 1 }
                )),
                2,
                "both {name} loads must invoke the authenticated require"
            );
        }
    }
}

#[test]
fn authenticated_http_calls_preserve_mutable_runtime_module_objects() {
    for name in ["http", "node:http", "https", "node:https"] {
        let source = format!(
            "const api = require('{name}'); const load = require;\n\
             const again = load('{name}');\n\
             api.request = function () {{ return 'replacement'; }};\n\
             api.request('unused'); again.request('unused');\n\
             require('{name}').request('unused');"
        );
        let tree = crate::parser_api_stability::parse_script(&source).unwrap();
        let ir0 = Ir0Module::from_syntax_tree(tree, "native-http-values.cjs");
        let output = lower_ir0_to_ir3(
            &ir0,
            &LoweringContext::new("native-http-values", "cjs", "policy")
                .with_authenticated_commonjs_runtime_bindings(),
        )
        .expect("HTTP module exports remain mutable values");
        for capability in [
            "builtin:HttpRequest",
            "builtin:HttpsRequest",
            "net:client_request",
        ] {
            assert_eq!(count_hostcall_deep(&output.ir1.ops, capability), 0);
        }
        assert_eq!(
            count_ops_deep(&output.ir1.ops, &|op| matches!(
                op,
                Ir1Op::Call { arg_count: 1 }
            )),
            3,
            "literal, aliased and inline loads call the authenticated require for {name}"
        );
    }
}

#[test]
fn preserved_commonjs_builtin_loads_reach_the_runtime_callee() {
    for name in [
        "buffer",
        "child_process",
        "crypto",
        "zlib",
        "http",
        "https",
        "events",
        "os",
        "querystring",
        "url",
        "timers",
        "perf_hooks",
        "fs",
        "fs/promises",
        "path",
        "util",
    ] {
        for prefix in ["", "node:"] {
            let specifier = format!("{prefix}{name}");
            let source =
                format!("const value = require('{specifier}'); console.log(typeof value);");
            let output = lower_preserving_runtime_loads(&source, true);
            let ops = &output.ir1.ops;
            assert_eq!(
                count_ops_deep(ops, &|op| matches!(op, Ir1Op::Call { arg_count: 1 })),
                1,
                "{specifier} must remain one call of the authenticated require binding"
            );
            assert_eq!(
                count_ops_deep(ops, &|op| matches!(op,
                    Ir1Op::LoadLiteral { value: Ir1Literal::String(value) }
                    if value.as_str() == Some(specifier.as_str()))),
                1,
                "the runtime policy must see the original alias spelling"
            );
            assert_eq!(
                count_ops_deep(ops, &|op| matches!(
                    op,
                    Ir1Op::DeclareFunction { .. } | Ir1Op::CreateFunction { .. }
                )),
                0,
                "a source require must not become a hidden builtin loader"
            );
        }
    }
}

#[test]
fn authenticated_filesystem_calls_preserve_mutable_runtime_module_objects() {
    for name in ["fs", "node:fs", "fs/promises", "node:fs/promises"] {
        let method = if name.ends_with("/promises") {
            "readFile"
        } else {
            "readFileSync"
        };
        let source = format!(
            "const fs = require('{name}'); const load = require;\n\
             const again = load('{name}');\n\
             fs.{method} = function () {{ return 'replacement'; }};\n\
             fs.{method}('unread'); again.{method}('unread');\n\
             require('{name}').{method}('unread');"
        );
        let tree = crate::parser_api_stability::parse_script(&source).unwrap();
        let ir0 = Ir0Module::from_syntax_tree(tree, "native-fs-values.cjs");
        let output = lower_ir0_to_ir3(
            &ir0,
            &LoweringContext::new("native-fs-values", "cjs", "policy")
                .with_authenticated_commonjs_runtime_bindings(),
        )
        .expect("literal and aliased CommonJS loads stay on the runtime module path");
        assert_eq!(count_hostcall_deep(&output.ir1.ops, "fs:read"), 0);
        assert_eq!(count_hostcall_deep(&output.ir1.ops, "fs:write"), 0);
        assert_eq!(
            count_ops_deep(&output.ir1.ops, &|op| matches!(
                op,
                Ir1Op::Call { arg_count: 1 }
            )),
            3,
            "literal, aliased and inline loads call the actual CommonJS binding for {name}"
        );
    }
}

#[test]
fn authenticated_events_keep_runtime_statics_and_methods() {
    for name in ["events", "node:events"] {
        let source = format!(
            "const events = require('{name}');\n\
             const {{ EventEmitter: E, once }} = require('{name}');\n\
             E.defaultMaxListeners; events.captureRejections;\n\
             events.once(null, 'ready'); once(null, 'ready');"
        );
        let tree = crate::parser_api_stability::parse_script(&source).unwrap();
        let output = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "native-events-values.cjs"),
            &LoweringContext::new("native-events-values", "cjs", "policy")
                .with_authenticated_commonjs_runtime_bindings(),
        )
        .expect("CommonJS Events operations read the retained module values");
        assert_eq!(
            count_hostcall_deep(&output.ir1.ops, "builtin:EventsOnce"),
            0
        );
        assert_eq!(
            count_hostcall_deep(&output.ir1.ops, "builtin:EventEmitterConstructorRef"),
            0
        );
        assert_eq!(
            count_ops_deep(&output.ir1.ops, &|op| matches!(
                op,
                Ir1Op::Call { arg_count: 1 }
            )),
            2,
            "literal and destructured loads retain runtime require for {name}"
        );
    }
}

#[test]
fn authenticated_stream_and_timer_methods_keep_runtime_dispatch() {
    let source = "const { Readable, pipeline, promises } = require('stream');\n\
        const stream = Readable.from([1]);\n\
        pipeline(stream, stream, function () {});\n\
        promises.pipeline(stream, stream);\n\
        const timers = require('timers'); timers.setTimeout(function () {}, 0);\n\
        const tp = require('timers/promises'); tp.setTimeout(0);";
    let tree = crate::parser_api_stability::parse_script(source).unwrap();
    let output = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "native-stream-timers.cjs"),
        &LoweringContext::new("native-stream-timers", "cjs", "policy")
            .with_authenticated_commonjs_runtime_bindings(),
    )
    .expect("shared CommonJS module methods are read at runtime");
    for capability in [
        "builtin:StreamReadableFrom",
        "builtin:StreamPipeline",
        "builtin:StreamPromisesPipeline",
        "builtin:SetTimeout",
        "builtin:TimersPromisesSetTimeout",
    ] {
        assert_eq!(
            count_hostcall_deep(&output.ir1.ops, capability),
            0,
            "{capability}"
        );
    }
    assert_eq!(
        count_ops_deep(&output.ir1.ops, &|op| matches!(
            op,
            Ir1Op::Call { arg_count: 1 }
        )),
        3,
        "all three requests invoke the authenticated runtime require"
    );
}

#[test]
fn preserved_loads_survive_nested_destructured_and_inline_facades() {
    let output = lower_preserving_runtime_loads(
        "const { EventEmitter } = require('node:events');\n\
         const fs = require('fs');\n\
         fs.readFileSync('input');\n\
         require('fs').readFile('input', function () {});\n\
         require('fs/promises').readFile('input');\n\
         function deferred() { return require('node:buffer'); }\n",
        true,
    );
    let ops = &output.ir1.ops;
    assert_eq!(
        count_ops_deep(ops, &|op| matches!(op, Ir1Op::Call { arg_count: 1 })),
        5,
        "each source load remains a runtime call, including the deferred body"
    );
    assert_eq!(count_hostcall_deep(ops, "fs:read"), 0);
    assert_eq!(
        count_hostcall_deep(ops, "builtin:EventEmitterConstructorRef"),
        0
    );
    assert_eq!(
        count_ops_deep(ops, &|op| matches!(
            op,
            Ir1Op::DeclareFunction { .. } | Ir1Op::CreateFunction { .. }
        )),
        2,
        "only the two source functions may be introduced"
    );
    assert!(!ops.iter().any(|op| matches!(op,
        Ir1Op::LoadLiteral { value: Ir1Literal::String(value) }
        if value.as_str() == Some("node:buffer"))));
    assert_eq!(
        count_ops_deep(ops, &|op| matches!(op,
            Ir1Op::LoadLiteral { value: Ir1Literal::String(value) }
            if value.as_str() == Some("node:buffer"))),
        1,
        "a deferred load must not move into the entry prelude"
    );
}

#[test]
fn preserved_esm_builtin_imports_cannot_bypass_runtime_refusal() {
    let output = lower_preserving_runtime_loads(
        "import 'node:path';\n\
         import { Buffer as B } from 'node:buffer';\n\
         import { readFileSync } from 'node:fs';\n\
         import * as http from 'node:http';\n\
         readFileSync('input');\n\
         http.get('https://example.invalid/');\n",
        false,
    );
    let imports = output
        .ir1
        .ops
        .iter()
        .filter_map(|op| match op {
            Ir1Op::ImportModule { specifier, .. } => specifier.as_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        imports,
        ["node:path", "node:buffer", "node:fs", "node:http"]
    );
    assert_eq!(count_hostcall_deep(&output.ir1.ops, "fs:read"), 0);
    assert_eq!(count_hostcall_deep(&output.ir1.ops, "builtin:HttpGet"), 0);
    assert_eq!(count_hostcall_deep(&output.ir1.ops, "net:request"), 0);
}

#[test]
fn preserved_load_context_does_not_grant_ambient_require() {
    let tree =
        crate::parser_api_stability::parse_script("require('buffer');").expect("parse raw script");
    let ir0 = Ir0Module::from_syntax_tree(tree, "untrusted.cjs");
    let context = LoweringContext::new("trace", "decision", "policy");
    assert!(!context.preserve_runtime_module_loads);
    let error = lower_ir0_to_ir3(&ir0, &context.with_preserved_runtime_module_loads())
        .expect_err("preserving loads cannot manufacture a CommonJS binding");
    assert!(matches!(
        error,
        LoweringPipelineError::AmbientAuthorityViolation { .. }
    ));
}

#[test]
fn module_and_commonjs_bindings_shadow_immutable_global_names() {
    for name in ["undefined", "NaN", "Infinity"] {
        let source = format!("const {name} = 7; {name};");
        let ops = lower_esm_source_ops(&source, "global-shadow.mjs");
        assert!(ops.iter().any(|op| matches!(op, Ir1Op::LoadBinding { .. })));

        let tree = crate::parser_api_stability::parse_script(&source).expect("parse CommonJS");
        let ir0 = Ir0Module::from_syntax_tree(tree, "global-shadow.cjs");
        let result = lower_ir0_to_ir1_with_authenticated_runtime_bindings(
            &ir0,
            AmbientAuthorityGrant::DenyAll,
            true,
            false,
            false,
        )
        .expect("lower authenticated CommonJS");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::LoadBinding { .. }))
        );
    }
}

#[test]
fn lower_undefined_literal_expression() {
    let ir0 = expr_ir0(Expression::UndefinedLiteral);
    let result = lower_ir0_to_ir1(&ir0).expect("undefined should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined
        }
    )));
}

#[test]
fn lower_boolean_true_expression() {
    let ir0 = expr_ir0(Expression::BooleanLiteral(true));
    let result = lower_ir0_to_ir1(&ir0).expect("true should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Boolean(true)
        }
    )));
}

#[test]
fn lower_unresolved_identifier_uses_dynamic_name_lookup_bd_0k19b() {
    let ir0 = expr_ir0(Expression::Identifier("myVar".into()));
    let result = lower_ir0_to_ir1(&ir0).expect("identifier should lower");
    assert!(
        result.module.ops.iter().any(
            |op| matches!(op, Ir1Op::LoadName { name, allow_missing: false } if name == "myVar")
        )
    );
    assert!(
        result
            .module
            .scopes
            .iter()
            .flat_map(|scope| scope.bindings.iter())
            .all(|binding| binding.name != "myVar"),
        "an unresolvable reference must not become a synthetic lexical binding"
    );
}

#[test]
fn writable_builtin_globals_bypass_lowering_shortcuts_bd_1piai() {
    let ops = lower_script_source_ops(
        "Math.abs(-1); Math.PI; Date.now(); new Date(0); Promise.resolve(1);",
        "writable_builtin_globals_bd_1piai.js",
    );

    for capability in [
        "builtin:MathAbs",
        "builtin:MathPI",
        "builtin:DateNow",
        "builtin:Date",
        "promise:resolve",
        "builtin:PromiseResolveFunction",
    ] {
        assert_eq!(
            count_hostcall_deep(&ops, capability),
            0,
            "writable realm global must not lower through {capability}"
        );
    }
    for name in ["Math", "Date", "Promise"] {
        assert!(
            ops_deep_match(&ops, &|op| matches!(
                op,
                Ir1Op::LoadName {
                    name: loaded,
                    allow_missing: false
                } if loaded == name
            )),
            "{name} must flow through runtime name resolution"
        );
    }
}

#[test]
fn lower_const_without_init_errors() {
    let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::Identifier("x".into()),
            initializer: None,
            span: span(),
        }],
        span: span(),
    })]);
    let err = lower_ir0_to_ir1(&ir0).expect_err("const without init should fail");
    assert!(matches!(err, LoweringPipelineError::SemanticViolation(_)));
}

#[test]
fn validate_static_semantics_for_in_for_of_noop() {
    let ir0 = stmt_ir0(vec![
        Statement::ForIn(ForInStatement {
            binding: BindingPattern::Identifier("k".into()),
            binding_kind: Some(VariableDeclarationKind::Let),
            assignment_strictness: AssignmentStrictness::Sloppy,
            object: Expression::Identifier("obj".into()),
            body: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })),
            span: span(),
        }),
        Statement::ForOf(ForOfStatement {
            binding: BindingPattern::Identifier("v".into()),
            binding_kind: Some(VariableDeclarationKind::Const),
            assignment_strictness: AssignmentStrictness::Sloppy,
            iterable: Expression::Identifier("arr".into()),
            body: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(2),
                span: span(),
            })),
            span: span(),
        }),
    ]);
    let result = validate_ir0_static_semantics(&ir0);
    assert!(result.is_valid());
}

#[test]
fn full_pipeline_binary_expression() {
    let ir0 = expr_ir0(Expression::Binary {
        operator: BinaryOperator::Subtract,
        left: Box::new(Expression::NumericLiteral(10)),
        right: Box::new(Expression::NumericLiteral(3)),
    });
    let ctx = LoweringContext::new("t", "d", "p");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("full pipeline should succeed");
    assert!(!output.ir3.instructions.is_empty());
    assert_eq!(output.witnesses.len(), 3);
    assert_eq!(output.events.len(), 4);
}

#[test]
fn full_pipeline_if_statement() {
    let ir0 = stmt_ir0(vec![Statement::If(IfStatement {
        condition: Expression::BooleanLiteral(true),
        consequent: Box::new(Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(1),
            span: span(),
        })),
        alternate: None,
        span: span(),
    })]);
    let ctx = LoweringContext::new("t", "d", "p");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("if pipeline should succeed");
    assert!(!output.ir1.ops.is_empty());
    assert!(!output.ir3.instructions.is_empty());
}

#[test]
fn full_pipeline_while_statement() {
    let ir0 = stmt_ir0(vec![Statement::While(WhileStatement {
        condition: Expression::BooleanLiteral(false),
        body: Box::new(Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(1),
            span: span(),
        })),
        span: span(),
    })]);
    let ctx = LoweringContext::new("t", "d", "p");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("while pipeline should succeed");
    assert!(!output.ir3.instructions.is_empty());
}

#[test]
fn bare_for_in_of_targets_reuse_assignment_bindings_bd_5p1dp() {
    let source = r#"
        let key = "";
        for (key in { alpha: 1 }) {}
        let first = "";
        let second = "";
        for ([first, second] in { xy: 1 }) {}
        let value = 0;
        for (value of [3]) {}
        let left = 0;
        const right = 0;
        for ([left, right] of [[4, 5]]) {}
        let picked = 0;
        let rest = [];
        for ([{ p: picked } = { p: 9 }, ...rest] of [[undefined, 1, 2]]) {}
        for (missing of [7]) {}
    "#;
    let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd-5p1dp.js");
    let result = lower_ir0_to_ir1(&ir0).expect("bare loop targets should lower");

    let expected = [
        ("key", BindingKind::Let, 1_usize, 1_usize),
        ("first", BindingKind::Let, 1, 1),
        ("second", BindingKind::Let, 1, 1),
        ("value", BindingKind::Let, 1, 1),
        ("left", BindingKind::Let, 1, 1),
        ("right", BindingKind::Const, 1, 1),
        // A default pattern has one target write on each mutually
        // exclusive control-flow branch.
        ("picked", BindingKind::Let, 1, 2),
        ("rest", BindingKind::Let, 1, 1),
    ];

    for (name, expected_kind, expected_initializers, expected_assignments) in expected {
        let matching = result
            .module
            .scopes
            .iter()
            .flat_map(|scope| scope.bindings.iter())
            .filter(|binding| binding.name == name)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            1,
            "{name} must retain exactly one binding identity"
        );
        let binding = matching[0];
        assert_eq!(binding.kind, expected_kind, "{name} kind must be preserved");

        let initializer_count = result
            .module
            .ops
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    Ir1Op::StoreBinding { binding_id }
                        if *binding_id == binding.binding_id
                )
            })
            .count();
        assert_eq!(
            initializer_count, expected_initializers,
            "{name} must not receive a declaration-style loop store"
        );

        let assignment_count = result
            .module
            .ops
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    Ir1Op::AssignOp {
                        binding_id,
                        operator: AssignmentOperator::Assign,
                        ..
                    } if *binding_id == binding.binding_id
                )
            })
            .count();
        assert_eq!(
            assignment_count, expected_assignments,
            "{name} must receive only its loop-head assignment ops"
        );
    }

    assert!(
        result
            .module
            .scopes
            .iter()
            .flat_map(|scope| scope.bindings.iter())
            .all(|binding| binding.name != "missing"),
        "an unresolved loop target is a dynamic reference, not a fake Let binding"
    );
    assert_eq!(
        result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::PutName { name, strict: false } if name == "missing"))
            .count(),
        1,
        "the yielded value must perform exactly one sloppy dynamic put"
    );

    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ForInInit))
    );
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ForOfInit))
    );
}

#[test]
fn bare_loop_assignment_preserves_runtime_const_and_tdz_ops_bd_5p1dp() {
    for (source, expected_kind, assignment_before_init) in [
        ("const fixed = 1; for (fixed of [2]) {}", 2_u8, false),
        ("for (value of [1]) {} let value = 9;", 1_u8, true),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 = Ir0Module::from_syntax_tree(tree, "bd-5p1dp-runtime.js");
        let output = lower_ir0_to_ir3(&ir0, &LoweringContext::new("t", "d", "p"))
            .expect("runtime binding checks should lower");
        let instructions = &output.ir3.instructions;
        let (declare_index, name_pool_index) = instructions
            .iter()
            .enumerate()
            .find_map(|(index, instruction)| match instruction {
                Ir3Instruction::DeclareBinding {
                    name_pool_index,
                    kind,
                } if *kind == expected_kind => Some((index, *name_pool_index)),
                _ => None,
            })
            .expect("scope-routed lexical target must retain its runtime kind");
        let init_index = instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction,
                    Ir3Instruction::InitBinding {
                        name_pool_index: candidate,
                        ..
                    } if *candidate == name_pool_index
                )
            })
            .expect("declaration store must initialize the lexical target");
        let assign_index = instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction,
                    Ir3Instruction::StoreScoped {
                        name_pool_index: candidate,
                        ..
                    } if *candidate == name_pool_index
                )
            })
            .expect("loop AssignOp must remain a checked runtime assignment");

        assert!(declare_index < init_index && declare_index < assign_index);
        assert_eq!(
            assign_index < init_index,
            assignment_before_init,
            "TDZ assignment ordering must follow source control flow"
        );
    }
}

#[test]
fn deferred_loop_assignment_preserves_local_lexical_metadata_bd_pimva() {
    for (
        source,
        expected_name,
        expected_binding_kind,
        expected_runtime_kind,
        assignment_before_init,
    ) in [
        (
            "function run() { const fixed = 1; for (fixed of [2]) {} }",
            "fixed",
            BindingKind::Const,
            2_u8,
            false,
        ),
        (
            "let run = () => { for (value of [1]) {} let value = 9; };",
            "value",
            BindingKind::Let,
            1_u8,
            true,
        ),
    ] {
        let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
        let ir0 = Ir0Module::from_syntax_tree(tree, "bd-pimva-deferred-runtime.js");
        let output = lower_ir0_to_ir3(&ir0, &LoweringContext::new("t", "d", "p"))
            .expect("deferred runtime binding checks should lower");
        let (body_ops, local_lexical_bindings) = output
            .ir1
            .ops
            .iter()
            .find_map(|op| match op {
                Ir1Op::DeclareFunction {
                    body_ops,
                    local_lexical_bindings,
                    ..
                }
                | Ir1Op::CreateFunction {
                    body_ops,
                    local_lexical_bindings,
                    ..
                } => Some((body_ops, local_lexical_bindings)),
                _ => None,
            })
            .expect("source must contain one deferred function body");
        let matching_bindings = local_lexical_bindings
            .iter()
            .filter(|binding| binding.name == expected_name)
            .collect::<Vec<_>>();
        assert_eq!(
            matching_bindings.len(),
            1,
            "{expected_name} must have exactly one exact-ID metadata entry"
        );
        let binding = matching_bindings[0];
        assert_eq!(binding.kind, expected_binding_kind);
        let initializer_indices = body_ops
            .iter()
            .enumerate()
            .filter_map(|(index, op)| {
                matches!(
                    op,
                    Ir1Op::StoreBinding { binding_id }
                        | Ir1Op::InitializeBinding { binding_id }
                        if *binding_id == binding.binding_id
                )
                .then_some(index)
            })
            .collect::<Vec<_>>();
        let assignment_indices = body_ops
            .iter()
            .enumerate()
            .filter_map(|(index, op)| {
                matches!(
                    op,
                    Ir1Op::AssignOp { binding_id, .. }
                        if *binding_id == binding.binding_id
                )
                .then_some(index)
            })
            .collect::<Vec<_>>();
        assert_eq!(initializer_indices.len(), 1);
        assert_eq!(assignment_indices.len(), 1);
        assert_eq!(
            assignment_indices[0] < initializer_indices[0],
            assignment_before_init,
            "IR1 metadata and source-order operations must agree"
        );

        let function_desc = output
            .ir3
            .instructions
            .iter()
            .find_map(|instruction| match instruction {
                Ir3Instruction::CreateClosure { function_index, .. }
                | Ir3Instruction::CreateArrowClosure { function_index, .. } => {
                    output.ir3.function_table.get(*function_index as usize)
                }
                _ => None,
            })
            .expect("source must create a deferred closure body");
        let function_body = &output.ir3.instructions[function_desc.entry as usize..];
        let expected_runtime_name = runtime_lexical_binding_name(binding.binding_id, expected_name);
        let name_pool_index = u32::try_from(
            output
                .ir3
                .constant_pool
                .iter()
                .position(|value| value == expected_runtime_name.as_str())
                .expect("exact ID-qualified runtime lexical name must be interned"),
        )
        .expect("constant-pool index must fit u32");
        let declarations = function_body
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| match instruction {
                Ir3Instruction::DeclareBinding {
                    name_pool_index: candidate,
                    kind,
                } if *candidate == name_pool_index => Some((index, *kind)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(declarations.len(), 1);
        let (declare_index, actual_kind) = declarations[0];
        assert_eq!(actual_kind, expected_runtime_kind);
        let init_indices = function_body
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                matches!(
                    instruction,
                    Ir3Instruction::InitBinding {
                        name_pool_index: candidate,
                        ..
                    } if *candidate == name_pool_index
                )
                .then_some(index)
            })
            .collect::<Vec<_>>();
        let assign_indices = function_body
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                matches!(
                    instruction,
                    Ir3Instruction::StoreScoped {
                        name_pool_index: candidate,
                        ..
                    } if *candidate == name_pool_index
                )
                .then_some(index)
            })
            .collect::<Vec<_>>();

        assert_eq!(init_indices.len(), 1);
        assert_eq!(assign_indices.len(), 1);
        assert!(declare_index < init_indices[0]);
        assert!(declare_index < assign_indices[0]);
        assert_eq!(
            assign_indices[0] < init_indices[0],
            assignment_before_init,
            "deferred TDZ assignment ordering must follow source control flow"
        );
    }
}

#[test]
fn classify_ir1_op_await_is_read_effect() {
    let (boundary, cap, _flow) = classify_ir1_op(&Ir1Op::Await);
    assert_eq!(boundary, EffectBoundary::ReadEffect);
    assert!(cap.is_none());
}

#[test]
fn classify_ir1_op_throw_is_read_effect() {
    let (boundary, cap, _flow) = classify_ir1_op(&Ir1Op::Throw);
    assert_eq!(boundary, EffectBoundary::ReadEffect);
    assert!(cap.is_none());
}

#[test]
fn classify_ir1_op_call_is_pure() {
    let (boundary, cap, flow) = classify_ir1_op(&Ir1Op::Call { arg_count: 1 });
    assert_eq!(boundary, EffectBoundary::Pure);
    assert!(cap.is_none());
    assert!(flow.is_none());
}

#[test]
fn classify_ir1_op_load_literal_is_pure() {
    let (boundary, cap, _flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
        value: Ir1Literal::Integer(42),
    });
    assert_eq!(boundary, EffectBoundary::Pure);
    assert!(cap.is_none());
}

// -- Enrichment: PearlTower 2026-03-02 --

#[test]
fn sink_label_to_clearance_public_is_never_sink() {
    assert_eq!(
        sink_label_to_clearance(&Label::Public),
        Clearance::NeverSink
    );
}

#[test]
fn sink_label_to_clearance_internal_is_restricted() {
    assert_eq!(
        sink_label_to_clearance(&Label::Internal),
        Clearance::RestrictedSink
    );
}

#[test]
fn sink_label_to_clearance_confidential_is_audited() {
    assert_eq!(
        sink_label_to_clearance(&Label::Confidential),
        Clearance::AuditedSink
    );
}

#[test]
fn sink_label_to_clearance_secret_is_sealed() {
    assert_eq!(
        sink_label_to_clearance(&Label::Secret),
        Clearance::SealedSink
    );
}

#[test]
fn sink_label_to_clearance_top_secret_is_open() {
    assert_eq!(
        sink_label_to_clearance(&Label::TopSecret),
        Clearance::OpenSink
    );
}

#[test]
fn sink_label_to_clearance_custom_level_0_is_never() {
    let label = Label::Custom {
        name: "low".to_string(),
        level: 0,
    };
    assert_eq!(sink_label_to_clearance(&label), Clearance::NeverSink);
}

#[test]
fn sink_label_to_clearance_custom_level_1_is_restricted() {
    let label = Label::Custom {
        name: "mid".to_string(),
        level: 1,
    };
    assert_eq!(sink_label_to_clearance(&label), Clearance::RestrictedSink);
}

#[test]
fn sink_label_to_clearance_custom_level_2_is_audited() {
    let label = Label::Custom {
        name: "high".to_string(),
        level: 2,
    };
    assert_eq!(sink_label_to_clearance(&label), Clearance::AuditedSink);
}

#[test]
fn sink_label_to_clearance_custom_level_3_is_sealed() {
    let label = Label::Custom {
        name: "critical".to_string(),
        level: 3,
    };
    assert_eq!(sink_label_to_clearance(&label), Clearance::SealedSink);
}

#[test]
fn sink_label_to_clearance_custom_level_4_plus_is_open() {
    for level in [4, 5, 100, u32::MAX] {
        let label = Label::Custom {
            name: format!("lvl{level}"),
            level,
        };
        assert_eq!(sink_label_to_clearance(&label), Clearance::OpenSink);
    }
}

#[test]
fn flow_capability_supports_declassification_true_cases() {
    let cases = [
        CapabilityTag("ifc.declassify".to_string()),
        CapabilityTag("ifc.declassification.route".to_string()),
        CapabilityTag("DECLASSIFY".to_string()),
        CapabilityTag("auto_declassification".to_string()),
    ];
    for cap in &cases {
        assert!(
            flow_capability_supports_declassification(cap),
            "expected true for {:?}",
            cap
        );
    }
}

#[test]
fn flow_capability_supports_declassification_false_cases() {
    let cases = [
        CapabilityTag("hostcall.invoke".to_string()),
        CapabilityTag("module.import".to_string()),
        CapabilityTag("ifc.check_flow".to_string()),
        CapabilityTag("network.write".to_string()),
    ];
    for cap in &cases {
        assert!(
            !flow_capability_supports_declassification(cap),
            "expected false for {:?}",
            cap
        );
    }
}

#[test]
fn runtime_checkpoint_reason_dynamic_capability() {
    let flow = FlowAnnotation {
        data_label: Label::Public,
        sink_clearance: Label::Public,
        declassification_required: false,
    };
    let cap = CapabilityTag("hostcall.invoke".to_string());
    assert_eq!(runtime_checkpoint_reason(&flow, &cap), "dynamic_capability");
}

#[test]
fn runtime_checkpoint_reason_ambiguous_data_label() {
    let flow = FlowAnnotation {
        data_label: Label::Custom {
            name: "pii".to_string(),
            level: 2,
        },
        sink_clearance: Label::Public,
        declassification_required: false,
    };
    let cap = CapabilityTag("ifc.check_flow".to_string());
    assert_eq!(
        runtime_checkpoint_reason(&flow, &cap),
        "ambiguous_data_label"
    );
}

#[test]
fn runtime_checkpoint_reason_ambiguous_sink_clearance() {
    let flow = FlowAnnotation {
        data_label: Label::Public,
        sink_clearance: Label::Custom {
            name: "audit_sink".to_string(),
            level: 1,
        },
        declassification_required: false,
    };
    let cap = CapabilityTag("ifc.check_flow".to_string());
    assert_eq!(
        runtime_checkpoint_reason(&flow, &cap),
        "ambiguous_sink_clearance"
    );
}

#[test]
fn runtime_checkpoint_reason_fallback() {
    let flow = FlowAnnotation {
        data_label: Label::Internal,
        sink_clearance: Label::Internal,
        declassification_required: false,
    };
    let cap = CapabilityTag("ifc.check_flow".to_string());
    assert_eq!(
        runtime_checkpoint_reason(&flow, &cap),
        "runtime_checkpoint_required"
    );
}

#[test]
fn flow_proof_artifact_entry_serde_roundtrip() {
    let entry = FlowProofArtifactEntry {
        op_index: 7,
        source_label: Label::Confidential,
        sink_clearance: Label::Internal,
        capability: Some("hostcall.invoke".to_string()),
        proof_method: ProofMethod::StaticAnalysis,
    };
    let json = serde_json::to_string(&entry).expect("serialize derived Serialize");
    let back: FlowProofArtifactEntry =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(entry, back);
}

#[test]
fn denied_flow_artifact_entry_serde_roundtrip() {
    let entry = DeniedFlowArtifactEntry {
        op_index: 3,
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        capability: None,
        reason: "lattice violation".to_string(),
        error_code: "FE-LOWER-IFC-0001".to_string(),
    };
    let json = serde_json::to_string(&entry).expect("serialize derived Serialize");
    let back: DeniedFlowArtifactEntry =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(entry, back);
}

#[test]
fn required_declassification_artifact_entry_serde_roundtrip() {
    let entry = RequiredDeclassificationArtifactEntry {
        op_index: 5,
        source_label: Label::Confidential,
        sink_clearance: Label::Public,
        capability: Some("ifc.declassify".to_string()),
        obligation_id: "obl-42".to_string(),
        decision_contract_id: "decision-42".to_string(),
        declassification_route_ref: Some("route-42".to_string()),
        requires_operator_approval: true,
        receipt_linkage_required: true,
        replay_command_hint: REQUIRED_DECLASSIFICATION_REPLAY_COMMAND_HINT.to_string(),
    };
    let json = serde_json::to_string(&entry).expect("serialize derived Serialize");
    let back: RequiredDeclassificationArtifactEntry =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(entry, back);
}

#[test]
fn runtime_checkpoint_artifact_entry_serde_roundtrip() {
    let entry = RuntimeCheckpointArtifactEntry {
        op_index: 9,
        source_label: Label::Internal,
        sink_clearance: Label::Custom {
            name: "audit".to_string(),
            level: 2,
        },
        capability: Some("hostcall.invoke".to_string()),
        reason: "dynamic_capability".to_string(),
    };
    let json = serde_json::to_string(&entry).expect("serialize derived Serialize");
    let back: RuntimeCheckpointArtifactEntry =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(entry, back);
}

#[test]
fn lowering_pipeline_error_display_flow_lattice_failure() {
    let err = LoweringPipelineError::FlowLatticeFailure {
        detail: "lattice merge diverged".to_string(),
    };
    let display = err.to_string();
    assert!(
        display.contains("lattice merge diverged"),
        "FlowLatticeFailure display should contain detail: {display}"
    );
}

#[test]
fn runtime_checkpoint_artifact_entry_confidential_roundtrip() {
    let entry = RuntimeCheckpointArtifactEntry {
        op_index: 7,
        source_label: Label::Confidential,
        sink_clearance: Label::Public,
        capability: Some("ifc.check_flow".to_string()),
        reason: "checkpoint serde roundtrip test".to_string(),
    };
    let json = serde_json::to_string(&entry).expect("serialize derived Serialize");
    let back: RuntimeCheckpointArtifactEntry =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(entry, back);
}

#[test]
fn flow_requires_runtime_checkpoint_confidential() {
    let flow = FlowAnnotation {
        data_label: Label::Confidential,
        sink_clearance: Label::Custom {
            name: "log".to_string(),
            level: 0,
        },
        declassification_required: false,
    };
    let cap = CapabilityTag("ifc.check_flow".to_string());
    assert!(flow_requires_runtime_checkpoint(Some(&flow), &cap));
}

#[test]
fn flow_requires_runtime_checkpoint_static_safe() {
    let flow = FlowAnnotation {
        data_label: Label::Public,
        sink_clearance: Label::Public,
        declassification_required: false,
    };
    let cap = CapabilityTag("ifc.check_flow".to_string());
    assert!(!flow_requires_runtime_checkpoint(Some(&flow), &cap));
}

// -- Optional chaining lowering tests (bd-1lsy.2.10.1) ------------------

#[test]
fn optional_member_static_property_lowers_to_ir1() {
    // obj?.prop
    let ir0 = expr_ir0(Expression::OptionalMember {
        object: Box::new(Expression::Identifier("obj".to_string())),
        property: Box::new(Expression::Identifier("prop".to_string())),
        computed: false,
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("optional member should lower");
    // Must contain JumpIfNullish for the short-circuit path.
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::JumpIfNullish { .. })),
        "optional member must emit JumpIfNullish"
    );
    // Must contain GetProperty for the non-nullish path.
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::GetProperty { .. })),
        "optional member must emit GetProperty"
    );
    // Must contain LoadLiteral Undefined for the nullish path.
    assert!(
        result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined
            }
        )),
        "optional member must emit LoadLiteral Undefined"
    );
}

#[test]
fn optional_member_computed_property_lowers_to_ir1() {
    // arr?.[0]
    let ir0 = expr_ir0(Expression::OptionalMember {
        object: Box::new(Expression::Identifier("arr".to_string())),
        property: Box::new(Expression::NumericLiteral(0)),
        computed: true,
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("optional computed member should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::JumpIfNullish { .. })),
        "computed optional member must emit JumpIfNullish"
    );
    assert!(
        result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::GetProperty {
                key: Ir1PropertyKey::Dynamic
            }
        )),
        "computed optional member must emit dynamic GetProperty"
    );
}

#[test]
fn optional_call_lowers_to_ir1() {
    // fn?.()
    let ir0 = expr_ir0(Expression::OptionalCall {
        callee: Box::new(Expression::Identifier("fn_val".to_string())),
        arguments: vec![],
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("optional call should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::JumpIfNullish { .. })),
        "optional call must emit JumpIfNullish"
    );
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Call { arg_count: 0 })),
        "optional call must emit Call with 0 args"
    );
    assert!(
        result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined
            }
        )),
        "optional call must emit LoadLiteral Undefined"
    );
}

#[test]
fn optional_call_with_args_lowers_to_ir1() {
    // maybe?.(1, 2)
    let ir0 = expr_ir0(Expression::OptionalCall {
        callee: Box::new(Expression::Identifier("maybe".to_string())),
        arguments: vec![Expression::NumericLiteral(1), Expression::NumericLiteral(2)],
        span: None,
    });
    let result = lower_ir0_to_ir1(&ir0).expect("optional call with args should lower");
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Call { arg_count: 2 })),
        "optional call must emit Call with 2 args"
    );
}

#[test]
fn optional_member_lowers_through_full_pipeline() {
    // obj?.prop — full IR0 → IR3 pipeline
    let ir0 = expr_ir0(Expression::OptionalMember {
        object: Box::new(Expression::Identifier("obj".to_string())),
        property: Box::new(Expression::Identifier("prop".to_string())),
        computed: false,
        span: None,
    });
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0→IR1");
    let ir2 = lower_ir1_to_ir2(&ir1.module).expect("IR1→IR2");
    let ir3 = lower_ir2_to_ir3(&ir2.module).expect("IR2→IR3");
    // IR3 should contain JumpIfNullish.
    assert!(
        ir3.module
            .instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::JumpIfNullish { .. })),
        "IR3 must contain JumpIfNullish for optional member"
    );
    // IR3 should contain GetProperty.
    assert!(
        ir3.module
            .instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::GetProperty { .. })),
        "IR3 must contain GetProperty for optional member"
    );
    // IR3 should contain LoadUndefined.
    assert!(
        ir3.module
            .instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::LoadUndefined { .. })),
        "IR3 must contain LoadUndefined for nullish short-circuit"
    );
}

#[test]
fn optional_call_lowers_through_full_pipeline() {
    // fn?.() — full IR0 → IR3 pipeline
    let ir0 = expr_ir0(Expression::OptionalCall {
        callee: Box::new(Expression::Identifier("fn_val".to_string())),
        arguments: vec![Expression::NumericLiteral(42)],
        span: None,
    });
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0→IR1");
    let ir2 = lower_ir1_to_ir2(&ir1.module).expect("IR1→IR2");
    let ir3 = lower_ir2_to_ir3(&ir2.module).expect("IR2→IR3");
    assert!(
        ir3.module
            .instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::JumpIfNullish { .. })),
        "IR3 must contain JumpIfNullish for optional call"
    );
    // Optional calls must lower to a real call instruction at IR3.
    assert!(
        ir3.module
            .instructions
            .iter()
            .any(|i| matches!(i, Ir3Instruction::Call { .. })),
        "IR3 must contain Call for optional call"
    );
}

#[test]
fn nested_optional_member_chain_lowers() {
    // a?.b?.c — nested optional members
    let inner = Expression::OptionalMember {
        object: Box::new(Expression::Identifier("a".to_string())),
        property: Box::new(Expression::Identifier("b".to_string())),
        computed: false,
        span: None,
    };
    let ir0 = expr_ir0(Expression::OptionalMember {
        object: Box::new(inner),
        property: Box::new(Expression::Identifier("c".to_string())),
        computed: false,
        span: None,
    });
    let ir1 = lower_ir0_to_ir1(&ir0).expect("nested optional chain should lower");
    // Should emit two JumpIfNullish ops (one per ?. in the chain).
    let nullish_count = ir1
        .module
        .ops
        .iter()
        .filter(|op| matches!(op, Ir1Op::JumpIfNullish { .. }))
        .count();
    assert_eq!(
        nullish_count, 2,
        "nested chain a?.b?.c must emit 2 JumpIfNullish ops"
    );
}

// -----------------------------------------------------------------------
// Destructuring completeness tests (bd-6a61n.1.5)
// -----------------------------------------------------------------------

#[test]
fn object_destructuring_emits_get_property() {
    // const { a, b } = source
    let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::ObjectPattern(vec![
                ObjectPatternProperty {
                    key: Expression::Identifier("a".into()),
                    value: BindingPattern::Identifier("a".into()),
                    computed: false,
                    shorthand: true,
                },
                ObjectPatternProperty {
                    key: Expression::Identifier("b".into()),
                    value: BindingPattern::Identifier("b".into()),
                    computed: false,
                    shorthand: true,
                },
            ]),
            initializer: Some(Expression::Identifier("source".into())),
            span: span(),
        }],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("should lower");
    let get_props: Vec<_> = result
        .module
        .ops
        .iter()
        .filter_map(|op| {
            if let Ir1Op::GetProperty {
                key: Ir1PropertyKey::Static(k),
            } = op
            {
                k.as_str()
            } else {
                None
            }
        })
        .collect();
    assert!(
        get_props.contains(&"a"),
        "should emit GetProperty for 'a', got: {get_props:?}"
    );
    assert!(
        get_props.contains(&"b"),
        "should emit GetProperty for 'b', got: {get_props:?}"
    );
}

#[test]
fn object_destructuring_rename_emits_correct_key() {
    // const { a: x } = source — key is "a", binding is "x"
    let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
                key: Expression::Identifier("a".into()),
                value: BindingPattern::Identifier("x".into()),
                computed: false,
                shorthand: false,
            }]),
            initializer: Some(Expression::Identifier("source".into())),
            span: span(),
        }],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("should lower");
    let get_props: Vec<_> = result
        .module
        .ops
        .iter()
        .filter_map(|op| {
            if let Ir1Op::GetProperty {
                key: Ir1PropertyKey::Static(k),
            } = op
            {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();
    assert!(
        get_props.iter().any(|key| key == "a"),
        "should emit GetProperty for key 'a', got: {get_props:?}"
    );
    // Verify binding "x" exists.
    let scope = result.module.scopes.first().expect("root scope");
    assert!(scope.bindings.iter().any(|b| b.name == "x"));
}

#[test]
fn object_destructuring_preserves_exact_static_key_bd_b12xs_6() {
    let exact = JsString::from_code_units(&[0xD800]);
    let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
                key: Expression::StringLiteral(exact.clone()),
                value: BindingPattern::Identifier("value".into()),
                computed: false,
                shorthand: false,
            }]),
            initializer: Some(Expression::Identifier("source".into())),
            span: span(),
        }],
        span: span(),
    })]);

    let result = lower_ir0_to_ir1(&ir0).expect("exact object pattern key should lower");
    assert!(result.module.ops.iter().any(|op| matches!(
        op,
        Ir1Op::GetProperty {
            key: Ir1PropertyKey::Static(key)
        } if key == &exact
    )));
}

#[test]
fn array_destructuring_emits_iterator_acquisition_and_steps() {
    // const [a, b] = source
    let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::ArrayPattern(vec![
                Some(BindingPattern::Identifier("a".into())),
                Some(BindingPattern::Identifier("b".into())),
            ]),
            initializer: Some(Expression::Identifier("source".into())),
            span: span(),
        }],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("should lower");
    let operations = &result.module.ops;
    let protocol: Vec<_> = operations
        .iter()
        .filter_map(|op| match op {
            Ir1Op::HostCall { capability, .. }
                if capability.starts_with("builtin:DestructureIterator") =>
            {
                Some(capability.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        protocol,
        vec![
            "builtin:DestructureIteratorInit",
            "builtin:DestructureIteratorNext",
            "builtin:DestructureIteratorDone",
            "builtin:DestructureIteratorNext",
            "builtin:DestructureIteratorDone"
        ]
    );
    assert!(
        !operations
            .iter()
            .any(|op| matches!(op, Ir1Op::GetProperty { .. } | Ir1Op::ArraySlice)),
        "array patterns must never fall back to indexed Get or eager slicing"
    );
    let acquisitions = protocol
        .iter()
        .filter(|cap| **cap == "builtin:DestructureIteratorInit")
        .count();
    for reason in [
        IteratorCloseReason::Break,
        IteratorCloseReason::Throw,
        IteratorCloseReason::Return,
    ] {
        assert_eq!(
            operations
                .iter()
                .filter(|op| matches!(op, Ir1Op::IteratorClose { reason: r } if *r == reason))
                .count(),
            acquisitions,
            "every nested pattern owns a normal, throw and return close path"
        );
    }
}

#[test]
fn array_destructuring_with_hole() {
    // const [, b] = source — first element is a hole
    let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::ArrayPattern(vec![
                None, // hole
                Some(BindingPattern::Identifier("b".into())),
            ]),
            initializer: Some(Expression::Identifier("source".into())),
            span: span(),
        }],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("should lower");
    let operations = &result.module.ops;
    let protocol: Vec<_> = operations
        .iter()
        .filter_map(|op| match op {
            Ir1Op::HostCall { capability, .. }
                if capability.starts_with("builtin:DestructureIterator") =>
            {
                Some(capability.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        protocol,
        vec![
            "builtin:DestructureIteratorInit",
            "builtin:DestructureIteratorElide",
            "builtin:DestructureIteratorDone",
            "builtin:DestructureIteratorNext",
            "builtin:DestructureIteratorDone"
        ]
    );
    assert!(
        !operations
            .iter()
            .any(|op| matches!(op, Ir1Op::GetProperty { .. } | Ir1Op::ArraySlice)),
        "array patterns must never fall back to indexed Get or eager slicing"
    );
    let acquisitions = protocol
        .iter()
        .filter(|cap| **cap == "builtin:DestructureIteratorInit")
        .count();
    for reason in [
        IteratorCloseReason::Break,
        IteratorCloseReason::Throw,
        IteratorCloseReason::Return,
    ] {
        assert_eq!(
            operations
                .iter()
                .filter(|op| matches!(op, Ir1Op::IteratorClose { reason: r } if *r == reason))
                .count(),
            acquisitions,
            "every nested pattern owns a normal, throw and return close path"
        );
    }
}

#[test]
fn nested_object_destructuring_emits_nested_get_property() {
    // const { a: { b } } = source
    let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
                key: Expression::Identifier("a".into()),
                value: BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
                    key: Expression::Identifier("b".into()),
                    value: BindingPattern::Identifier("b".into()),
                    computed: false,
                    shorthand: true,
                }]),
                computed: false,
                shorthand: false,
            }]),
            initializer: Some(Expression::Identifier("source".into())),
            span: span(),
        }],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("should lower");
    let get_props: Vec<_> = result
        .module
        .ops
        .iter()
        .filter_map(|op| {
            if let Ir1Op::GetProperty {
                key: Ir1PropertyKey::Static(k),
            } = op
            {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();
    assert!(
        get_props.iter().any(|key| key == "a"),
        "should emit GetProperty for outer key 'a'"
    );
    assert!(
        get_props.iter().any(|key| key == "b"),
        "should emit GetProperty for nested key 'b'"
    );
}

#[test]
fn nested_array_destructuring_emits_nested_iterators() {
    // const [, [b]] = source — nested array destructuring
    let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::ArrayPattern(vec![
                None,
                Some(BindingPattern::ArrayPattern(vec![Some(
                    BindingPattern::Identifier("b".into()),
                )])),
            ]),
            initializer: Some(Expression::Identifier("source".into())),
            span: span(),
        }],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("should lower");
    let operations = &result.module.ops;
    let protocol: Vec<_> = operations
        .iter()
        .filter_map(|op| match op {
            Ir1Op::HostCall { capability, .. }
                if capability.starts_with("builtin:DestructureIterator") =>
            {
                Some(capability.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        protocol,
        vec![
            "builtin:DestructureIteratorInit",
            "builtin:DestructureIteratorElide",
            "builtin:DestructureIteratorDone",
            "builtin:DestructureIteratorNext",
            "builtin:DestructureIteratorDone",
            "builtin:DestructureIteratorInit",
            "builtin:DestructureIteratorNext",
            "builtin:DestructureIteratorDone"
        ]
    );
    assert!(
        !operations
            .iter()
            .any(|op| matches!(op, Ir1Op::GetProperty { .. } | Ir1Op::ArraySlice)),
        "array patterns must never fall back to indexed Get or eager slicing"
    );
    let acquisitions = protocol
        .iter()
        .filter(|cap| **cap == "builtin:DestructureIteratorInit")
        .count();
    for reason in [
        IteratorCloseReason::Break,
        IteratorCloseReason::Throw,
        IteratorCloseReason::Return,
    ] {
        assert_eq!(
            operations
                .iter()
                .filter(|op| matches!(op, Ir1Op::IteratorClose { reason: r } if *r == reason))
                .count(),
            acquisitions,
            "every nested pattern owns a normal, throw and return close path"
        );
    }
}

#[test]
fn destructuring_assignment_pattern_emits_default_check() {
    // const { a = 1 } = source
    let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
                key: Expression::Identifier("a".into()),
                value: BindingPattern::AssignmentPattern {
                    left: Box::new(BindingPattern::Identifier("a".into())),
                    right: Expression::NumericLiteral(1),
                },
                computed: false,
                shorthand: true,
            }]),
            initializer: Some(Expression::Identifier("source".into())),
            span: span(),
        }],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("should lower");
    assert!(
        result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::BinaryOp {
                operator: BinaryOperator::StrictEqual
            }
        )),
        "should emit strict-equal check against undefined"
    );
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::JumpIfTruthy { .. })),
        "should emit JumpIfTruthy for default branch"
    );
    assert!(
        result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(1)
            }
        )),
        "should load the default literal"
    );
}

#[test]
fn array_destructuring_assignment_pattern_emits_default_check() {
    // const [a = 2] = source
    let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::ArrayPattern(vec![Some(BindingPattern::AssignmentPattern {
                left: Box::new(BindingPattern::Identifier("a".into())),
                right: Expression::NumericLiteral(2),
            })]),
            initializer: Some(Expression::Identifier("source".into())),
            span: span(),
        }],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("should lower");
    assert!(
        result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::BinaryOp {
                operator: BinaryOperator::StrictEqual
            }
        )),
        "should emit strict-equal check against undefined"
    );
    assert!(
        result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::JumpIfTruthy { .. })),
        "should emit JumpIfTruthy for default branch"
    );
    assert!(
        result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(2)
            }
        )),
        "should load the default literal"
    );
}

#[test]
fn destructuring_allocates_all_named_bindings() {
    // const { a, b: c } = source — should allocate both "a" and "c"
    let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::ObjectPattern(vec![
                ObjectPatternProperty {
                    key: Expression::Identifier("a".into()),
                    value: BindingPattern::Identifier("a".into()),
                    computed: false,
                    shorthand: true,
                },
                ObjectPatternProperty {
                    key: Expression::Identifier("b".into()),
                    value: BindingPattern::Identifier("c".into()),
                    computed: false,
                    shorthand: false,
                },
            ]),
            initializer: Some(Expression::Identifier("source".into())),
            span: span(),
        }],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("should lower");
    let scope = result.module.scopes.first().expect("root scope");
    let names: Vec<&str> = scope.bindings.iter().map(|b| b.name.as_str()).collect();
    assert!(names.contains(&"a"), "binding 'a' should exist");
    assert!(names.contains(&"c"), "binding 'c' should exist");
}

#[test]
fn destructuring_uses_internal_source_binding() {
    let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::ObjectPattern(vec![
                ObjectPatternProperty {
                    key: Expression::Identifier("a".into()),
                    value: BindingPattern::Identifier("a".into()),
                    computed: false,
                    shorthand: true,
                },
                ObjectPatternProperty {
                    key: Expression::Identifier("b".into()),
                    value: BindingPattern::Identifier("b".into()),
                    computed: false,
                    shorthand: true,
                },
            ]),
            initializer: Some(Expression::Identifier("source".into())),
            span: span(),
        }],
        span: span(),
    })]);
    let result = lower_ir0_to_ir1(&ir0).expect("should lower");
    let scope = result.module.scopes.first().expect("root scope");
    let internal_source = scope
        .bindings
        .iter()
        .find(|binding| binding.name.contains("destructure_source"))
        .expect("destructuring should allocate an internal source binding");
    let a_binding = scope
        .bindings
        .iter()
        .find(|binding| binding.name == "a")
        .expect("binding a should exist");
    assert_ne!(
        internal_source.binding_id, a_binding.binding_id,
        "source binding must not alias the first user binding"
    );
    assert!(
        result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::LoadBinding { binding_id }
                if *binding_id == internal_source.binding_id
        )),
        "destructuring should read properties from the internal source binding"
    );
}

#[test]
fn oversized_ast_fails_preallocation_budget_for_ops() {
    use crate::ast::{ExpressionStatement, ParseGoal, SourceSpan, SyntaxTree};
    use crate::ir_contract::{Ir0Module, IrHeader, IrLevel, IrSchemaVersion};

    // Create an IR0 module with a large body that would exceed MAX_PREALLOC_OPS
    // MAX_PREALLOC_OPS = 1_000_000, so we need body.len() * 8 > 1_000_000
    // Therefore body.len() > 125_000
    let large_body_size = 130_000; // Well over the threshold

    let large_body: Vec<Statement> = (0..large_body_size)
        .map(|i| {
            Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral(format!("stmt_{}", i).into()),
                span: SourceSpan::new(0, 10, 1, 1, 1, 11),
            })
        })
        .collect();

    let ir0 = Ir0Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir0,
            source_hash: None,
            source_label: "test_oversized".to_string(),
        },
        script_strict: None,
        tree: SyntaxTree {
            goal: ParseGoal::Script,
            body: large_body,
            span: SourceSpan::new(0, 100, 1, 1, 1, 101),
        },
    };

    // Attempt to lower - should fail with AllocationBudgetExceeded, not panic
    let result = lower_ir0_to_ir1(&ir0);
    match result {
        Err(LoweringPipelineError::AllocationBudgetExceeded { requested, limit }) => {
            assert_eq!(limit, MAX_PREALLOC_OPS);
            assert_eq!(requested, large_body_size * 8);
            assert!(requested > limit, "requested should exceed limit");
        }
        // SAFETY: Test validates allocation budget exceeded error for large allocations
        other => panic!("Expected AllocationBudgetExceeded error, got: {:?}", other),
    }
}

#[test]
fn oversized_ast_fails_preallocation_budget_for_bindings() {
    use crate::ast::{ExpressionStatement, ParseGoal, SourceSpan, SyntaxTree};
    use crate::ir_contract::{Ir0Module, IrHeader, IrLevel, IrSchemaVersion};

    // Create an IR0 module with a large body that would exceed MAX_PREALLOC_BINDINGS
    // MAX_PREALLOC_BINDINGS = 250_000, so we need body.len() * 4 > 250_000
    // Therefore body.len() > 62_500
    let large_body_size = 65_000; // Well over the threshold

    let large_body: Vec<Statement> = (0..large_body_size)
        .map(|i| {
            Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral(format!("stmt_{}", i).into()),
                span: SourceSpan::new(0, 10, 1, 1, 1, 11),
            })
        })
        .collect();

    let ir0 = Ir0Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir0,
            source_hash: None,
            source_label: "test_oversized_bindings".to_string(),
        },
        script_strict: None,
        tree: SyntaxTree {
            goal: ParseGoal::Script,
            body: large_body,
            span: SourceSpan::new(0, 100, 1, 1, 1, 101),
        },
    };

    // Attempt to lower - should fail with AllocationBudgetExceeded for ops first
    // (since ops budget is checked first and will trigger at 65_000 * 8 = 520_000 > 1_000_000 is false,
    //  but bindings budget is 65_000 * 4 = 260_000 > 250_000 is true)

    // Actually, let me recalculate: 65_000 * 8 = 520_000 < 1_000_000 (ops OK)
    // 65_000 * 4 = 260_000 > 250_000 (bindings exceed) - so bindings should fail
    let result = lower_ir0_to_ir1(&ir0);
    match result {
        Err(LoweringPipelineError::AllocationBudgetExceeded { requested, limit }) => {
            assert_eq!(limit, MAX_PREALLOC_BINDINGS);
            assert_eq!(requested, large_body_size * 4);
            assert!(requested > limit, "requested should exceed limit");
        }
        // SAFETY: Test validates allocation budget exceeded error for large binding allocation
        other => panic!(
            "Expected AllocationBudgetExceeded error for bindings, got: {:?}",
            other
        ),
    }
}

#[test]
fn function_body_match_arms_handle_all_valid_ir1_ops() {
    // Regression test for bd-2zyj5: Ensure catch-all replacement doesn't break existing functionality
    // Test that LoadLiteral (one of the explicitly handled operations) works correctly in function bodies
    use crate::ast::{BlockStatement, FunctionDeclaration, ParseGoal, SyntaxTree};
    use crate::ir_contract::{Ir0Module, IrHeader, IrLevel, IrSchemaVersion};

    let function_with_literal = Statement::FunctionDeclaration(FunctionDeclaration {
        name: Some("testFunc".to_string()),
        params: vec![],
        body: BlockStatement {
            body: vec![Statement::Return(ReturnStatement {
                argument: Some(Expression::NumericLiteral(42)),
                span: span(),
            })],
            span: span(),
        },
        is_async: false,
        is_generator: false,
        span: span(),
        source_text: None,
        strict: false,
    });

    let ir0 = Ir0Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir0,
            source_hash: None,
            source_label: "regression_test_bd_2zyj5".to_string(),
        },
        script_strict: None,
        tree: SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![function_with_literal],
            span: span(),
        },
    };

    // This should successfully lower through all IR levels without hitting unreachable!() paths
    let ir1_result = lower_ir0_to_ir1(&ir0);
    assert!(
        ir1_result.is_ok(),
        "IR0->IR1 lowering should succeed with explicit match arms"
    );

    let ir1 = ir1_result
        .expect("operation should succeed for valid inputs")
        .module;
    let ir2_result = lower_ir1_to_ir2(&ir1);
    assert!(ir2_result.is_ok(), "IR1->IR2 lowering should succeed");

    let ir2 = ir2_result
        .expect("operation should succeed for valid inputs")
        .module;
    let ir3_result = lower_ir2_to_ir3(&ir2);
    assert!(
        ir3_result.is_ok(),
        "IR2->IR3 lowering should succeed without hitting unreachable!() for handled operations"
    );

    // Verify that IR3 contains proper instructions for the literal and return
    let ir3 = ir3_result
        .expect("operation should succeed for valid inputs")
        .module;
    assert!(
        !ir3.instructions.is_empty(),
        "IR3 should contain lowered instructions"
    );

    // Should contain at least a LoadInt instruction for the literal 42
    assert!(
        ir3.instructions
            .iter()
            .any(|instr| matches!(instr, Ir3Instruction::LoadInt { value: 42, .. })),
        "IR3 should contain LoadInt instruction for literal 42"
    );
}

// -- Metamorphic Statement Reordering Tests (bd-uz6fe) --

#[test]
fn statement_reordering_equivalence_independent_variable_declarations() {
    // Test that reordering independent statements produces IR that differs only in explicit order
    use crate::ast::{BindingPattern, Expression, VariableDeclaration, VariableDeclarator};

    // Create fixture with independent variable declarations (no data dependencies)
    let stmt_a = Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Let,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::Identifier("a".to_string()),
            initializer: Some(Expression::NumericLiteral(1)),
            span: span(),
        }],
        span: span(),
    });

    let stmt_b = Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Let,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::Identifier("b".to_string()),
            initializer: Some(Expression::NumericLiteral(2)),
            span: span(),
        }],
        span: span(),
    });

    let stmt_c = Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::Identifier("c".to_string()),
            initializer: Some(Expression::NumericLiteral(3)),
            span: span(),
        }],
        span: span(),
    });

    // Original order: [a, b, c]
    let ir0_original = stmt_ir0(vec![stmt_a.clone(), stmt_b.clone(), stmt_c.clone()]);
    let result_original =
        lower_ir0_to_ir1(&ir0_original).expect("original order should lower successfully");

    // Permuted order: [c, a, b]
    let ir0_permuted = stmt_ir0(vec![stmt_c.clone(), stmt_a.clone(), stmt_b.clone()]);
    let result_permuted =
        lower_ir0_to_ir1(&ir0_permuted).expect("permuted order should lower successfully");

    // Both should have the same number of bindings (variables declared)
    assert_eq!(
        result_original.module.scopes[0].bindings.len(),
        result_permuted.module.scopes[0].bindings.len(),
        "Both orderings should declare the same number of bindings"
    );

    // Collect binding names from both results
    let original_binding_names: std::collections::BTreeSet<String> = result_original.module.scopes
        [0]
    .bindings
    .iter()
    .map(|binding| binding.name.clone())
    .collect();

    let permuted_binding_names: std::collections::BTreeSet<String> = result_permuted.module.scopes
        [0]
    .bindings
    .iter()
    .map(|binding| binding.name.clone())
    .collect();

    // The same bindings should be declared in both orderings
    assert_eq!(
        original_binding_names, permuted_binding_names,
        "Both orderings should declare the same binding names"
    );

    // Verify specific expected bindings are present
    assert!(
        original_binding_names.contains("a"),
        "Binding 'a' should be declared"
    );
    assert!(
        original_binding_names.contains("b"),
        "Binding 'b' should be declared"
    );
    assert!(
        original_binding_names.contains("c"),
        "Binding 'c' should be declared"
    );

    // Both should have the same number of ops (excluding order-dependent details)
    assert_eq!(
        result_original.module.ops.len(),
        result_permuted.module.ops.len(),
        "Both orderings should generate the same number of IR1 operations"
    );

    let summarize_ops = |module: &Ir1Module| {
        let mut summary = std::collections::BTreeMap::new();
        for op in &module.ops {
            let key = format!("{:?}", std::mem::discriminant(op));
            *summary.entry(key).or_insert(0usize) += 1;
        }
        summary
    };

    assert_eq!(
        summarize_ops(&result_original.module),
        summarize_ops(&result_permuted.module),
        "Equivalent statement orderings should preserve the same operation mix"
    );
}

#[test]
fn statement_reordering_equivalence_mixed_independent_statements() {
    // Test with mixed statement types (variables and expressions) that are independent
    use crate::ast::{
        BindingPattern, Expression, ExpressionStatement, VariableDeclaration, VariableDeclarator,
    };

    let var_stmt = Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::Identifier("x".to_string()),
            initializer: Some(Expression::NumericLiteral(10)),
            span: span(),
        }],
        span: span(),
    });

    let expr_stmt1 = Statement::Expression(ExpressionStatement {
        expression: Expression::NumericLiteral(100),
        span: span(),
    });

    let expr_stmt2 = Statement::Expression(ExpressionStatement {
        expression: Expression::StringLiteral("test".into()),
        span: span(),
    });

    // Original order: [var, expr1, expr2]
    let ir0_original = stmt_ir0(vec![
        var_stmt.clone(),
        expr_stmt1.clone(),
        expr_stmt2.clone(),
    ]);
    let result_original =
        lower_ir0_to_ir1(&ir0_original).expect("original mixed order should lower successfully");

    // Permuted order: [expr2, var, expr1]
    let ir0_permuted = stmt_ir0(vec![
        expr_stmt2.clone(),
        var_stmt.clone(),
        expr_stmt1.clone(),
    ]);
    let result_permuted =
        lower_ir0_to_ir1(&ir0_permuted).expect("permuted mixed order should lower successfully");

    // Should have same binding structure
    assert_eq!(
        result_original.module.scopes[0].bindings.len(),
        result_permuted.module.scopes[0].bindings.len(),
        "Mixed statement orderings should declare the same number of bindings"
    );

    // Verify the variable binding is present in both
    let original_has_x = result_original.module.scopes[0]
        .bindings
        .iter()
        .any(|binding| binding.name == "x");
    let permuted_has_x = result_permuted.module.scopes[0]
        .bindings
        .iter()
        .any(|binding| binding.name == "x");

    assert!(
        original_has_x && permuted_has_x,
        "Variable 'x' should be declared in both orderings"
    );

    let summarize_ops = |module: &Ir1Module| {
        let mut summary = std::collections::BTreeMap::new();
        for op in &module.ops {
            let key = format!("{:?}", std::mem::discriminant(op));
            *summary.entry(key).or_insert(0usize) += 1;
        }
        summary
    };

    assert_eq!(
        summarize_ops(&result_original.module),
        summarize_ops(&result_permuted.module),
        "Mixed independent statements should preserve the same operation mix"
    );
}

#[test]
fn statement_reordering_preserves_operation_count() {
    // Test that reordering doesn't change the total operation count
    use crate::ast::{BindingPattern, Expression, VariableDeclaration, VariableDeclarator};

    let stmts: Vec<Statement> = (0..5)
        .map(|i| {
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier(format!("var_{}", i)),
                    initializer: Some(Expression::NumericLiteral(i)),
                    span: span(),
                }],
                span: span(),
            })
        })
        .collect();

    // Original order: [0, 1, 2, 3, 4]
    let ir0_original = stmt_ir0(stmts.clone());
    let result_original =
        lower_ir0_to_ir1(&ir0_original).expect("original order should lower successfully");

    // Reverse order: [4, 3, 2, 1, 0]
    let mut stmts_reversed = stmts.clone();
    stmts_reversed.reverse();
    let ir0_reversed = stmt_ir0(stmts_reversed);
    let result_reversed =
        lower_ir0_to_ir1(&ir0_reversed).expect("reversed order should lower successfully");

    // Operation counts should be identical
    assert_eq!(
        result_original.module.ops.len(),
        result_reversed.module.ops.len(),
        "Statement reordering should preserve total operation count"
    );

    // Binding counts should be identical
    assert_eq!(
        result_original.module.scopes[0].bindings.len(),
        result_reversed.module.scopes[0].bindings.len(),
        "Statement reordering should preserve total binding count"
    );

    // All variable names should be present in both
    let original_names: std::collections::BTreeSet<String> = result_original.module.scopes[0]
        .bindings
        .iter()
        .map(|b| b.name.clone())
        .collect();

    let reversed_names: std::collections::BTreeSet<String> = result_reversed.module.scopes[0]
        .bindings
        .iter()
        .map(|b| b.name.clone())
        .collect();

    assert_eq!(
        original_names, reversed_names,
        "Statement reordering should preserve all declared variable names"
    );

    // Verify specific variables are present
    for i in 0..5 {
        let var_name = format!("var_{}", i);
        assert!(
            original_names.contains(&var_name),
            "Variable '{}' should be declared in original order",
            var_name
        );
        assert!(
            reversed_names.contains(&var_name),
            "Variable '{}' should be declared in reversed order",
            var_name
        );
    }
}

// ---------------------------------------------------------------------------
// Snapshot Tests for IR Lowering Pipeline Output
// ---------------------------------------------------------------------------

/// Helper to run full lowering pipeline and serialize output deterministically
fn run_lowering_pipeline_for_golden(ir0: &Ir0Module, test_name: &str) -> LoweringPipelineOutput {
    let context = LoweringContext::new(
        format!("golden_test_{}", test_name),
        format!("decision_{}", test_name),
        format!("policy_{}", test_name),
    );

    lower_ir0_to_ir3(ir0, &context).expect("Lowering pipeline should succeed for golden test")
}

/// Assert the lowering pipeline output matches the committed insta snapshot.
fn assert_lowering_pipeline_snapshot(ir0: &Ir0Module, test_name: &str) {
    let output = run_lowering_pipeline_for_golden(ir0, test_name);
    let actual_json =
        serde_json::to_string_pretty(&output).expect("IR output should serialize to JSON");

    let snapshot_name = format!("lowering_pipeline__{test_name}");
    insta::with_settings!({
        snapshot_path => "../../tests/snapshots",
        prepend_module_to_snapshot => false,
    }, {
        insta::assert_snapshot!(snapshot_name, actual_json);
    });
}

/// Create IR0 for simple arithmetic expression
fn arithmetic_ir0() -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::Binary {
                left: Box::new(Expression::NumericLiteral(42)),
                operator: BinaryOperator::Add,
                right: Box::new(Expression::NumericLiteral(7)),
            },
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "arithmetic.js")
}

/// Create IR0 for if-else conditional
fn conditional_ir0() -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::If(IfStatement {
            condition: Expression::Binary {
                left: Box::new(Expression::Identifier("x".to_string())),
                operator: BinaryOperator::GreaterThan,
                right: Box::new(Expression::NumericLiteral(0)),
            },
            consequent: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("positive".into()),
                span: span(),
            })),
            alternate: Some(Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("non-positive".into()),
                span: span(),
            }))),
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "conditional.js")
}

/// Create IR0 for function declaration
fn function_declaration_ir0() -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::FunctionDeclaration(FunctionDeclaration {
            name: Some("add".to_string()),
            params: vec![
                FunctionParam {
                    pattern: BindingPattern::Identifier("a".to_string()),
                    span: span(),
                },
                FunctionParam {
                    pattern: BindingPattern::Identifier("b".to_string()),
                    span: span(),
                },
            ],
            body: BlockStatement {
                body: vec![Statement::Return(ReturnStatement {
                    argument: Some(Expression::Binary {
                        left: Box::new(Expression::Identifier("a".to_string())),
                        operator: BinaryOperator::Add,
                        right: Box::new(Expression::Identifier("b".to_string())),
                    }),
                    span: span(),
                })],
                span: span(),
            },
            is_generator: false,
            is_async: false,
            span: span(),
            source_text: None,
            strict: false,
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "function.js")
}

/// Create IR0 for variable declarations
fn variable_declarations_ir0() -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("x".to_string()),
                    initializer: Some(Expression::NumericLiteral(10)),
                    span: span(),
                }],
                span: span(),
            }),
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Const,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("message".to_string()),
                    initializer: Some(Expression::StringLiteral("Hello, world!".into())),
                    span: span(),
                }],
                span: span(),
            }),
        ],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "variables.js")
}

/// Create IR0 for simple loop (for statement)
fn loop_ir0() -> Ir0Module {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![Statement::For(ForStatement {
            init: Some(Box::new(Statement::VariableDeclaration(
                VariableDeclaration {
                    kind: VariableDeclarationKind::Let,
                    declarations: vec![VariableDeclarator {
                        pattern: BindingPattern::Identifier("i".to_string()),
                        initializer: Some(Expression::NumericLiteral(0)),
                        span: span(),
                    }],
                    span: span(),
                },
            ))),
            condition: Some(Expression::Binary {
                left: Box::new(Expression::Identifier("i".to_string())),
                operator: BinaryOperator::LessThan,
                right: Box::new(Expression::NumericLiteral(5)),
            }),
            update: Some(Expression::Assignment {
                operator: AssignmentOperator::AddAssign,
                left: Box::new(Expression::Identifier("i".to_string())),
                right: Box::new(Expression::NumericLiteral(1)),
                assignment_strictness: AssignmentStrictness::Sloppy,
            }),
            body: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::Call {
                    callee: Box::new(Expression::Identifier("log".to_string())),
                    arguments: vec![Expression::Identifier("i".to_string())],
                    span: None,
                },
                span: span(),
            })),
            span: span(),
        })],
        span: span(),
    };
    Ir0Module::from_syntax_tree(tree, "loop.js")
}

#[test]
fn golden_arithmetic_lowering() {
    let ir0 = arithmetic_ir0();
    assert_lowering_pipeline_snapshot(&ir0, "arithmetic_expression");
}

#[test]
fn golden_conditional_lowering() {
    let ir0 = conditional_ir0();
    assert_lowering_pipeline_snapshot(&ir0, "if_else_statement");
}

#[test]
fn golden_function_declaration_lowering() {
    let ir0 = function_declaration_ir0();
    assert_lowering_pipeline_snapshot(&ir0, "function_declaration");
}

#[test]
fn golden_variable_declarations_lowering() {
    let ir0 = variable_declarations_ir0();
    assert_lowering_pipeline_snapshot(&ir0, "variable_declarations");
}

#[test]
fn golden_loop_lowering() {
    let ir0 = loop_ir0();
    assert_lowering_pipeline_snapshot(&ir0, "for_loop_statement");
}

#[test]
fn golden_simple_literal_lowering() {
    let ir0 = script_ir0(); // Reuse existing simple literal test
    assert_lowering_pipeline_snapshot(&ir0, "numeric_literal");
}

// MIGRATION TESTS: Unified Authority Algebra
#[test]
fn unified_authority_lattice_creation() {
    let auth1 = create_unified_authority_from_components(
        LabelClass::Public,
        Some("fs_read".to_string()),
        Some(1_000_000), // 1.0 in millionths
    );
    let auth2 = create_unified_authority_from_components(
        LabelClass::Internal,
        Some("fs_write".to_string()),
        Some(500_000), // 0.5 in millionths
    );

    // Test basic lattice operations
    let joined = auth1.join(&auth2);
    assert_eq!(joined.ifc_label, LabelClass::Internal); // Higher security label

    let met = auth1.meet(&auth2);
    assert_eq!(met.ifc_label, LabelClass::Public); // Lower security label
}

#[test]
fn unified_authority_subsumes() {
    let low_auth =
        create_unified_authority_from_components(LabelClass::Public, None, Some(100_000));
    let high_auth = create_unified_authority_from_components(
        LabelClass::Secret,
        Some("global".to_string()),
        Some(2_000_000),
    );

    // High authority should subsume low authority
    assert!(high_auth.subsumes(&low_auth));
    assert!(!low_auth.subsumes(&high_auth));
}

// --- bd-cwfiv: member-target compound assignment must read-modify-write ---
//
// Before the fix, the member-target assignment lowering ignored the operator
// and stored only the RHS, so `o.c += 1` lowered to `o.c = 1`; repeated
// `o.c += 1` never accumulated (each read the original value). These exercise
// the full pipeline via `HybridRouter::eval` and assert the accumulated value.
fn cwfiv_eval(source: &str) -> String {
    let mut engine = crate::HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn member_compound_add_accumulates_in_function_bd_cwfiv() {
    // The exact bd-cwfiv repro: previously yielded "1" (stale read), must be "3".
    assert_eq!(
        cwfiv_eval(
            "let g = function (o) { o.c += 1; o.c += 1; o.c += 1; return o.c; }; g({ c: 0 });"
        ),
        "3"
    );
}

#[test]
fn member_compound_add_accumulates_top_level_bd_cwfiv() {
    assert_eq!(
        cwfiv_eval("let o = { c: 0 }; o.c += 1; o.c += 1; o.c += 1; o.c;"),
        "3"
    );
}

#[test]
fn member_compound_subtract_and_multiply_bd_cwfiv() {
    assert_eq!(cwfiv_eval("let o = { n: 10 }; o.n -= 3; o.n;"), "7");
    assert_eq!(cwfiv_eval("let o = { n: 5 }; o.n *= 4; o.n;"), "20");
}

#[test]
fn member_compound_computed_key_bd_cwfiv() {
    assert_eq!(
        cwfiv_eval(r#"let o = { c: 0 }; o["c"] += 5; o["c"] += 5; o["c"];"#),
        "10"
    );
}

#[test]
fn member_plain_assign_unchanged_bd_cwfiv() {
    // Control: plain `=` must still overwrite (the compound branch must not
    // intercept the Assign operator).
    assert_eq!(cwfiv_eval("let o = { c: 9 }; o.c = 1; o.c;"), "1");
}

// ================================================================
// bd-0qks9: authenticated CommonJS wrapper bindings
// ================================================================

#[test]
fn authenticated_commonjs_context_binds_wrapper_inputs_without_widening_scripts_bd_0qks9() {
    let source = "const req = require;\n\
                  module.exports = [req('./dep.cjs'), exports, __filename, __dirname];\n";
    let tree = crate::parser_api_stability::parse_script(source).expect("parse CommonJS");
    let ir0 = Ir0Module::from_syntax_tree(tree, "/tmp/authenticated-context.cjs");

    let untrusted_error = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("bd-0qks9", "untrusted", "deny-all"),
    )
    .expect_err("a .cjs source label alone must not authenticate require");
    assert!(matches!(
        untrusted_error,
        LoweringPipelineError::AmbientAuthorityViolation {
            required_effect: EffectKind::FsRead,
            ..
        }
    ));

    let output = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("bd-0qks9", "authenticated", "cjs-loader")
            .with_authenticated_commonjs_runtime_bindings(),
    )
    .expect("the authenticated CJS loader context should lower wrapper bindings");

    for name in AUTHENTICATED_COMMONJS_RUNTIME_BINDINGS {
        assert!(
            output.ir1.scopes.iter().any(|scope| {
                scope
                    .bindings
                    .iter()
                    .any(|binding| binding.name == name && binding.kind == BindingKind::Parameter)
            }),
            "authenticated CommonJS input {name} must be a real root binding"
        );
    }
    assert_eq!(
        count_hostcall_deep(&output.ir1.ops, "module:require"),
        0,
        "authenticated require must call the injected wrapper binding, not bypass it through a HostCall"
    );
    assert!(
        ops_deep_match(&output.ir1.ops, &|op| matches!(
            op,
            Ir1Op::Call { .. } | Ir1Op::CallMethod { .. }
        )),
        "the aliased injected require must remain a real callable value"
    );
    assert!(
        output
            .ir2
            .required_capabilities
            .iter()
            .any(|capability| capability.0 == "module_load"),
        "the authenticated wrapper must declare its first-class require authority in IR2"
    );
    assert!(
        output
            .ir3
            .required_capabilities
            .iter()
            .any(|capability| capability.0 == "module_load"),
        "the authenticated wrapper must preserve first-class require authority in IR3"
    );
}

// ================================================================
// bd-xewby: context-sensitive ambient-authority profile
// (benign process shape in trusted eval, deny-all for untrusted)
// ================================================================

fn lower_script_with_grant_bd_xewby(
    source: &str,
    grant: AmbientAuthorityGrant,
) -> Result<LoweringPassResult<Ir1Module>, LoweringPipelineError> {
    let tree = crate::parser_api_stability::parse_script(source).expect("parse script");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_xewby_fixture.js");
    lower_ir0_to_ir1_with_ambient_grant(&ir0, grant)
}

#[test]
fn bd_xewby_process_ambient_effect_mapping_is_member_aware() {
    // Env VALUE reads stay `EnvRead` (denied even under the trusted grant).
    assert_eq!(
        required_effect_for_ambient_authority("process", Some("env")),
        Some(EffectKind::EnvRead)
    );
    // Benign shape descriptors map to the dedicated `ProcessShapeRead`.
    assert_eq!(
        required_effect_for_ambient_authority("process", Some("argv")),
        Some(EffectKind::ProcessShapeRead)
    );
    assert_eq!(
        required_effect_for_ambient_authority("process", Some("platform")),
        Some(EffectKind::ProcessShapeRead)
    );
    // A bare `process` object load stays Global: granting possession would
    // launder the static-member allowlist through aliases/computed keys.
    assert_eq!(
        required_effect_for_ambient_authority("process", None),
        Some(EffectKind::Global)
    );
    // Non-benign authority surfaces keep `EnvRead` (denied under the shape grant).
    assert_eq!(
        required_effect_for_ambient_authority("process", Some("exit")),
        Some(EffectKind::EnvRead)
    );
    // `globalThis.process` is intentionally left `EnvRead` (conservative: not
    // widened by the trusted grant, so the red-team globalThis path stays denied).
    assert_eq!(
        required_effect_for_ambient_authority("globalThis", Some("process")),
        Some(EffectKind::EnvRead)
    );
}

#[test]
fn bd_xewby_grant_root_effect_sets() {
    assert!(AmbientAuthorityGrant::DenyAll.root_effect_set().is_empty());
    let trusted = AmbientAuthorityGrant::TrustedProcessShape.root_effect_set();
    assert!(trusted.contains(EffectKind::ProcessShapeRead));
    // The trusted grant is NARROW: it confers exactly one effect and never
    // env-value / eval / fs / net authority.
    assert_eq!(trusted.len(), 1);
    assert!(!trusted.contains(EffectKind::EnvRead));
    assert!(!trusted.contains(EffectKind::Global));
    assert!(!trusted.contains(EffectKind::Eval));
    assert!(!trusted.contains(EffectKind::FsRead));
}

#[test]
fn bd_xewby_is_benign_process_shape_member_allowlist() {
    for benign in ["argv", "argv0", "arch", "platform", "version", "pid"] {
        assert!(
            is_benign_process_shape_member(benign),
            "{benign} should be a benign process-shape member"
        );
    }
    for authority in ["env", "exit", "kill", "chdir", "binding", "stdout"] {
        assert!(
            !is_benign_process_shape_member(authority),
            "{authority} must NOT be a benign process-shape member"
        );
    }
}

#[test]
fn bd_xewby_trusted_eval_lowers_process_argv_shape_read() {
    // A trusted top-level eval may lower an allowlisted static member without
    // exposing a normally lowerable bare `process` object.
    lower_script_with_grant_bd_xewby(
        "process.argv.length;\n",
        AmbientAuthorityGrant::TrustedProcessShape,
    )
    .expect("trusted eval should lower a benign process.argv shape read");
}

#[test]
fn bd_xewby_untrusted_lowering_rejects_process_argv() {
    // The SAME read is rejected under the deny-all default (untrusted
    // extension / red-team lowering), carrying the `ProcessShapeRead` effect.
    let error =
        lower_script_with_grant_bd_xewby("process.argv.length;\n", AmbientAuthorityGrant::DenyAll)
            .expect_err("untrusted lowering must reject process.argv");
    assert!(
        matches!(
            error,
            LoweringPipelineError::AmbientAuthorityViolation {
                required_effect: EffectKind::ProcessShapeRead,
                ..
            }
        ),
        "expected ProcessShapeRead ambient-authority violation, got {error:?}"
    );
    // The public deny-all entry point agrees.
    assert!(matches!(
        lower_ir0_to_ir1(&Ir0Module::from_syntax_tree(
            crate::parser_api_stability::parse_script("process.argv.length;\n").expect("parse"),
            "bd_xewby_public.js",
        )),
        Err(LoweringPipelineError::AmbientAuthorityViolation { .. })
    ));
}

#[test]
fn typeof_placeholders_never_shadow_later_ambient_authority_bd_d0n7u() {
    for (label, source, expected_effect) in [
        (
            "require",
            "typeof require; require('fs');",
            EffectKind::FsRead,
        ),
        (
            "fetch",
            "typeof fetch; fetch('http://127.0.0.1:9/');",
            EffectKind::NetConnect,
        ),
        (
            "crypto",
            "typeof crypto; crypto.getHashes();",
            EffectKind::RandomRead,
        ),
    ] {
        let error = lower_script_with_grant_bd_xewby(source, AmbientAuthorityGrant::DenyAll)
            .expect_err("a typeof placeholder must not authorize a later ambient use");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation {
                    required_effect,
                    ..
                } if required_effect == expected_effect
            ),
            "{label} must retain its ambient denial after typeof, got {error:?}"
        );
    }
}

#[test]
fn repeated_typeof_ambient_reference_stays_non_authoritative_bd_d0n7u() {
    lower_script_with_grant_bd_xewby(
        "typeof require; typeof require; typeof fetch; typeof fetch; typeof crypto; typeof crypto;",
        AmbientAuthorityGrant::DenyAll,
    )
    .expect("repeated typeof probes must not exercise ambient authority");
}

#[test]
fn bd_xewby_trusted_eval_still_denies_process_env_possession() {
    // Named reads lower to a runtime EnvRead capability gate (bd-omckp),
    // but the trusted shape grant still cannot expose the env object.
    let error = lower_script_with_grant_bd_xewby(
        "process.env;\n",
        AmbientAuthorityGrant::TrustedProcessShape,
    )
    .expect_err("trusted eval must still reject possession of the env object");
    assert!(
        matches!(
            error,
            LoweringPipelineError::AmbientAuthorityViolation {
                required_effect: EffectKind::EnvRead,
                ..
            }
        ),
        "expected EnvRead ambient-authority violation, got {error:?}"
    );
}

#[test]
fn bd_y30zw_trusted_process_shape_grant_is_static_member_only() {
    for (label, source) in [
        ("bare", "process;\n"),
        ("alias", "const p = process; p.platform;\n"),
        ("computed shape", "process['platform'];\n"),
        ("computed env", "process['env']['PATH'];\n"),
        ("computed exit", "process['exit'](0);\n"),
        ("destructure", "const { platform } = process;\n"),
        (
            "grant laundering",
            "process.platform;\nprocess['env']['PATH'];\n",
        ),
    ] {
        let error =
            lower_script_with_grant_bd_xewby(source, AmbientAuthorityGrant::TrustedProcessShape)
                .expect_err("trusted shape grant must not expose the process object");
        assert!(
            matches!(
                error,
                LoweringPipelineError::AmbientAuthorityViolation { .. }
            ),
            "{label} must fail at the ambient gate, got {error:?}"
        );
    }
}

#[test]
fn bd_y30zw_source_process_binding_is_ordinary_user_data() {
    lower_script_with_grant_bd_xewby(
        "const process = { platform: 'local', pid: 7 };\nprocess.platform;\nprocess['pid'];\n",
        AmbientAuthorityGrant::DenyAll,
    )
    .expect("a lexical process binding must not be treated as ambient authority");
}

#[test]
fn bd_znj5l_preset_dictionary_options_loop_and_instanceof_error_lowering() {
    let source = r#"
    const zlib = require('zlib');
    const dictionary = Buffer.from('the quick brown fox');
    const compressed = zlib.deflateSync('the quick brown fox jumps', { dictionary });
    console.log(zlib.inflateSync(compressed, { dictionary }).toString());
    for (const options of [undefined, { dictionary: Buffer.from('wrong') }]) {
      try {
        zlib.inflateSync(compressed, options);
        console.log('no-throw');
      } catch (error) {
        console.log(error instanceof Error, error.code);
      }
    }
    "#;
    let tree = crate::parser_api_stability::parse_script(source).expect("parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_znj5l_debug.js".to_string());
    let context = LoweringContext::new("trace-1", "decision-1", "policy-1")
        .with_ambient_authority_grant(AmbientAuthorityGrant::TrustedProcessShape);
    let result = lower_ir0_to_ir3(&ir0, &context);
    match result {
        Ok(output) => {
            for (i, op) in output.ir2.ops.iter().enumerate() {
                println!("op {i:02}: {:?} | flow={:?}", op.inner, op.flow);
            }
        }
        Err(err) => {
            panic!("lower_ir0_to_ir3 failed: {err:?}");
        }
    }
}

/// bd-9vouw.223: a function body inherits the enclosing scope's lexical
/// and capture-origin markers for the names its code mentions (here `v1`
/// directly and `v999` only inside a nested function), the CommonJS
/// wrapper's and the internal ones, and for no other enclosing name.
#[test]
fn a_body_inherits_markers_only_for_names_its_code_mentions_bd_9vouw_223() {
    let mut outer = BTreeMap::new();
    for index in 0..1000u32 {
        let name = format!("v{index}");
        outer.insert(name.clone(), index + 1);
        outer.insert(lexical_binding_sentinel(&name), 0);
        outer.insert(capture_origin_sentinel(&name), index + 1);
    }
    outer.insert("require".to_string(), 2000);
    outer.insert(commonjs_wrapper_sentinel("require"), 2000);
    outer.insert(capture_origin_sentinel("require"), 2000);
    outer.insert(CANONICAL_COMMONJS_REQUIRE_SENTINEL.to_string(), 2000);
    outer.insert(
        capture_origin_sentinel(&make_internal_binding_name("for_of_source", 7)),
        7,
    );
    let body = vec![
        Statement::Expression(ExpressionStatement {
            expression: Expression::Identifier("v1".to_string()),
            span: span(),
        }),
        Statement::Return(ReturnStatement {
            argument: Some(Expression::Function {
                name: None,
                params: Vec::new(),
                body: BlockStatement {
                    body: vec![Statement::Return(ReturnStatement {
                        argument: Some(Expression::Identifier("v999".to_string())),
                        span: span(),
                    })],
                    span: span(),
                },
                is_async: false,
                is_generator: false,
                source_text: None,
                strict: false,
            }),
            span: span(),
        }),
    ];
    let mentioned = MentionedNames::of_function(None, &[], &body);
    let mut body_lookup = BTreeMap::new();
    let mut body_binding_index = 0;
    prepare_function_body_bindings(
        Some(&body),
        None,
        false,
        &mentioned,
        &outer,
        &mut body_lookup,
        &mut body_binding_index,
    );
    let inherited = body_lookup
        .iter()
        .map(|(key, id)| (key.clone(), *id))
        .collect::<Vec<_>>();
    let mut expected = vec![
        (lexical_binding_sentinel("v1"), 0),
        (capture_origin_sentinel("v1"), 2),
        (lexical_binding_sentinel("v999"), 0),
        (capture_origin_sentinel("v999"), 1000),
        (commonjs_wrapper_sentinel("require"), 2000),
        (capture_origin_sentinel("require"), 2000),
        (CANONICAL_COMMONJS_REQUIRE_SENTINEL.to_string(), 2000),
        (
            capture_origin_sentinel(&make_internal_binding_name("for_of_source", 7)),
            7,
        ),
    ];
    expected.sort();
    assert_eq!(inherited, expected);
}

/// bd-9vouw.227: the tracked sweeps of BindingFlowShapes reset exactly
/// the bindings the full sweeps reset, over a deterministic mixed
/// sequence of stores and sweeps. The reference is a plain map swept the
/// way invalidate_{nonprimitive,heap_backed}_binding_flow_shapes swept
/// every binding before (their match lists, copied).
#[test]
fn binding_flow_shape_sweeps_match_full_sweeps_bd_9vouw_227() {
    const SHAPES: [FlowValueShape; 18] = [
        FlowValueShape::Unknown,
        FlowValueShape::Primitive,
        FlowValueShape::Callable,
        FlowValueShape::CallableContainer,
        FlowValueShape::ArrayIsArrayFunction,
        FlowValueShape::FunctionConstructor,
        FlowValueShape::EventEmitterConstructor,
        FlowValueShape::EventEmitterObject,
        FlowValueShape::EventEmitterFluentMethod,
        FlowValueShape::EventEmitterEmitMethod,
        FlowValueShape::OwnKeyArray,
        FlowValueShape::OwnKeyJoinMethod,
        FlowValueShape::FreshAggregate,
        FlowValueShape::ClosedResult,
        FlowValueShape::BufferObject,
        FlowValueShape::ConstantsObject,
        FlowValueShape::Primitive,
        FlowValueShape::FreshAggregate,
    ];
    let mut tracked = BindingFlowShapes::default();
    let mut reference = BTreeMap::<BindingId, FlowValueShape>::new();
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let (mut nonprimitive_sweeps, mut heap_sweeps, mut resets) = (0, 0, 0);
    for _ in 0..20_000 {
        match next() % 10 {
            0 => {
                nonprimitive_sweeps += 1;
                invalidate_nonprimitive_binding_flow_shapes(&mut tracked);
                for shape in reference.values_mut() {
                    if !matches!(
                        *shape,
                        FlowValueShape::Primitive
                            | FlowValueShape::Callable
                            | FlowValueShape::ArrayIsArrayFunction
                            | FlowValueShape::FunctionConstructor
                            | FlowValueShape::EventEmitterObject
                            | FlowValueShape::BufferObject
                            | FlowValueShape::ClosedResult
                            | FlowValueShape::ConstantsObject
                    ) {
                        resets += usize::from(*shape != FlowValueShape::Unknown);
                        *shape = FlowValueShape::Unknown;
                    }
                }
            }
            1 => {
                heap_sweeps += 1;
                invalidate_heap_backed_binding_flow_shapes(&mut tracked);
                for shape in reference.values_mut() {
                    if matches!(
                        *shape,
                        FlowValueShape::BufferObject
                            | FlowValueShape::ClosedResult
                            | FlowValueShape::FreshAggregate
                            | FlowValueShape::ConstantsObject
                    ) {
                        resets += 1;
                        *shape = FlowValueShape::Unknown;
                    }
                }
            }
            _ => {
                let binding_id = u32::try_from(next() % 64).expect("small id");
                let shape = SHAPES[usize::try_from(next() % 18).expect("small index")];
                tracked.insert(binding_id, shape);
                reference.insert(binding_id, shape);
            }
        }
        assert_eq!(tracked.shapes, reference);
    }
    // The sequence exercised both sweeps and resets real shapes.
    assert!(nonprimitive_sweeps > 100 && heap_sweeps > 100 && resets > 1_000);
}

#[test]
fn sloppy_self_captured_named_fn_expr_and_nested_deferred_body_lower_cleanly() {
    use crate::parser::Es2020Parser;
    let source = r#"
        function outer() {
            var f = function f() {
                function inner() { return typeof f; }
                f = 1;
                f += 1;
                return inner();
            };
            return f();
        }
        outer();
    "#;
    let parser = crate::parser::CanonicalEs2020Parser;
    let tree = parser
        .parse(source, crate::ast::ParseGoal::Script)
        .expect("parse sloppy self-captured nested function");
    let ir0 = Ir0Module::from_syntax_tree(tree, "rc_a0_self_capture.js");
    let ctx = LoweringContext::new("trace-rc-a0", "decision-rc-a0", "policy-rc-a0");
    let out = lower_ir0_to_ir3(&ir0, &ctx).expect("lower nested deferred functions");
    assert!(
        out.ir3.function_table.len() >= 3,
        "expected outer, f, and inner in function_table"
    );
}
