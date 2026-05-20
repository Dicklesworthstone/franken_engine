#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterError, QuickJsLane, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum RequirementLevel {
    Must,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum InstructionFamily {
    ArithmeticAndCoercion,
    ConstantsAndMove,
    ControlFlow,
    HostcallCapabilities,
    ObjectAndArray,
    ScopeBindings,
}

#[derive(Debug, Clone)]
struct InstructionCase {
    id: &'static str,
    family: InstructionFamily,
    requirement: RequirementLevel,
    description: &'static str,
    instructions: Vec<Ir3Instruction>,
    constant_pool: &'static [&'static str],
    extra_capabilities: &'static [RuntimeCapability],
    expected: ExpectedOutcome,
}

#[derive(Debug, Clone)]
enum ExpectedOutcome {
    Value(ExpectedValue),
    CapabilityDenied(&'static str),
}

impl ExpectedOutcome {
    fn label(&self) -> String {
        match self {
            Self::Value(value) => value.label(),
            Self::CapabilityDenied(capability) => format!("capability_denied:{capability}"),
        }
    }
}

#[derive(Debug, Clone)]
enum ExpectedValue {
    Bool(bool),
    Int(i64),
    Str(&'static str),
    Undefined,
}

impl ExpectedValue {
    fn matches(&self, actual: &Value) -> bool {
        match (self, actual) {
            (Self::Bool(expected), Value::Bool(actual)) => expected == actual,
            (Self::Int(expected), Value::Int(actual)) => expected == actual,
            (Self::Str(expected), Value::Str(actual)) => expected == actual,
            (Self::Undefined, Value::Undefined) => true,
            _ => false,
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Bool(value) => value.to_string(),
            Self::Int(value) => value.to_string(),
            Self::Str(value) => format!("{value:?}"),
            Self::Undefined => "undefined".to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
struct CaseReport {
    id: &'static str,
    family: InstructionFamily,
    requirement: RequirementLevel,
    description: &'static str,
    expected: String,
    actual: String,
    status: &'static str,
    instructions_executed: Option<u64>,
    witness_events: Option<usize>,
    hostcall_decisions: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ConformanceReport {
    schema: &'static str,
    suite: &'static str,
    case_count: usize,
    family_counts: BTreeMap<InstructionFamily, usize>,
    cases: Vec<CaseReport>,
}

fn test_config(extra_capabilities: &[RuntimeCapability]) -> InterpreterConfig {
    let mut capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    capabilities.extend(extra_capabilities.iter().copied());

    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = capabilities;
    config
}

fn test_module(instructions: Vec<Ir3Instruction>, constant_pool: Vec<String>) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "ir3-executable-instruction-conformance".to_string(),
        },
        instructions,
        constant_pool,
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

fn execute_case(case: &InstructionCase) -> Result<ExecutionResult, InterpreterError> {
    let module = test_module(
        case.instructions.clone(),
        case.constant_pool
            .iter()
            .map(|value| value.to_string())
            .collect(),
    );
    QuickJsLane::with_config(test_config(case.extra_capabilities))
        .execute(&module, "ir3-executable-instruction-conformance")
}

fn value_label(value: &Value) -> String {
    match value {
        Value::Str(value) => format!("{value:?}"),
        other => other.to_string(),
    }
}

fn execute_for_report(case: &InstructionCase) -> Result<CaseReport, String> {
    let expected = case.expected.label();
    match (&case.expected, execute_case(case)) {
        (ExpectedOutcome::Value(expected_value), Ok(result)) => {
            let actual = value_label(&result.value);
            if !expected_value.matches(&result.value) {
                return Err(format!("{} expected {}, got {}", case.id, expected, actual));
            }
            if result.witness_events.is_empty() {
                return Err(format!(
                    "{} completed without replay witness events",
                    case.id
                ));
            }

            Ok(CaseReport {
                id: case.id,
                family: case.family,
                requirement: case.requirement,
                description: case.description,
                expected,
                actual,
                status: "pass",
                instructions_executed: Some(result.instructions_executed),
                witness_events: Some(result.witness_events.len()),
                hostcall_decisions: Some(result.hostcall_decisions.len()),
            })
        }
        (ExpectedOutcome::CapabilityDenied(expected_capability), Err(error)) => match error {
            InterpreterError::CapabilityDenied { capability }
                if capability == *expected_capability =>
            {
                Ok(CaseReport {
                    id: case.id,
                    family: case.family,
                    requirement: case.requirement,
                    description: case.description,
                    expected,
                    actual: format!("capability_denied:{capability}"),
                    status: "pass",
                    instructions_executed: None,
                    witness_events: None,
                    hostcall_decisions: None,
                })
            }
            other => Err(format!(
                "{} expected capability denial for {}, got {other:?}",
                case.id, expected_capability
            )),
        },
        (_, Ok(result)) => Err(format!(
            "{} expected {}, got value {}",
            case.id,
            expected,
            value_label(&result.value)
        )),
        (_, Err(error)) => Err(format!("{} expected {}, got {error:?}", case.id, expected)),
    }
}

fn build_report() -> Result<ConformanceReport, String> {
    let mut family_counts = BTreeMap::new();
    let mut reports = Vec::new();

    for case in cases() {
        let report = execute_for_report(&case)?;
        *family_counts.entry(report.family).or_insert(0) += 1;
        reports.push(report);
    }

    Ok(ConformanceReport {
        schema: "ir3-executable-instruction-conformance.v1",
        suite: "franken-engine-ir3-executable-instruction-semantics",
        case_count: reports.len(),
        family_counts,
        cases: reports,
    })
}

fn case(
    id: &'static str,
    family: InstructionFamily,
    description: &'static str,
    instructions: Vec<Ir3Instruction>,
    constant_pool: &'static [&'static str],
    extra_capabilities: &'static [RuntimeCapability],
    expected: ExpectedOutcome,
) -> InstructionCase {
    InstructionCase {
        id,
        family,
        requirement: RequirementLevel::Must,
        description,
        instructions,
        constant_pool,
        extra_capabilities,
        expected,
    }
}

fn hostcall(capability: &str, start: u32, count: u32, dst: u32) -> Ir3Instruction {
    Ir3Instruction::HostCall {
        capability: CapabilityTag(capability.to_string()),
        args: RegRange { start, count },
        dst,
    }
}

fn cases() -> Vec<InstructionCase> {
    use ExpectedOutcome::{CapabilityDenied, Value};
    use ExpectedValue::{Bool, Int, Str, Undefined};
    use InstructionFamily::{
        ArithmeticAndCoercion, ConstantsAndMove, ControlFlow, HostcallCapabilities, ObjectAndArray,
        ScopeBindings,
    };

    vec![
        case(
            "load_string_then_move_to_return_register",
            ConstantsAndMove,
            "LoadStr and Move must preserve a constant-pool string value.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::Move { dst: 0, src: 1 },
                Ir3Instruction::Halt,
            ],
            &["alpha"],
            &[],
            Value(Str("alpha")),
        ),
        case(
            "return_short_circuits_later_instructions",
            ControlFlow,
            "Return must complete with its source register before later instructions run.",
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 1 },
                Ir3Instruction::LoadInt { dst: 1, value: 7 },
                Ir3Instruction::Return { value: 1 },
                Ir3Instruction::LoadInt { dst: 0, value: 99 },
                Ir3Instruction::Halt,
            ],
            &[],
            &[],
            Value(Int(7)),
        ),
        case(
            "integer_addition_writes_destination",
            ArithmeticAndCoercion,
            "Add must combine integer operands and write the destination register.",
            vec![
                Ir3Instruction::LoadInt { dst: 1, value: 40 },
                Ir3Instruction::LoadInt { dst: 2, value: 2 },
                Ir3Instruction::Add {
                    dst: 0,
                    lhs: 1,
                    rhs: 2,
                },
                Ir3Instruction::Halt,
            ],
            &[],
            &[],
            Value(Int(42)),
        ),
        case(
            "unary_plus_coerces_decimal_string",
            ArithmeticAndCoercion,
            "UnaryPlus must coerce a decimal string through the IR3 numeric path.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::UnaryPlus { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &["42"],
            &[],
            Value(Int(42)),
        ),
        case(
            "strict_equality_reports_boolean",
            ArithmeticAndCoercion,
            "StrictEq must compare equal integer registers to a boolean true result.",
            vec![
                Ir3Instruction::LoadInt { dst: 1, value: 11 },
                Ir3Instruction::LoadInt { dst: 2, value: 11 },
                Ir3Instruction::StrictEq {
                    dst: 0,
                    lhs: 1,
                    rhs: 2,
                },
                Ir3Instruction::Halt,
            ],
            &[],
            &[],
            Value(Bool(true)),
        ),
        case(
            "void_writes_undefined",
            ArithmeticAndCoercion,
            "Void must produce undefined regardless of the source register.",
            vec![
                Ir3Instruction::LoadInt { dst: 1, value: 5 },
                Ir3Instruction::Void { dst: 0, src: 1 },
                Ir3Instruction::Halt,
            ],
            &[],
            &[],
            Value(Undefined),
        ),
        case(
            "truthy_jump_selects_target_block",
            ControlFlow,
            "JumpIf must use IR3 truthiness to select the target instruction.",
            vec![
                Ir3Instruction::LoadBool {
                    dst: 1,
                    value: true,
                },
                Ir3Instruction::JumpIf { cond: 1, target: 4 },
                Ir3Instruction::LoadInt { dst: 0, value: 1 },
                Ir3Instruction::Jump { target: 5 },
                Ir3Instruction::LoadInt { dst: 0, value: 2 },
                Ir3Instruction::Halt,
            ],
            &[],
            &[],
            Value(Int(2)),
        ),
        case(
            "nullish_jump_selects_target_for_undefined",
            ControlFlow,
            "JumpIfNullish must branch for undefined.",
            vec![
                Ir3Instruction::LoadUndefined { dst: 1 },
                Ir3Instruction::JumpIfNullish { cond: 1, target: 4 },
                Ir3Instruction::LoadInt { dst: 0, value: 1 },
                Ir3Instruction::Jump { target: 5 },
                Ir3Instruction::LoadInt { dst: 0, value: 9 },
                Ir3Instruction::Halt,
            ],
            &[],
            &[],
            Value(Int(9)),
        ),
        case(
            "nullish_jump_does_not_branch_for_false",
            ControlFlow,
            "JumpIfNullish must not treat false as nullish.",
            vec![
                Ir3Instruction::LoadBool {
                    dst: 1,
                    value: false,
                },
                Ir3Instruction::JumpIfNullish { cond: 1, target: 4 },
                Ir3Instruction::LoadInt { dst: 0, value: 4 },
                Ir3Instruction::Jump { target: 5 },
                Ir3Instruction::LoadInt { dst: 0, value: 9 },
                Ir3Instruction::Halt,
            ],
            &[],
            &[],
            Value(Int(4)),
        ),
        case(
            "object_property_round_trip",
            ObjectAndArray,
            "NewObject, SetProperty, and GetProperty must round-trip a data property.",
            vec![
                Ir3Instruction::NewObject { dst: 0 },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 2, value: 42 },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 2,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 1,
                    dst: 3,
                },
                Ir3Instruction::Move { dst: 0, src: 3 },
                Ir3Instruction::Halt,
            ],
            &["answer"],
            &[],
            Value(Int(42)),
        ),
        case(
            "delete_property_reports_success",
            ObjectAndArray,
            "DeleteProperty must report true for a configurable ordinary data property.",
            vec![
                Ir3Instruction::NewObject { dst: 0 },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 2, value: 1 },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 2,
                },
                Ir3Instruction::DeleteProperty {
                    obj: 0,
                    key: 1,
                    dst: 0,
                },
                Ir3Instruction::Halt,
            ],
            &["temp"],
            &[],
            Value(Bool(true)),
        ),
        case(
            "array_push_updates_length_property",
            ObjectAndArray,
            "ArrayPush must append one element and publish the deterministic length property.",
            vec![
                Ir3Instruction::NewArray { dst: 0 },
                Ir3Instruction::LoadInt { dst: 1, value: 7 },
                Ir3Instruction::ArrayPush {
                    array: 0,
                    element: 1,
                },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 2,
                    dst: 3,
                },
                Ir3Instruction::Move { dst: 0, src: 3 },
                Ir3Instruction::Halt,
            ],
            &["length"],
            &[],
            Value(Int(1)),
        ),
        case(
            "template_literal_concatenates_register_range",
            ObjectAndArray,
            "TemplateLiteral must concatenate strings and expression registers in order.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 1, value: 7 },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 1,
                },
                Ir3Instruction::TemplateLiteral {
                    parts: RegRange { start: 0, count: 3 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
            ],
            &["a", "b"],
            &[],
            Value(Str("a7b")),
        ),
        case(
            "let_binding_init_then_load_scoped",
            ScopeBindings,
            "DeclareBinding, InitBinding, and LoadScoped must resolve an initialized let binding.",
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 44 },
                Ir3Instruction::DeclareBinding {
                    name_pool_index: 0,
                    kind: 1,
                },
                Ir3Instruction::InitBinding {
                    name_pool_index: 0,
                    src: 0,
                },
                Ir3Instruction::LoadScoped {
                    dst: 1,
                    name_pool_index: 0,
                },
                Ir3Instruction::Move { dst: 0, src: 1 },
                Ir3Instruction::Halt,
            ],
            &["answer"],
            &[],
            Value(Int(44)),
        ),
        case(
            "builtin_hostcall_denied_without_builtin_capability",
            HostcallCapabilities,
            "HostCall must fail closed when a builtin capability is not granted.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 1,
                },
                Ir3Instruction::LoadInt { dst: 2, value: 0 },
                hostcall("builtin:StringPrototypeIncludes", 0, 3, 0),
                Ir3Instruction::Halt,
            ],
            &["abc", "b"],
            &[],
            CapabilityDenied("builtin:StringPrototypeIncludes"),
        ),
        case(
            "builtin_hostcall_succeeds_with_builtin_capability",
            HostcallCapabilities,
            "HostCall must run through the allowed builtin dispatch path when Builtin is granted.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 1,
                },
                Ir3Instruction::LoadInt { dst: 2, value: 0 },
                hostcall("builtin:StringPrototypeIncludes", 0, 3, 0),
                Ir3Instruction::Halt,
            ],
            &["abc", "b"],
            &[RuntimeCapability::Builtin],
            Value(Bool(true)),
        ),
    ]
}

#[test]
fn ir3_executable_instruction_conformance_matrix_must_pass() {
    let report = build_report().expect("IR3 executable instruction conformance report");

    assert_eq!(report.case_count, cases().len());
    for family in [
        InstructionFamily::ArithmeticAndCoercion,
        InstructionFamily::ConstantsAndMove,
        InstructionFamily::ControlFlow,
        InstructionFamily::HostcallCapabilities,
        InstructionFamily::ObjectAndArray,
        InstructionFamily::ScopeBindings,
    ] {
        assert!(
            report.family_counts.contains_key(&family),
            "missing conformance family {family:?}"
        );
    }
    assert!(
        report
            .cases
            .iter()
            .any(|case| case.hostcall_decisions.unwrap_or_default() > 0),
        "allowed hostcall case should record a hostcall decision"
    );
    assert!(
        report
            .cases
            .iter()
            .filter_map(|case| case.witness_events)
            .all(|count| count > 0),
        "completed cases should record replay witness events"
    );
}

#[test]
fn ir3_executable_instruction_report_is_deterministic() {
    let first = serde_json::to_string_pretty(
        &build_report().expect("first IR3 executable conformance report"),
    )
    .expect("serialize first report");
    let second = serde_json::to_string_pretty(
        &build_report().expect("second IR3 executable conformance report"),
    )
    .expect("serialize second report");

    assert_eq!(first, second);
    assert!(first.contains("\"schema\": \"ir3-executable-instruction-conformance.v1\""));
    assert!(first.contains("\"witness_events\""));
    assert!(first.contains("\"hostcall_decisions\""));
}
