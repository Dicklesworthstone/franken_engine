#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterError, QuickJsLane, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{
    Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion,
};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum RequirementLevel {
    Must,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum AbstractOpCategory {
    Bitwise,
    Equality,
    Relational,
    ToBoolean,
    ToNumber,
    TypeOf,
    Void,
}

#[derive(Debug, Clone)]
struct AbstractOpCase {
    id: &'static str,
    section: &'static str,
    level: RequirementLevel,
    category: AbstractOpCategory,
    description: &'static str,
    instructions: Vec<Ir3Instruction>,
    constant_pool: &'static [&'static str],
    expected: ExpectedValue,
}

#[derive(Debug, Clone)]
enum ExpectedValue {
    Bool(bool),
    FloatNan,
    Int(i64),
    Str(&'static str),
    Undefined,
}

impl ExpectedValue {
    fn matches(&self, actual: &Value) -> bool {
        match (self, actual) {
            (Self::Bool(expected), Value::Bool(actual)) => expected == actual,
            (Self::FloatNan, Value::Float(actual)) => actual.is_nan(),
            (Self::Int(expected), Value::Int(actual)) => expected == actual,
            (Self::Str(expected), Value::Str(actual)) => expected == actual,
            (Self::Undefined, Value::Undefined) => true,
            _ => false,
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Bool(value) => value.to_string(),
            Self::FloatNan => "NaN".to_string(),
            Self::Int(value) => value.to_string(),
            Self::Str(value) => format!("{value:?}"),
            Self::Undefined => "undefined".to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
struct CaseReport {
    id: &'static str,
    section: &'static str,
    level: RequirementLevel,
    category: AbstractOpCategory,
    description: &'static str,
    expected: String,
    actual: String,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ConformanceReport {
    schema: &'static str,
    suite: &'static str,
    case_count: usize,
    category_counts: BTreeMap<AbstractOpCategory, usize>,
    cases: Vec<CaseReport>,
}

fn test_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn test_module(instructions: Vec<Ir3Instruction>, constant_pool: Vec<String>) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "runtime-abstract-ops-conformance".to_string(),
        },
        instructions,
        constant_pool,
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

fn execute_module(
    instructions: Vec<Ir3Instruction>,
    constant_pool: Vec<String>,
) -> Result<Value, InterpreterError> {
    let module = test_module(instructions, constant_pool);
    let result: ExecutionResult =
        QuickJsLane::with_config(test_config()).execute(&module, "runtime-abstract-ops")?;
    Ok(result.value)
}

fn execute_case(case: &AbstractOpCase) -> Result<Value, InterpreterError> {
    execute_module(
        case.instructions.clone(),
        case.constant_pool.iter().map(|value| value.to_string()).collect(),
    )
}

fn value_label(value: &Value) -> String {
    match value {
        Value::Float(value) if value.is_nan() => "NaN".to_string(),
        Value::Float(value) if value.is_negative_zero() => "-0".to_string(),
        Value::Str(value) => format!("{value:?}"),
        other => other.to_string(),
    }
}

fn build_report() -> Result<ConformanceReport, String> {
    let mut category_counts = BTreeMap::new();
    let mut case_reports = Vec::new();

    for case in cases() {
        let actual = execute_case(&case).map_err(|error| {
            format!(
                "{} ({}) failed to execute: {error:?}",
                case.id, case.section
            )
        })?;
        let expected = case.expected.label();
        let actual_label = value_label(&actual);
        if !case.expected.matches(&actual) {
            return Err(format!(
                "{} ({}) expected {}, got {}",
                case.id, case.section, expected, actual_label
            ));
        }

        *category_counts.entry(case.category).or_insert(0) += 1;
        case_reports.push(CaseReport {
            id: case.id,
            section: case.section,
            level: case.level,
            category: case.category,
            description: case.description,
            expected,
            actual: actual_label,
            status: "pass",
        });
    }

    Ok(ConformanceReport {
        schema: "runtime-abstract-ops-conformance.v1",
        suite: "franken-engine-ir3-runtime-abstract-ops",
        case_count: case_reports.len(),
        category_counts,
        cases: case_reports,
    })
}

fn case(
    id: &'static str,
    section: &'static str,
    category: AbstractOpCategory,
    description: &'static str,
    instructions: Vec<Ir3Instruction>,
    constant_pool: &'static [&'static str],
    expected: ExpectedValue,
) -> AbstractOpCase {
    AbstractOpCase {
        id,
        section,
        level: RequirementLevel::Must,
        category,
        description,
        instructions,
        constant_pool,
        expected,
    }
}

fn cases() -> Vec<AbstractOpCase> {
    use AbstractOpCategory::{
        Bitwise, Equality, Relational, ToBoolean, ToNumber, TypeOf, Void,
    };

    vec![
        case(
            "to_boolean_undefined_is_falsy",
            "ecma262:sec-toboolean",
            ToBoolean,
            "LogicalNot must observe undefined as falsy.",
            vec![
                Ir3Instruction::LoadUndefined { dst: 0 },
                Ir3Instruction::LogicalNot { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Bool(true),
        ),
        case(
            "to_boolean_null_is_falsy",
            "ecma262:sec-toboolean",
            ToBoolean,
            "LogicalNot must observe null as falsy.",
            vec![
                Ir3Instruction::LoadNull { dst: 0 },
                Ir3Instruction::LogicalNot { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Bool(true),
        ),
        case(
            "to_boolean_empty_string_is_falsy",
            "ecma262:sec-toboolean",
            ToBoolean,
            "LogicalNot must observe the empty string as falsy.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::LogicalNot { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[""],
            ExpectedValue::Bool(true),
        ),
        case(
            "to_boolean_nonempty_string_is_truthy",
            "ecma262:sec-toboolean",
            ToBoolean,
            "LogicalNot must observe non-empty strings as truthy.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::LogicalNot { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &["x"],
            ExpectedValue::Bool(false),
        ),
        case(
            "to_boolean_zero_is_falsy",
            "ecma262:sec-toboolean",
            ToBoolean,
            "LogicalNot must observe +0 as falsy.",
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 0 },
                Ir3Instruction::LogicalNot { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Bool(true),
        ),
        case(
            "to_boolean_object_is_truthy",
            "ecma262:sec-toboolean",
            ToBoolean,
            "LogicalNot must observe ordinary objects as truthy.",
            vec![
                Ir3Instruction::NewObject { dst: 0 },
                Ir3Instruction::LogicalNot { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Bool(false),
        ),
        case(
            "to_number_string_integer",
            "ecma262:sec-tonumber",
            ToNumber,
            "Unary plus must coerce a decimal string to the same numeric value.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::UnaryPlus { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &["42"],
            ExpectedValue::Int(42),
        ),
        case(
            "to_number_whitespace_string_zero",
            "ecma262:sec-tonumber-applied-to-the-string-type",
            ToNumber,
            "Unary plus must coerce whitespace-only strings to +0.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::UnaryPlus { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &["  \t\n"],
            ExpectedValue::Int(0),
        ),
        case(
            "to_number_true_is_one",
            "ecma262:sec-tonumber",
            ToNumber,
            "Unary plus must coerce true to 1.",
            vec![
                Ir3Instruction::LoadBool {
                    dst: 0,
                    value: true,
                },
                Ir3Instruction::UnaryPlus { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Int(1),
        ),
        case(
            "to_number_null_is_zero",
            "ecma262:sec-tonumber",
            ToNumber,
            "Unary plus must coerce null to +0.",
            vec![
                Ir3Instruction::LoadNull { dst: 0 },
                Ir3Instruction::UnaryPlus { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Int(0),
        ),
        case(
            "to_number_undefined_is_nan",
            "ecma262:sec-tonumber",
            ToNumber,
            "Unary plus must coerce undefined to NaN.",
            vec![
                Ir3Instruction::LoadUndefined { dst: 0 },
                Ir3Instruction::UnaryPlus { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::FloatNan,
        ),
        case(
            "typeof_undefined",
            "ecma262:sec-typeof-operator",
            TypeOf,
            "typeof undefined must return the string 'undefined'.",
            vec![
                Ir3Instruction::LoadUndefined { dst: 0 },
                Ir3Instruction::TypeOf { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Str("undefined"),
        ),
        case(
            "typeof_null_is_object",
            "ecma262:sec-typeof-operator",
            TypeOf,
            "typeof null must preserve the JavaScript 'object' result.",
            vec![
                Ir3Instruction::LoadNull { dst: 0 },
                Ir3Instruction::TypeOf { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Str("object"),
        ),
        case(
            "typeof_boolean",
            "ecma262:sec-typeof-operator",
            TypeOf,
            "typeof boolean values must return 'boolean'.",
            vec![
                Ir3Instruction::LoadBool {
                    dst: 0,
                    value: false,
                },
                Ir3Instruction::TypeOf { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Str("boolean"),
        ),
        case(
            "typeof_number",
            "ecma262:sec-typeof-operator",
            TypeOf,
            "typeof numeric values must return 'number'.",
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::TypeOf { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Str("number"),
        ),
        case(
            "typeof_object",
            "ecma262:sec-typeof-operator",
            TypeOf,
            "typeof ordinary objects must return 'object'.",
            vec![
                Ir3Instruction::NewObject { dst: 0 },
                Ir3Instruction::TypeOf { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Str("object"),
        ),
        case(
            "void_discards_operand",
            "ecma262:sec-void-operator",
            Void,
            "void must evaluate the operand and produce undefined.",
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 123 },
                Ir3Instruction::Void { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Undefined,
        ),
        case(
            "abstract_equality_null_undefined",
            "ecma262:sec-islooselyequal",
            Equality,
            "Loose equality must consider null and undefined equal.",
            vec![
                Ir3Instruction::LoadNull { dst: 0 },
                Ir3Instruction::LoadUndefined { dst: 1 },
                Ir3Instruction::Eq {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Bool(true),
        ),
        case(
            "abstract_equality_string_number",
            "ecma262:sec-islooselyequal",
            Equality,
            "Loose equality must compare numeric strings and numbers after coercion.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 1, value: 1 },
                Ir3Instruction::Eq {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Halt,
            ],
            &["1"],
            ExpectedValue::Bool(true),
        ),
        case(
            "strict_equality_string_number",
            "ecma262:sec-isstrictlyequal",
            Equality,
            "Strict equality must not coerce string and number operands.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 1, value: 1 },
                Ir3Instruction::StrictEq {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Halt,
            ],
            &["1"],
            ExpectedValue::Bool(false),
        ),
        case(
            "strict_equality_nan_is_false",
            "ecma262:sec-isstrictlyequal",
            Equality,
            "Strict equality must return false for NaN compared with itself.",
            vec![
                Ir3Instruction::LoadFloat {
                    dst: 0,
                    bits: f64::NAN.to_bits(),
                },
                Ir3Instruction::StrictEq {
                    dst: 0,
                    lhs: 0,
                    rhs: 0,
                },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Bool(false),
        ),
        case(
            "strict_equality_negative_zero_positive_zero",
            "ecma262:sec-isstrictlyequal",
            Equality,
            "Strict equality must consider -0 and +0 equal.",
            vec![
                Ir3Instruction::LoadFloat {
                    dst: 0,
                    bits: (-0.0_f64).to_bits(),
                },
                Ir3Instruction::LoadFloat {
                    dst: 1,
                    bits: 0.0_f64.to_bits(),
                },
                Ir3Instruction::StrictEq {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Bool(true),
        ),
        case(
            "relational_numeric_string_less_than_number",
            "ecma262:sec-islessthan",
            Relational,
            "Relational comparison must coerce numeric strings when operands are not both strings.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 1, value: 10 },
                Ir3Instruction::Lt {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Halt,
            ],
            &["2"],
            ExpectedValue::Bool(true),
        ),
        case(
            "relational_string_lexicographic",
            "ecma262:sec-islessthan",
            Relational,
            "Relational comparison must use lexicographic order for two strings.",
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 1,
                },
                Ir3Instruction::Gt {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Halt,
            ],
            &["b", "a"],
            ExpectedValue::Bool(true),
        ),
        case(
            "relational_nan_less_than_is_false",
            "ecma262:sec-islessthan",
            Relational,
            "Relational comparison involving NaN must be false.",
            vec![
                Ir3Instruction::LoadFloat {
                    dst: 0,
                    bits: f64::NAN.to_bits(),
                },
                Ir3Instruction::LoadInt { dst: 1, value: 1 },
                Ir3Instruction::Lt {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Bool(false),
        ),
        case(
            "bitwise_not_undefined",
            "ecma262:sec-binary-bitwise-operators-runtime-semantics-evaluation",
            Bitwise,
            "Bitwise not must convert undefined through NaN to int32 zero.",
            vec![
                Ir3Instruction::LoadUndefined { dst: 0 },
                Ir3Instruction::BitNot { dst: 0, src: 0 },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Int(-1),
        ),
        case(
            "bitwise_and_true_three",
            "ecma262:sec-binary-bitwise-operators-runtime-semantics-evaluation",
            Bitwise,
            "Bitwise and must apply ToInt32 to boolean operands.",
            vec![
                Ir3Instruction::LoadBool {
                    dst: 0,
                    value: true,
                },
                Ir3Instruction::LoadInt { dst: 1, value: 3 },
                Ir3Instruction::BitAnd {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Int(1),
        ),
        case(
            "bitwise_left_shift_masks_count",
            "ecma262:sec-left-shift-operator-runtime-semantics-evaluation",
            Bitwise,
            "Left shift must mask the shift count to five bits.",
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 1 },
                Ir3Instruction::LoadInt { dst: 1, value: 33 },
                Ir3Instruction::Shl {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Int(2),
        ),
        case(
            "bitwise_unsigned_right_shift_negative_one",
            "ecma262:sec-unsigned-right-shift-operator-runtime-semantics-evaluation",
            Bitwise,
            "Unsigned right shift must convert the signed int32 input to uint32 before shifting.",
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: -1 },
                Ir3Instruction::LoadInt { dst: 1, value: 1 },
                Ir3Instruction::Ushr {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Halt,
            ],
            &[],
            ExpectedValue::Int(2_147_483_647),
        ),
    ]
}

#[test]
fn runtime_abstract_ops_conformance_matrix_must_pass() {
    let report = build_report().expect("runtime abstract-op conformance cases must pass");

    assert_eq!(report.case_count, 29);
    for category in [
        AbstractOpCategory::Bitwise,
        AbstractOpCategory::Equality,
        AbstractOpCategory::Relational,
        AbstractOpCategory::ToBoolean,
        AbstractOpCategory::ToNumber,
        AbstractOpCategory::TypeOf,
        AbstractOpCategory::Void,
    ] {
        assert!(
            report.category_counts.contains_key(&category),
            "missing category coverage for {category:?}"
        );
    }
    assert!(report.cases.iter().all(|case| case.status == "pass"));
}

#[test]
fn runtime_abstract_ops_conformance_report_is_deterministic() {
    let first = build_report().expect("first conformance report must build");
    let second = build_report().expect("second conformance report must build");

    let first_json = serde_json::to_string_pretty(&first).unwrap();
    let second_json = serde_json::to_string_pretty(&second).unwrap();
    assert_eq!(first_json, second_json);
}
