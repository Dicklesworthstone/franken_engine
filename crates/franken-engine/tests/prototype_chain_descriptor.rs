#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{CapabilityTag, Ir3Instruction, Ir3Module, RegRange};

const PROTOTYPE_DESCRIPTOR_TEST_BUDGET: u64 = 512;
const PROXY_GET_FALLBACK_MAX_ELAPSED: Duration = Duration::from_secs(5);

fn config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = PROTOTYPE_DESCRIPTOR_TEST_BUDGET;
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]);
    config
}

fn builtin(name: &str) -> CapabilityTag {
    CapabilityTag(format!("builtin:{name}"))
}

fn module(source_label: &str, pool: Vec<&str>, instructions: Vec<Ir3Instruction>) -> Ir3Module {
    let mut module = Ir3Module::new(ContentHash::compute(source_label.as_bytes()), source_label);
    module.constant_pool = pool.into_iter().map(str::to_string).collect();
    module.required_capabilities = instructions
        .iter()
        .filter_map(|instruction| match instruction {
            Ir3Instruction::HostCall { capability, .. } => Some(capability.clone()),
            _ => None,
        })
        .collect();
    module.instructions = instructions;
    module
}

fn execute(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
    InterpreterCore::new(config(), "prototype-chain-descriptor").execute(module)
}

#[derive(Clone, Copy, Debug)]
enum ExpectedValue {
    Bool(bool),
    Int(i64),
    Str(&'static str),
    Undefined,
}

impl ExpectedValue {
    fn assert_matches(self, actual: &Value, case: &PrototypeConformanceCase) {
        match (self, actual) {
            (ExpectedValue::Bool(expected), Value::Bool(actual)) => {
                assert_eq!(
                    expected, *actual,
                    "{} ({}) returned the wrong boolean",
                    case.id, case.requirement
                );
            }
            (ExpectedValue::Int(expected), Value::Int(actual)) => {
                assert_eq!(
                    expected, *actual,
                    "{} ({}) returned the wrong integer",
                    case.id, case.requirement
                );
            }
            (ExpectedValue::Str(expected), Value::Str(actual)) => {
                assert_eq!(
                    expected,
                    actual.as_ref(),
                    "{} ({}) returned the wrong string",
                    case.id,
                    case.requirement
                );
            }
            (ExpectedValue::Undefined, Value::Undefined) => {}
            (expected, actual) => panic!(
                "{} ({}) expected {expected:?}, got {actual:?}",
                case.id, case.requirement
            ),
        }
    }
}

struct PrototypeConformanceCase {
    id: &'static str,
    spec_ref: &'static str,
    requirement: &'static str,
    module: fn() -> Ir3Module,
    expected: ExpectedValue,
}

struct UnsupportedSemantic {
    id: &'static str,
    spec_ref: &'static str,
    reason: &'static str,
}

const UNSUPPORTED_SEMANTICS: &[UnsupportedSemantic] = &[
    UnsupportedSemantic {
        id: "accessor-descriptor-get-set",
        spec_ref: "ECMA-262 [[GetOwnProperty]] accessor descriptors",
        reason: "IR3 object heap descriptors currently materialize data values only",
    },
    UnsupportedSemantic {
        id: "instanceof-symbol-hasinstance",
        spec_ref: "ECMA-262 OrdinaryHasInstance / @@hasInstance",
        reason: "baseline InstanceOf covers constructor prototype chains, not Symbol.hasInstance traps",
    },
];

fn conformance_cases() -> Vec<PrototypeConformanceCase> {
    vec![
        PrototypeConformanceCase {
            id: "get-own-data",
            spec_ref: "ECMA-262 [[Get]] own property",
            requirement: "own data property lookup returns the object's value",
            module: own_data_get_module,
            expected: ExpectedValue::Int(11),
        },
        PrototypeConformanceCase {
            id: "get-inherited-data",
            spec_ref: "ECMA-262 [[Get]] prototype traversal",
            requirement: "missing own property is read from the prototype chain",
            module: inherited_data_get_module,
            expected: ExpectedValue::Str("parent"),
        },
        PrototypeConformanceCase {
            id: "get-own-shadows-inherited",
            spec_ref: "ECMA-262 [[Get]] own before inherited",
            requirement: "own property shadows an inherited property of the same key",
            module: shadowed_data_get_module,
            expected: ExpectedValue::Str("child"),
        },
        PrototypeConformanceCase {
            id: "set-creates-own-shadow",
            spec_ref: "ECMA-262 [[Set]] ordinary receiver write",
            requirement: "setting an inherited key creates the receiver's own value",
            module: set_shadow_data_module,
            expected: ExpectedValue::Str("own"),
        },
        PrototypeConformanceCase {
            id: "delete-own-reveals-inherited",
            spec_ref: "ECMA-262 [[Delete]] and subsequent [[Get]]",
            requirement: "deleting an own shadow reveals the inherited property",
            module: delete_reveals_inherited_module,
            expected: ExpectedValue::Str("parent"),
        },
        PrototypeConformanceCase {
            id: "in-finds-inherited",
            spec_ref: "ECMA-262 RelationalExpression in",
            requirement: "the in operator observes inherited properties",
            module: in_operator_inherited_module,
            expected: ExpectedValue::Bool(true),
        },
        PrototypeConformanceCase {
            id: "in-missing-false",
            spec_ref: "ECMA-262 RelationalExpression in",
            requirement: "the in operator returns false for absent chain keys",
            module: in_operator_missing_module,
            expected: ExpectedValue::Bool(false),
        },
        PrototypeConformanceCase {
            id: "descriptor-own-value",
            spec_ref: "ECMA-262 Object.getOwnPropertyDescriptor data descriptor",
            requirement: "own descriptors expose their value field",
            module: own_descriptor_value_module,
            expected: ExpectedValue::Int(42),
        },
        PrototypeConformanceCase {
            id: "descriptor-inherited-value",
            spec_ref: "ECMA-262 prototype-aware property descriptor lookup",
            requirement: "prototype descriptor lookup returns inherited data",
            module: inherited_descriptor_lookup_module,
            expected: ExpectedValue::Str("inherited"),
        },
        PrototypeConformanceCase {
            id: "own-descriptor-excludes-inherited",
            spec_ref: "ECMA-262 Object.getOwnPropertyDescriptor own-only lookup",
            requirement: "own descriptor lookup does not report inherited data",
            module: own_descriptor_excludes_inherited_module,
            expected: ExpectedValue::Undefined,
        },
        PrototypeConformanceCase {
            id: "descriptor-frozen-non-configurable",
            spec_ref: "ECMA-262 frozen data descriptor attributes",
            requirement: "frozen properties report configurable=false",
            module: frozen_configurable_descriptor_module,
            expected: ExpectedValue::Bool(false),
        },
        PrototypeConformanceCase {
            id: "proxy-get-no-trap-fallback",
            spec_ref: "ECMA-262 Proxy [[Get]] target fallback",
            requirement: "a proxy without a get trap delegates lookup to its target",
            module: proxy_get_no_trap_fallback_module,
            expected: ExpectedValue::Str("target"),
        },
    ]
}

fn own_data_get_module() -> Ir3Module {
    module(
        "own-data-get",
        vec!["own"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 11 },
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
            Ir3Instruction::Return { value: 3 },
        ],
    )
}

fn inherited_data_get_module() -> Ir3Module {
    module(
        "inherited-data-get",
        vec!["slot", "parent"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::NewObject { dst: 3 },
            Ir3Instruction::Move { dst: 4, src: 0 },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectSetPrototypeOf"),
                args: RegRange { start: 3, count: 2 },
                dst: 5,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 1,
                dst: 6,
            },
            Ir3Instruction::Return { value: 6 },
        ],
    )
}

fn shadowed_data_get_module() -> Ir3Module {
    module(
        "shadowed-data-get",
        vec!["slot", "parent", "child"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::NewObject { dst: 3 },
            Ir3Instruction::Move { dst: 4, src: 0 },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectSetPrototypeOf"),
                args: RegRange { start: 3, count: 2 },
                dst: 5,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 3,
                key: 1,
                val: 4,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 1,
                dst: 6,
            },
            Ir3Instruction::Return { value: 6 },
        ],
    )
}

fn set_shadow_data_module() -> Ir3Module {
    module(
        "set-shadow-data",
        vec!["slot", "proto", "own"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::NewObject { dst: 3 },
            Ir3Instruction::Move { dst: 4, src: 0 },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectSetPrototypeOf"),
                args: RegRange { start: 3, count: 2 },
                dst: 5,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 3,
                key: 1,
                val: 4,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 1,
                dst: 6,
            },
            Ir3Instruction::Return { value: 6 },
        ],
    )
}

fn delete_reveals_inherited_module() -> Ir3Module {
    module(
        "delete-reveals-inherited",
        vec!["slot", "parent", "child"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::NewObject { dst: 3 },
            Ir3Instruction::Move { dst: 4, src: 0 },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectSetPrototypeOf"),
                args: RegRange { start: 3, count: 2 },
                dst: 5,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 3,
                key: 1,
                val: 4,
            },
            Ir3Instruction::DeleteProperty {
                obj: 3,
                key: 1,
                dst: 6,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 1,
                dst: 7,
            },
            Ir3Instruction::Return { value: 7 },
        ],
    )
}

fn in_operator_inherited_module() -> Ir3Module {
    module(
        "in-operator-inherited",
        vec!["slot", "parent"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::NewObject { dst: 3 },
            Ir3Instruction::Move { dst: 4, src: 0 },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectSetPrototypeOf"),
                args: RegRange { start: 3, count: 2 },
                dst: 5,
            },
            Ir3Instruction::InOp {
                dst: 6,
                lhs: 1,
                rhs: 3,
            },
            Ir3Instruction::Return { value: 6 },
        ],
    )
}

fn in_operator_missing_module() -> Ir3Module {
    module(
        "in-operator-missing",
        vec!["slot", "parent", "missing"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::NewObject { dst: 3 },
            Ir3Instruction::Move { dst: 4, src: 0 },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectSetPrototypeOf"),
                args: RegRange { start: 3, count: 2 },
                dst: 5,
            },
            Ir3Instruction::LoadStr {
                dst: 6,
                pool_index: 2,
            },
            Ir3Instruction::InOp {
                dst: 7,
                lhs: 6,
                rhs: 3,
            },
            Ir3Instruction::Return { value: 7 },
        ],
    )
}

fn own_descriptor_excludes_inherited_module() -> Ir3Module {
    inherited_descriptor_value_module(true)
}

fn inherited_descriptor_lookup_module() -> Ir3Module {
    inherited_descriptor_value_module(false)
}

fn frozen_configurable_descriptor_module() -> Ir3Module {
    frozen_descriptor_flag_module("configurable")
}

fn proxy_get_no_trap_fallback_module() -> Ir3Module {
    module(
        "proxy-get-no-trap-fallback",
        vec!["slot", "target"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::NewObject { dst: 1 },
            Ir3Instruction::HostCall {
                capability: builtin("Proxy"),
                args: RegRange { start: 0, count: 2 },
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
    )
}

fn own_descriptor_value_module() -> Ir3Module {
    module(
        "own-descriptor-value",
        vec!["ownProp", "value"],
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
            Ir3Instruction::HostCall {
                capability: builtin("ObjectGetOwnPropertyDescriptor"),
                args: RegRange { start: 0, count: 2 },
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
    )
}

fn inherited_descriptor_value_module(own_only: bool) -> Ir3Module {
    let capability = if own_only {
        "ObjectGetOwnPropertyDescriptor"
    } else {
        "ObjectGetPropertyDescriptor"
    };
    let mut instructions = vec![
        Ir3Instruction::NewObject { dst: 0 },
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 0,
        },
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 1,
        },
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 1,
            val: 2,
        },
        Ir3Instruction::NewObject { dst: 3 },
        Ir3Instruction::Move { dst: 4, src: 0 },
        Ir3Instruction::HostCall {
            capability: builtin("ObjectSetPrototypeOf"),
            args: RegRange { start: 3, count: 2 },
            dst: 5,
        },
        Ir3Instruction::LoadStr {
            dst: 4,
            pool_index: 0,
        },
        Ir3Instruction::HostCall {
            capability: builtin(capability),
            args: RegRange { start: 3, count: 2 },
            dst: 6,
        },
    ];

    if own_only {
        instructions.push(Ir3Instruction::Return { value: 6 });
    } else {
        instructions.extend([
            Ir3Instruction::LoadStr {
                dst: 7,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 6,
                key: 7,
                dst: 8,
            },
            Ir3Instruction::Return { value: 8 },
        ]);
    }

    module(
        "inherited-descriptor-value",
        vec!["inheritedProp", "inherited", "value"],
        instructions,
    )
}

fn missing_descriptor_module() -> Ir3Module {
    module(
        "missing-descriptor",
        vec!["missingProp"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectGetPropertyDescriptor"),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
        ],
    )
}

fn frozen_descriptor_flag_module(flag: &str) -> Ir3Module {
    module(
        "frozen-descriptor-flags",
        vec!["frozenProp", "frozen", flag],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectFreeze"),
                args: RegRange { start: 0, count: 1 },
                dst: 3,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectGetOwnPropertyDescriptor"),
                args: RegRange { start: 0, count: 2 },
                dst: 4,
            },
            Ir3Instruction::LoadStr {
                dst: 5,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 4,
                key: 5,
                dst: 6,
            },
            Ir3Instruction::Return { value: 6 },
        ],
    )
}

fn shadowed_descriptor_value_module(own_only: bool) -> Ir3Module {
    let capability = if own_only {
        "ObjectGetOwnPropertyDescriptor"
    } else {
        "ObjectGetPropertyDescriptor"
    };
    module(
        "shadowed-descriptor",
        vec!["shadowProp", "parent", "child", "value"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::NewObject { dst: 3 },
            Ir3Instruction::Move { dst: 4, src: 0 },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectSetPrototypeOf"),
                args: RegRange { start: 3, count: 2 },
                dst: 5,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 3,
                key: 1,
                val: 4,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin(capability),
                args: RegRange { start: 3, count: 2 },
                dst: 6,
            },
            Ir3Instruction::LoadStr {
                dst: 7,
                pool_index: 3,
            },
            Ir3Instruction::GetProperty {
                obj: 6,
                key: 7,
                dst: 8,
            },
            Ir3Instruction::Return { value: 8 },
        ],
    )
}

/// Run a single conformance case end-to-end. Factored out so each per-case
/// `#[test]` below can isolate hangs / panics to its own line of the matrix.
/// (bd-f4ycb)
fn run_conformance_case(case_id: &'static str) {
    let case = conformance_cases()
        .into_iter()
        .find(|c| c.id == case_id)
        .unwrap_or_else(|| panic!("no conformance case named `{case_id}`"));
    assert!(
        !case.spec_ref.is_empty(),
        "{} has no spec reference",
        case.id
    );
    let module = (case.module)();
    let result = execute(&module).unwrap_or_else(|err| {
        panic!(
            "{} ({}) should execute, got {err:?}",
            case.id, case.requirement
        )
    });
    case.expected.assert_matches(&result.value, &case);
}

#[test]
fn prototype_property_descriptor_conformance_matrix() {
    for case in conformance_cases() {
        run_conformance_case(case.id);
    }
}

#[test]
fn prototype_conformance_get_own_data() {
    run_conformance_case("get-own-data");
}

#[test]
fn prototype_conformance_get_inherited_data() {
    run_conformance_case("get-inherited-data");
}

#[test]
fn prototype_conformance_get_own_shadows_inherited() {
    run_conformance_case("get-own-shadows-inherited");
}

#[test]
fn prototype_conformance_set_creates_own_shadow() {
    run_conformance_case("set-creates-own-shadow");
}

#[test]
fn prototype_conformance_delete_own_reveals_inherited() {
    run_conformance_case("delete-own-reveals-inherited");
}

#[test]
fn prototype_conformance_in_finds_inherited() {
    run_conformance_case("in-finds-inherited");
}

#[test]
fn prototype_conformance_in_missing_false() {
    run_conformance_case("in-missing-false");
}

#[test]
fn prototype_conformance_descriptor_own_value() {
    run_conformance_case("descriptor-own-value");
}

#[test]
fn prototype_conformance_descriptor_inherited_value() {
    run_conformance_case("descriptor-inherited-value");
}

#[test]
fn prototype_conformance_own_descriptor_excludes_inherited() {
    run_conformance_case("own-descriptor-excludes-inherited");
}

#[test]
fn prototype_conformance_descriptor_frozen_non_configurable() {
    run_conformance_case("descriptor-frozen-non-configurable");
}

#[test]
fn prototype_conformance_proxy_get_no_trap_fallback() {
    let started = Instant::now();
    run_conformance_case("proxy-get-no-trap-fallback");
    assert!(
        started.elapsed() < PROXY_GET_FALLBACK_MAX_ELAPSED,
        "proxy-get-no-trap-fallback exceeded {:?}",
        PROXY_GET_FALLBACK_MAX_ELAPSED
    );
}

#[test]
fn prototype_property_descriptor_conformance_inventory_is_explicit() {
    let cases = conformance_cases();
    assert!(
        (8..=12).contains(&cases.len()),
        "expected 8-12 executable conformance cases, got {}",
        cases.len()
    );

    let mut ids = BTreeSet::new();
    for case in cases {
        assert!(
            ids.insert(case.id),
            "duplicate conformance case id {}",
            case.id
        );
        assert!(
            !case.requirement.is_empty(),
            "{} must describe the enforced requirement",
            case.id
        );
        assert!(
            !case.spec_ref.is_empty(),
            "{} must reference the spec surface",
            case.id
        );
    }

    let mut waived = BTreeSet::new();
    for semantic in UNSUPPORTED_SEMANTICS {
        assert!(
            waived.insert(semantic.id),
            "duplicate unsupported semantic waiver {}",
            semantic.id
        );
        assert!(
            !semantic.spec_ref.is_empty() && !semantic.reason.is_empty(),
            "{} must document both spec reference and waiver reason",
            semantic.id
        );
    }
}

#[test]
fn own_property_descriptor_exposes_value() {
    let result = execute(&own_descriptor_value_module()).expect("own descriptor should execute");
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn own_property_descriptor_ignores_inherited_properties() {
    let result = execute(&inherited_descriptor_value_module(true))
        .expect("own descriptor lookup should execute");
    assert_eq!(result.value, Value::Undefined);
}

#[test]
fn prototype_chain_descriptor_finds_inherited_properties() {
    let result = execute(&inherited_descriptor_value_module(false))
        .expect("prototype descriptor lookup should execute");
    assert_eq!(result.value, Value::str("inherited"));
}

#[test]
fn prototype_chain_descriptor_returns_undefined_for_missing_property() {
    let result = execute(&missing_descriptor_module()).expect("missing descriptor should execute");
    assert_eq!(result.value, Value::Undefined);
}

#[test]
fn frozen_own_descriptor_reports_non_writable_and_non_configurable() {
    let writable = execute(&frozen_descriptor_flag_module("writable"))
        .expect("frozen writable descriptor should execute");
    let configurable = execute(&frozen_descriptor_flag_module("configurable"))
        .expect("frozen configurable descriptor should execute");

    assert_eq!(writable.value, Value::Bool(false));
    assert_eq!(configurable.value, Value::Bool(false));
}

#[test]
fn shadowed_property_descriptor_prefers_child_value() {
    let own = execute(&shadowed_descriptor_value_module(true))
        .expect("own shadowed descriptor should execute");
    let inherited = execute(&shadowed_descriptor_value_module(false))
        .expect("prototype shadowed descriptor should execute");

    assert_eq!(own.value, Value::str("child"));
    assert_eq!(inherited.value, Value::str("child"));
}

// The former `#[cfg(any())] mod legacy_private_heap_descriptor_tests` block was removed
// here (bd-bg9l1.24). It never compiled — it referenced removed private heap-descriptor
// APIs. Own / inherited / shadowed / missing descriptors, accessor & frozen/sealed
// descriptor flags and deep prototype chains are covered by the active current-API tests
// and the `prototype_property_descriptor_conformance_matrix` above in this file.
