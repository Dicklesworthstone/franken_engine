//! Immutable global value names must resolve as identifiers before folding.
//! Exercise the public parser/lowering/runtime path in both core profiles.

use std::collections::BTreeSet;

use frankenengine_core::ast::{Expression, ParseGoal, Statement};
use frankenengine_core::baseline_interpreter::{
    InterpreterConfig, InterpreterError, QuickJsLane, V8Lane, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn execute_both(source: &str) -> [Result<Value, InterpreterError>; 2] {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .unwrap_or_else(|error| panic!("parse {source:?}: {error:?}"));
    let ir0 = Ir0Module::from_syntax_tree(tree, "global-value-bindings");
    let context = LoweringContext::new("globals-trace", "globals-decision", "globals-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .unwrap_or_else(|error| panic!("lower {source:?}: {error:?}"))
        .ir3;
    let grants = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    let mut quickjs = InterpreterConfig::quickjs_defaults();
    quickjs.granted_capabilities = grants.clone();
    let mut v8 = InterpreterConfig::v8_defaults();
    v8.granted_capabilities = grants;
    [
        QuickJsLane::with_config(quickjs)
            .execute(&module, "globals-trace")
            .map(|result| result.value),
        V8Lane::with_config(v8)
            .execute(&module, "globals-trace")
            .map(|result| result.value),
    ]
}

fn assert_value(source: &str, expected: Value) {
    for (lane, result) in execute_both(source).into_iter().enumerate() {
        assert_eq!(
            result.unwrap_or_else(|error| panic!("lane {lane}, {source:?}: {error:?}")),
            expected,
            "lane {lane}, {source:?}"
        );
    }
}

#[test]
fn unshadowed_global_values_keep_their_numeric_and_undefined_semantics() {
    for source in [
        "undefined === void 0;",
        "NaN !== NaN;",
        "Infinity === 1 / 0;",
        "-Infinity === -1 / 0;",
        "typeof undefined === 'undefined' && typeof NaN === 'number' && typeof Infinity === 'number';",
        "(function () { return Infinity === 1 / 0 && NaN !== NaN && undefined === void 0; })();",
        "(function (x = Infinity, y = NaN, z = undefined) { return x === 1 / 0 && y !== y && z === void 0; })();",
        r"undef\u0069ned === void 0 && N\u0061N !== NaN && Inf\u0069nity === Infinity;",
        "delete undefined === false && delete NaN === false && delete Infinity === false;",
    ] {
        assert_value(source, Value::Bool(true));
    }
}

#[test]
fn parameters_and_local_declarations_shadow_all_three_names() {
    for source in [
        "(function (undefined, NaN, Infinity) { return undefined + NaN + Infinity; })(2, 3, 5);",
        "(function () { var undefined = 2; var NaN = 3; var Infinity = 5; return undefined + NaN + Infinity; })();",
        "(function () { let undefined = 2; const NaN = 3; let Infinity = 5; return undefined + NaN + Infinity; })();",
        "((undefined, NaN, Infinity) => undefined + NaN + Infinity)(2, 3, 5);",
        r"(function (undef\u0069ned, N\u0061N, Inf\u0069nity) { return undefined + NaN + Infinity; })(2, 3, 5);",
    ] {
        assert_value(source, Value::Int(10));
    }
}

#[test]
fn closures_preserve_outer_binding_identity_and_live_updates() {
    for source in [
        "(function (undefined) { function read() { return undefined; } undefined = 7; return read(); })(2);",
        "(function (NaN) { return function () { return () => NaN; }; })(7)()();",
        "(function (Infinity) { return { read() { return Infinity; } }; })(7).read();",
        "(function () { let undefined = 2; function read() { return undefined; } undefined = 7; return read(); })();",
        "(function () { let Infinity = 2; const read = () => Infinity; Infinity = 7; return read(); })();",
        "(function () { let NaN = 7; class C { read() { return NaN; } } return new C().read(); })();",
    ] {
        assert_value(source, Value::Int(7));
    }
}

#[test]
fn default_parameter_resolution_does_not_capture_body_declarations() {
    assert_value(
        "(function () { let Infinity = 7; function f(value = Infinity) { let Infinity = 2; return value; } return f(); })();",
        Value::Int(7),
    );
    assert_value(
        "(function (undefined = 2, NaN = undefined + 1, Infinity = NaN + 4) { return Infinity; })();",
        Value::Int(7),
    );
    assert_value(
        "(function (x = undefined) { var undefined = 7; return x === void 0; })();",
        Value::Bool(true),
    );
}

#[test]
fn writes_and_updates_target_shadowing_bindings() {
    assert_value(
        "(function (undefined, NaN, Infinity) { undefined += 2; var old = NaN++; ++Infinity; return undefined === 4 && old === 3 && NaN === 4 && Infinity === 6; })(2, 3, 5);",
        Value::Bool(true),
    );
    assert_value(
        "(function (undefined) { var read = () => undefined; undefined++; return read(); })(6);",
        Value::Int(7),
    );
}

#[test]
fn block_scope_and_hoisted_var_resolution_precede_global_folding() {
    assert_value(
        "let result = 0; { let undefined = 2; let NaN = 3; let Infinity = 5; result = undefined + NaN + Infinity; } result === 10 && undefined === void 0 && NaN !== NaN && Infinity === 1 / 0;",
        Value::Bool(true),
    );
    assert_value(
        "(function () { var before = Infinity; if (false) { var Infinity = 3; } return before === void 0; })();",
        Value::Bool(true),
    );
}

#[test]
fn parameter_temporal_dead_zone_is_not_folded_to_a_global_value() {
    for source in [
        "(function (x = undefined, undefined = 7) { return x; })();",
        "(function (x = NaN, NaN = 7) { return x; })();",
        "(function (x = Infinity, Infinity = 7) { return x; })();",
    ] {
        for (lane, result) in execute_both(source).into_iter().enumerate() {
            let error = result.expect_err("later parameter access must fail its TDZ");
            assert!(
                error.to_string().contains("before initialization"),
                "lane {lane}, {source:?}: {error}"
            );
        }
    }
}

#[test]
fn assignments_and_updates_parse_as_identifier_references() {
    for source in ["undefined = 7;", "NaN += 1;", "Infinity++;", "--undefined;"] {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect("global property names are valid assignment references");
        let Statement::Expression(statement) = &tree.body[0] else {
            panic!("expected an expression statement");
        };
        let reference = match &statement.expression {
            Expression::Assignment { left, .. } => left,
            Expression::Update { argument, .. } => argument,
            other => panic!("expected assignment or update, got {other:?}"),
        };
        assert!(matches!(reference.as_ref(), Expression::Identifier(_)));

        // The core AST has no strictness provenance yet. Preserve an explicit
        // refusal until writes can distinguish strict throws from sloppy no-ops,
        // instead of fabricating a mutable global with a forward binding.
        let ir0 = Ir0Module::from_syntax_tree(tree, "global-write");
        let context = LoweringContext::new("write-trace", "write-decision", "write-policy");
        let error = lower_ir0_to_ir3(&ir0, &context)
            .expect_err("unshadowed globals must not become mutable bindings");
        assert!(
            error.to_string().contains("strictness provenance"),
            "{source}: {error}"
        );
    }
}
