//! bd-2vzgi — franken-core lone-surrogate string parity with the engine's
//! JsString model (bd-neika), pinned end-to-end through real source
//! execution: parse → IR0 → IR3 → QuickJsLane.
//!
//! These mirror the engine-side acceptance tests in
//! `crates/franken-engine/tests/js_string_integration.rs` for the surface
//! franken-core executes: `length`, `charAt`, `charCodeAt`, `codePointAt`,
//! `at`, `String.fromCharCode`, `+` concatenation healing, and template
//! literals. The differential-oracle seed corpus consensus over the same
//! programs lives in the engine crate
//! (`differential_oracle::default_engine_core_corpus`).

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterError, QuickJsLane, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::{Ir0Module, Ir1Op, Ir3Instruction};
use frankenengine_core::js_string::JsString;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir1, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

use std::collections::BTreeSet;

const HIGH: u16 = 0xD83D;
const LOW: u16 = 0xDE00;

/// Parse -> IR0 -> IR3 -> execute on the QuickJS lane with the minimal
/// execution capabilities, returning the full execution result.
fn run(source: &str) -> ExecutionResult {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_2vzgi");
    let context = LoweringContext::new("bd-2vzgi-trace", "bd-2vzgi-decision", "bd-2vzgi-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config)
        .execute(&module, "bd-2vzgi-trace")
        .unwrap_or_else(|error| panic!("execution should succeed for {source:?}: {error:?}"))
}

/// Completion value of a script whose final statement is an expression.
fn completion(source: &str) -> Value {
    run(source).value
}

/// Execute source that must FAIL at runtime, returning the interpreter error.
fn completion_err(source: &str) -> InterpreterError {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_7zwar");
    let context = LoweringContext::new("bd-7zwar-trace", "bd-7zwar-decision", "bd-7zwar-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config)
        .execute(&module, "bd-7zwar-trace")
        .expect_err("execution should fail")
}

fn lone(units: &[u16]) -> Value {
    Value::Str(JsString::from_code_units(units))
}

// --- length is the UTF-16 code-unit count -----------------------------------

#[test]
fn string_length_counts_utf16_code_units() {
    assert_eq!(completion("\"a\u{1F600}b\".length;"), Value::Int(4));
    assert_eq!(completion("\"abc\".length;"), Value::Int(3));
    assert_eq!(completion("\"\".length;"), Value::Int(0));
}

// --- charAt over exact code units --------------------------------------------

#[test]
fn char_at_surrogate_half_is_a_real_lone_surrogate() {
    let result = completion("\"a\u{1F600}b\".charAt(1);");
    assert_eq!(result, lone(&[HIGH]));
    let Value::Str(s) = result else {
        panic!("charAt must return a string value");
    };
    assert!(!s.is_well_formed());
    assert_eq!(s.code_units_vec(), vec![HIGH]);
    assert_eq!(s.as_utf8_projection(), "\u{FFFD}");
}

#[test]
fn char_at_bmp_unit_stays_well_formed() {
    assert_eq!(completion("\"a\u{1F600}b\".charAt(0);"), Value::str("a"));
    assert_eq!(completion("\"a\u{1F600}b\".charAt(3);"), Value::str("b"));
}

#[test]
fn char_at_out_of_range_and_negative_yield_empty_string() {
    assert_eq!(completion("\"ab\".charAt(9);"), Value::str(""));
    assert_eq!(completion("\"ab\".charAt(-1);"), Value::str(""));
}

// --- concatenation healing (the bd-2vzgi acceptance criterion) ---------------

#[test]
fn char_at_halves_heal_on_concatenation_to_strict_equal_original() {
    let src = "var s = \"a\u{1F600}b\"; (s.charAt(1) + s.charAt(2)) === \"\u{1F600}\";";
    assert_eq!(completion(src), Value::Bool(true));
}

#[test]
fn char_at_halves_heal_into_well_formed_value() {
    let result = completion("var s = \"a\u{1F600}b\"; s.charAt(1) + s.charAt(2);");
    assert_eq!(result, Value::str("\u{1F600}"));
    let Value::Str(healed) = result else {
        panic!("concat must return a string value");
    };
    assert!(healed.is_well_formed());
    assert_eq!(healed.code_units_vec(), vec![HIGH, LOW]);
}

#[test]
fn template_literal_heals_split_surrogate_parts() {
    let src = "var s = \"a\u{1F600}b\"; `${s.charAt(1)}${s.charAt(2)}` === \"\u{1F600}\";";
    assert_eq!(completion(src), Value::Bool(true));
}

// --- charCodeAt / codePointAt / at -------------------------------------------

#[test]
fn char_code_at_reads_exact_code_units() {
    assert_eq!(
        completion("\"a\u{1F600}b\".charCodeAt(1);"),
        Value::Int(i64::from(HIGH))
    );
    assert_eq!(
        completion("\"a\u{1F600}b\".charCodeAt(2);"),
        Value::Int(i64::from(LOW))
    );
    assert_eq!(completion("\"a\u{1F600}b\".charCodeAt(0);"), Value::Int(97));
}

#[test]
fn char_code_at_out_of_range_is_nan() {
    let result = completion("\"ab\".charCodeAt(9);");
    let Value::Float(f) = result else {
        panic!("out-of-range charCodeAt must be a float NaN, got {result:?}");
    };
    assert!(f.inner().is_nan());
}

#[test]
fn code_point_at_is_utf16_unit_indexed() {
    // UTF-16 code-unit indexed per ES2015 CodePointAt, matching the engine
    // seams upgraded by bd-rdnhc: index 1 lands on the high surrogate of the
    // pair (combines to U+1F600), index 2 lands on the unpaired view of the
    // low surrogate (yields its own unit value), index 3 is 'b'.
    assert_eq!(
        completion("\"a\u{1F600}b\".codePointAt(1);"),
        Value::Int(0x1F600)
    );
    assert_eq!(
        completion("\"a\u{1F600}b\".codePointAt(2);"),
        Value::Int(i64::from(LOW))
    );
    assert_eq!(
        completion("\"a\u{1F600}b\".codePointAt(3);"),
        Value::Int(98)
    );
    assert_eq!(
        completion("\"a\u{1F600}b\".codePointAt(4);"),
        Value::Undefined
    );
    assert_eq!(completion("\"ab\".codePointAt(9);"), Value::Undefined);
}

#[test]
fn string_at_supports_relative_code_unit_indexing() {
    assert_eq!(completion("\"a\u{1F600}b\".at(1);"), lone(&[HIGH]));
    assert_eq!(completion("\"a\u{1F600}b\".at(-1);"), Value::str("b"));
    assert_eq!(completion("\"a\u{1F600}b\".at(9);"), Value::Undefined);
}

// --- String.fromCharCode ------------------------------------------------------

#[test]
fn from_char_code_lone_surrogate_is_exact() {
    let result = completion("String.fromCharCode(55357);");
    assert_eq!(result, lone(&[HIGH]));
    let Value::Str(s) = result else {
        panic!("fromCharCode must return a string value");
    };
    assert!(!s.is_well_formed());
}

#[test]
fn from_char_code_pair_heals_to_supplementary() {
    assert_eq!(
        completion("String.fromCharCode(55357, 56832);"),
        Value::str("\u{1F600}")
    );
}

#[test]
fn from_char_code_round_trips_through_char_code_at() {
    assert_eq!(
        completion("String.fromCharCode(97, 55357).charCodeAt(1);"),
        Value::Int(i64::from(HIGH))
    );
}

#[test]
fn distinct_lone_surrogates_are_not_strictly_equal() {
    assert_eq!(
        completion("String.fromCharCode(55296) === String.fromCharCode(55297);"),
        Value::Bool(false)
    );
    assert_eq!(
        completion("String.fromCharCode(55296) === String.fromCharCode(55296);"),
        Value::Bool(true)
    );
}

#[test]
fn lone_surrogate_never_equals_its_lossy_projection() {
    assert_eq!(
        completion("String.fromCharCode(55357) === \"\u{FFFD}\";"),
        Value::Bool(false)
    );
}

// --- length/charAt through the healed value -----------------------------------

#[test]
fn healed_concat_has_supplementary_length_two() {
    assert_eq!(
        completion("var s = \"a\u{1F600}b\"; (s.charAt(1) + s.charAt(2)).length;"),
        Value::Int(2)
    );
    assert_eq!(
        completion("String.fromCharCode(55357).length;"),
        Value::Int(1)
    );
}

// --- bd-7zwar: core string-surface residual upgrades ---------------------------
//
// String.fromCodePoint, ES2024 isWellFormed/toWellFormed, JSON.stringify
// reachability from source, unknown-property-yields-undefined, code-unit
// relational order, and code-point-grain for..of / spread — all engine
// parity with bd-rdnhc.

#[test]
fn from_code_point_lone_surrogate_and_supplementary() {
    let result = completion("String.fromCodePoint(55296);");
    assert_eq!(result, lone(&[0xD800]));
    assert_eq!(
        completion("String.fromCodePoint(128512);"),
        Value::str("\u{1F600}")
    );
    assert_eq!(
        completion("String.fromCodePoint(97, 128512, 98);"),
        Value::str("a\u{1F600}b")
    );
}

#[test]
fn from_code_point_out_of_range_is_a_range_error() {
    let err = completion_err("String.fromCodePoint(1114112);"); // 0x110000
    assert!(
        matches!(err, InterpreterError::RangeError { .. }),
        "out-of-range code point must be a RangeError, got {err:?}"
    );
    let err = completion_err("String.fromCodePoint(1.5);");
    assert!(
        matches!(err, InterpreterError::RangeError { .. }),
        "non-integral code point must be a RangeError, got {err:?}"
    );
}

#[test]
fn is_well_formed_and_to_well_formed_report_real_surrogate_state() {
    assert_eq!(
        completion("\"a\u{1F600}b\".isWellFormed();"),
        Value::Bool(true)
    );
    assert_eq!(
        completion("String.fromCharCode(55296).isWellFormed();"),
        Value::Bool(false)
    );
    assert_eq!(
        completion("String.fromCharCode(55296).toWellFormed();"),
        Value::str("\u{FFFD}")
    );
    assert_eq!(completion("\"ok\".toWellFormed();"), Value::str("ok"));
}

#[test]
fn json_stringify_is_reachable_from_source_and_escapes_lone_surrogates() {
    let result = completion("JSON.stringify(String.fromCharCode(55296));");
    let Value::Str(s) = result else {
        panic!("JSON.stringify must return a string value");
    };
    assert_eq!(s.as_str(), Some("\"\\ud800\""));
    assert_eq!(completion("JSON.stringify(\"hi\");"), Value::str("\"hi\""));
}

// --- bd-zql4d: core unbound-global static builtin reachability ----------------

#[test]
fn executable_static_builtin_families_are_reachable_from_source() {
    assert_eq!(completion("Math.abs(-7);"), Value::Int(7));
    assert_eq!(
        completion("Object.keys({b: 2, a: 1}).length;"),
        Value::Int(2)
    );
    assert_eq!(completion("Object.values({a: 11})[0];"), Value::Int(11));
    assert_eq!(completion("Array.isArray([1, 2]);"), Value::Bool(true));
    assert_eq!(completion("Array.isArray({0: 1});"), Value::Bool(false));
}

#[test]
fn static_builtin_interception_supports_literal_computed_names_and_shadowing() {
    assert_eq!(completion("Math[\"abs\"](-9);"), Value::Int(9));
    assert_eq!(
        completion("let Math = {abs: function (x) { return x + 40; }}; Math.abs(2);"),
        Value::Int(42)
    );
    assert_eq!(
        completion("let JSON = {parse: function (x) { return x; }}; JSON.parse(17);"),
        Value::Int(17)
    );
    assert_eq!(completion("Math; Math.abs(-7);"), Value::Int(7));
    assert_eq!(
        completion("(function () { Math; return Math.abs(-8); })();"),
        Value::Int(8)
    );
    assert_eq!(
        completion(
            "let Math = {abs: function (x) { return x + 40; }}; \
             (function () { return Math.abs(2); })();"
        ),
        Value::Int(42)
    );

    let err = completion_err(
        "(function () { return Math.abs(-7); let Math = {abs: function () { return 99; }}; })();",
    );
    assert!(
        matches!(err, InterpreterError::TypeError { .. }),
        "a later lexical Math declaration must shadow the synthetic global, got {err:?}"
    );

    let err = completion_err("(function () { { return Math.abs(-7); let Math; } })();");
    assert!(
        matches!(err, InterpreterError::TypeError { .. }),
        "a block lexical Math declaration must shadow the synthetic global before initialization, got {err:?}"
    );
    assert_eq!(
        completion("{ let Math = {abs: function () { return 99; }}; }; Math.abs(-7);"),
        Value::Int(7),
        "a block lexical binding must not shadow the global after its block"
    );

    let assert_math_abs_not_intercepted = |source: &str| {
        fn contains_math_abs(ops: &[Ir1Op]) -> bool {
            ops.iter().any(|op| match op {
                Ir1Op::HostCall { capability, .. } => capability == "builtin:MathAbs",
                Ir1Op::DeclareFunction { body_ops, .. }
                | Ir1Op::CreateFunction { body_ops, .. } => contains_math_abs(body_ops),
                _ => false,
            })
        }

        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect("shadowing source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "bd_zql4d_container_shadow");
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("shadowing source should lower")
            .module;
        assert!(
            !contains_math_abs(&ir1.ops),
            "container-local Math must suppress static interception for {source}"
        );
    };

    for source in [
        "(function () { try { return Math.abs(-7); let Math; } finally {} })();",
        "(function () { try { throw 1; } catch (e) { return Math.abs(-7); let Math; } })();",
        "(function () { try {} finally { return Math.abs(-7); let Math; } })();",
        "(function () { switch (0) { case 0: return Math.abs(-7); case 1: let Math; } })();",
    ] {
        assert_math_abs_not_intercepted(source);
    }

    assert_math_abs_not_intercepted(
        "(function () { try { throw {abs: function (x) { return x + 40; }}; } \
         catch (Math) { return Math.abs(2); } })();",
    );
    assert_math_abs_not_intercepted("for (let Math of [Math.abs(-1)]) {}");
    assert_math_abs_not_intercepted("(function Math() { return Math.abs(-2); })();");
    assert_math_abs_not_intercepted(
        "(function ({Math}) { return Math.abs(2); })({Math: {abs: function (x) { return x + 40; }}});",
    );
    let err = completion_err("(function Math() { return Math.abs(-2); })();");
    assert!(
        matches!(err, InterpreterError::TypeError { .. }),
        "a named function expression must shadow the synthetic Math global, got {err:?}"
    );
    assert_eq!(
        completion(
            "(function Math() { \
               let Math = {abs: function (x) { return x + 40; }}; \
               return Math.abs(2); \
             })();"
        ),
        Value::Int(42),
        "a function-body lexical declaration must shadow its named-expression self binding"
    );
    assert_eq!(
        completion(
            "(function () { while (true) { try { break; } finally { let Math; } } return 7; })();"
        ),
        Value::Int(7),
        "duplicated finalizer control-flow paths need independent lexical bindings"
    );
    assert_eq!(
        completion("for (let Math = 0; Math < 1; Math = Math + 1) {} Math.abs(-2);"),
        Value::Int(2),
        "a C-style loop lexical binding must not leak after the loop"
    );
    assert_eq!(
        completion(
            "let Math = {abs: function (x) { return x + 40; }}; \
             for (let Math of [1]) {} Math.abs(2);"
        ),
        Value::Int(42),
        "for-of must restore an outer same-name lexical binding"
    );
    let err = completion_err("let x = [1]; for (let x of x) {}");
    assert!(
        matches!(err, InterpreterError::TypeError { .. }),
        "the lexical for-of head must shadow its RHS during the TDZ, got {err:?}"
    );
    let err = completion_err("let obj = {a: 1}; for (let obj in obj) {}");
    assert!(
        matches!(err, InterpreterError::TypeError { .. }),
        "the lexical for-in head must shadow its RHS during the TDZ, got {err:?}"
    );
    assert_eq!(
        completion("let x = 0; for (x of [1]) {} x;"),
        Value::Int(1),
        "a bare for-of target must assign the existing binding"
    );
    assert_eq!(
        completion("let k = ''; for (k in {a: 1}) {} k;"),
        Value::str("a"),
        "a bare for-in target must assign the existing binding"
    );

    let err = completion_err("(function () { return Math.abs(-7); if (false) { var Math; } })();");
    assert!(
        matches!(err, InterpreterError::TypeError { .. }),
        "a nested hoisted var must shadow Math across the function, got {err:?}"
    );

    assert_eq!(
        completion(
            "let Math = {abs: function (x) { return x + 40; }}; \
             class C { m() { return Math.abs(2); } } \
             (new C()).m();"
        ),
        Value::Int(42)
    );
    assert_eq!(
        completion(
            "let Math = {abs: function () { return 1; }}; let f; \
             { let Math = {abs: function () { return 2; }}; \
               f = function () { return Math.abs(0); }; }; f();"
        ),
        Value::Int(2),
        "a closure must capture the exact active same-name block binding"
    );
    assert_eq!(
        completion(
            "(function () { let Math = {abs: function () { return 1; }}; let f; \
               { let Math = {abs: function () { return 2; }}; \
                 f = function () { return Math.abs(0); }; }; \
               let g = function () { return Math.abs(0); }; \
               return f() * 10 + g(); })();"
        ),
        Value::Int(21),
        "nested closures created on opposite sides of a block boundary must capture distinct bindings"
    );
}

#[test]
fn block_lexical_shadow_is_removed_before_later_static_builtin_lowering() {
    let source = "{ let Math = {abs: function () { return 99; }}; }; Math.abs(-7);";
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_zql4d_block_scope");
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("source should lower to IR1")
        .module;
    assert!(
        ir1.ops.iter().any(|op| matches!(
            op,
            Ir1Op::HostCall { capability, .. } if capability == "builtin:MathAbs"
        )),
        "IR1 ops and scopes: {ir1:#?}"
    );
}

#[test]
fn nested_class_capture_metadata_names_the_exact_enclosing_local() {
    let source = "(function () { let x = 1; \
           let Math = {abs: function (n) { return n + 40; }}; \
           class C { m() { return Math.abs(2); } } \
           return (new C()).m(); })();";
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_zql4d_nested_class_capture");
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("source should lower to IR1")
        .module;
    let outer_body = ir1
        .ops
        .iter()
        .find_map(|op| match op {
            Ir1Op::CreateFunction { body_ops, .. } => Some(body_ops),
            _ => None,
        })
        .expect("outer function body");
    let (names, outer_ids) = outer_body
        .iter()
        .find_map(|op| match op {
            Ir1Op::CreateFunction {
                name: Some(name),
                free_vars,
                free_var_outer_ids,
                ..
            } if name == "m" => Some((free_vars, free_var_outer_ids)),
            _ => None,
        })
        .expect("class method closure metadata");

    assert_eq!(names, &["Math"]);
    assert_eq!(outer_ids, &[1]);
    assert_ne!(
        outer_ids,
        &[0],
        "the earlier non-captured x binding is id 0"
    );
}

#[test]
fn nested_static_builtin_authority_is_consistent_across_ir2_proof_and_ir3() {
    let source = "(function () { return (function () { return Math.abs(-4); })(); })();";
    let lower = || {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect("source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "bd_zql4d_nested_authority");
        let context = LoweringContext::new(
            "bd-zql4d-nested-trace",
            "bd-zql4d-nested-decision",
            "bd-zql4d-nested-policy",
        );
        lower_ir0_to_ir3(&ir0, &context).expect("source should lower")
    };
    let first = lower();
    let second = lower();
    let capability = "builtin:MathAbs";

    assert!(
        first
            .ir2
            .required_capabilities
            .iter()
            .any(|candidate| candidate.0 == capability),
        "function-only capability must be represented in IR2"
    );
    assert!(
        first
            .ir3
            .required_capabilities
            .iter()
            .any(|candidate| candidate.0 == capability),
        "function-only capability must survive into IR3"
    );
    assert!(first.ir3.instructions.iter().any(|instruction| matches!(
        instruction,
        Ir3Instruction::HostCall { capability: candidate, .. } if candidate.0 == capability
    )));
    let proof_entry = first
        .ir2_flow_proof_artifact
        .proved_flows
        .iter()
        .find(|entry| entry.capability.as_deref() == Some(capability))
        .expect("function-only capability must have an IR2 flow proof entry");
    assert!(
        proof_entry.op_index < first.ir2.ops.len() as u64,
        "nested proof sites must retain the top-level authority index namespace"
    );
    assert_eq!(
        first.ir2_flow_proof_artifact, second.ir2_flow_proof_artifact,
        "nested proof-site analysis must be deterministic"
    );
}

#[test]
fn json_parse_preserves_raw_lone_surrogate_units() {
    assert_eq!(
        completion(
            "let quote = String.fromCharCode(34); \
             let lone = String.fromCharCode(55296); \
             JSON.parse(quote + lone + quote).charCodeAt(0);"
        ),
        Value::Int(55296)
    );
}

#[test]
fn repeated_nested_flows_have_distinct_deterministic_body_paths() {
    let source = "(function () { Math.abs(-1); return Math.abs(-2); })();";
    let lower = || {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect("source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "bd_zql4d_nested_flow_sites");
        let context = LoweringContext::new(
            "bd-zql4d-site-trace",
            "bd-zql4d-site-decision",
            "bd-zql4d-site-policy",
        );
        lower_ir0_to_ir3(&ir0, &context).expect("source should lower")
    };
    let first = lower();
    let second = lower();
    let entries = first
        .ir2_flow_proof_artifact
        .proved_flows
        .iter()
        .filter(|entry| entry.capability.as_deref() == Some("builtin:MathAbs"))
        .collect::<Vec<_>>();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].op_index, entries[1].op_index);
    assert!(!entries[0].body_path.is_empty());
    assert!(!entries[1].body_path.is_empty());
    assert_ne!(entries[0].body_path, entries[1].body_path);
    assert_eq!(
        first.ir2_flow_proof_artifact, second.ir2_flow_proof_artifact,
        "nested body paths and artifact hashes must be deterministic"
    );
}

#[test]
fn json_parse_builds_nested_core_heap_values() {
    assert_eq!(
        completion(r#"JSON.parse('{"a":[1,true,null]}').a[0];"#),
        Value::Int(1)
    );
    assert_eq!(
        completion(r#"JSON.parse('{"a":[1,true,null]}').a.length;"#),
        Value::Int(3)
    );
    assert_eq!(
        completion(r#"JSON.parse('{"a":[1,true,null]}').a[1];"#),
        Value::Bool(true)
    );
    assert_eq!(completion("JSON.parse(\"42\");"), Value::Int(42));
    assert_eq!(completion("JSON.parse(\"42 trailing\");"), Value::Undefined);
    for invalid in ["01", "-01", "1.", "1e", "1e+"] {
        assert_eq!(
            completion(&format!("JSON.parse('{invalid}');")),
            Value::Undefined,
            "invalid JSON number {invalid:?} must be rejected"
        );
    }
    let negative_zero = completion("JSON.parse('-0');");
    let Value::Float(negative_zero) = negative_zero else {
        panic!("JSON.parse('-0') must retain a floating negative zero");
    };
    assert!(negative_zero.is_negative_zero());
}

#[test]
fn json_parse_treats_internal_accessor_prefixes_as_literal_data_keys() {
    let key = "__franken_ir_accessor_get__:x";
    assert_eq!(
        completion(
            r#"let o = JSON.parse('{"__franken_ir_accessor_get__:x":1}');
               Object.keys(o)[0];"#
        ),
        Value::str(key)
    );
    assert_eq!(
        completion(
            r#"let o = JSON.parse('{"__franken_ir_accessor_get__:x":1}');
               o["__franken_ir_accessor_get__:x"];"#
        ),
        Value::Int(1)
    );
    assert_eq!(
        completion(r#"let o = JSON.parse('{"__franken_ir_accessor_get__:x":1}'); o.x;"#),
        Value::Undefined
    );
}

#[test]
fn json_parse_preserves_lone_surrogate_escape_units() {
    let parsed = completion("JSON.parse(JSON.stringify(String.fromCharCode(55296)));");
    assert_eq!(parsed, lone(&[0xD800]));
    assert_eq!(
        completion("JSON.parse(JSON.stringify(String.fromCharCode(55296))).charCodeAt(0);"),
        Value::Int(0xD800)
    );
    assert_eq!(
        completion(r#"JSON.parse('"' + '\uD83D' + '\uDE00' + '"');"#),
        Value::str("\u{1F600}")
    );
}

#[test]
fn unknown_property_on_string_receiver_yields_undefined() {
    assert_eq!(completion("\"abc\".nope;"), Value::Undefined);
    assert_eq!(
        completion("\"abc\".nope === \"abc\".alsoNope;"),
        Value::Bool(true)
    );
}

#[test]
fn string_relational_order_uses_utf16_code_units() {
    // Lone surrogates order by exact unit (0xD800 < 0xE000), not by the
    // U+FFFD projection (which would sort above U+E000).
    assert_eq!(
        completion("String.fromCharCode(55296) < String.fromCharCode(57344);"),
        Value::Bool(true)
    );
    assert_eq!(
        completion("String.fromCharCode(55296) < String.fromCharCode(55297);"),
        Value::Bool(true)
    );
    // Astral sorts below high-BMP under code-unit order.
    assert_eq!(
        completion("\"\u{1F600}\" < \"\u{FF5A}\";"),
        Value::Bool(true)
    );
    // Well-formed BMP ordering is unchanged.
    assert_eq!(completion("\"a\" < \"b\";"), Value::Bool(true));
    assert_eq!(completion("\"b\" <= \"a\";"), Value::Bool(false));
}

#[test]
fn for_of_iterates_code_points_and_preserves_lone_surrogates() {
    assert_eq!(
        completion("var n = 0; for (var c of \"a\u{1F600}b\") { n = n + 1; } n;"),
        Value::Int(3)
    );
    assert_eq!(
        completion(
            "var s = \"a\" + String.fromCharCode(55357) + \"b\"; \
             var codes = \"\"; \
             for (var c of s) { codes = codes + c.charCodeAt(0) + \",\"; } \
             codes;"
        ),
        Value::str("97,55357,98,")
    );
}

#[test]
fn spread_of_string_produces_code_point_elements() {
    assert_eq!(
        completion("var a = [...\"a\u{1F600}b\"]; a.length;"),
        Value::Int(3)
    );
    assert_eq!(
        completion("var a = [...String.fromCharCode(55296)]; a[0].charCodeAt(0);"),
        Value::Int(55296)
    );
}

#[test]
fn for_of_inside_a_function_body_terminates_and_counts_code_points() {
    // bd-ddloz: ForOf*/ForIn* ops previously lowered to NOPs inside
    // function bodies, leaving the loop's jumps intact — the loop never
    // advanced and spun to instruction-budget exhaustion.
    assert_eq!(
        completion(
            "(function () { var n = 0; for (var c of \"a\u{1F600}b\") { n = n + 1; } return n; })();"
        ),
        Value::Int(3)
    );
    assert_eq!(
        completion(
            "(function () { var out = \"\"; for (var c of \"xyz\") { out = out + c; } return out; })();"
        ),
        Value::str("xyz")
    );
}

#[test]
fn for_in_inside_a_function_body_terminates() {
    assert_eq!(
        completion(
            "(function () { var n = 0; var o = {a: 1, b: 2}; for (var k in o) { n = n + 1; } return n; })();"
        ),
        Value::Int(2)
    );
}
