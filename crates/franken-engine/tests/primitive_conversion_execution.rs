//! Observable primitive conversions through source parsing, lowering and both VM profiles.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "primitive-conversion-execution.js".into(),
                text: format!("const log = console.log;\n{source}"),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("conversion regression source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "primitive-conversion-execution.js"),
        &LoweringContext::new("json-trace", "json-decision", "json-policy"),
    )
    .expect("conversion regression source must lower")
    .ir3
}

fn cores() -> impl Iterator<Item = InterpreterCore> {
    [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ]
    .into_iter()
    .map(|mut config| {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "primitive-conversion-execution")
    })
}

fn assert_output(source: &str, expected: &[&str]) {
    let module = lower(source);
    for mut core in cores() {
        let result = core
            .execute(&module)
            .expect("native conversion execution must succeed");
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn number_uses_string_numeric_grammar_and_ieee_rounding() {
    assert_output(
        r#"
 log(JSON.stringify([Number(), Number(null), Number(true), Number(false), Number(''), Number(' \t\n'), Number('0x20'), Number('0b101'), Number('0o17')]));
 log(JSON.stringify([Number('9007199254740993'), Number('9223372036854775808'), Number('1e400')]));
 log(Object.is(Number('-0'), -0), Object.is(Number('-0.0e3'), -0));
 log(Number.isNaN(Number(undefined)), Number('Infinity') === Infinity);
"#,
        &[
            "[0,0,1,0,0,0,32,5,15]",
            "[9007199254740992,9223372036854776000,null]",
            "true true",
            "true true",
        ],
    );
}

#[test]
fn number_trims_only_ecmascript_whitespace_and_rejects_partial_tokens() {
    assert_output(
        r#"
 log(Number('\ufeff \ufeff\n42\ufeff \ufeff'));
 log(Number.isNaN(Number('\u008542')), Number.isNaN(Number('\u180e42')));
 log(Number.isNaN(Number('1_000')), Number.isNaN(Number('1e+')), Number.isNaN(Number('+0x10')), Number.isNaN(Number('0b102')));
 log(Number.isNaN(Number('inf')), Number.isNaN(Number('infinity')), Number.isNaN(Number('12junk')));
"#,
        &["42", "true true", "true true true true", "true true true"],
    );
}

#[test]
fn number_runs_observable_hooks_in_number_hint_order() {
    assert_output(
        r#"
 const seen = [];
 const value = { valueOf: function() { seen.push('value'); return this; }, toString: function() { seen.push('string'); return '41'; } };
 log(Number(value), seen.join('|'));
 value[Symbol.toPrimitive] = function(hint) { log(hint, this === value); return '0x2a'; };
 log(Number(value));
 value[Symbol.toPrimitive] = function() { throw 'conversion-stop'; };
 try { Number(value); } catch (error) { log(error); }
 log(Number('7'));
"#,
        &[
            "41 value|string",
            "number true",
            "42",
            "conversion-stop",
            "7",
        ],
    );
}

#[test]
fn string_runs_hooks_and_only_direct_symbols_get_descriptive_conversion() {
    assert_output(
        r#"
 const value = { toString: function() { log('string'); return this; }, valueOf: function() { log('value'); return 12; } };
 log(String(value));
 log(String(Symbol('label')));
 value[Symbol.toPrimitive] = function(hint) { log(hint); return '\ud800'; };
 log(String(value).charCodeAt(0));
 value[Symbol.toPrimitive] = function() { return Symbol('blocked'); };
 try { String(value); } catch (error) { log(error instanceof TypeError); }
 log(String(), String(-0), String(1e21));
"#,
        &[
            "string",
            "value",
            "12",
            "Symbol(label)",
            "string",
            "55296",
            "true",
            " 0 1e+21",
        ],
    );
}

#[test]
fn global_number_predicates_coerce_but_number_statics_do_not() {
    assert_output(
        r#"
 let calls = 0;
 const value = { valueOf: function() { calls++; return '  '; } };
 log(isNaN(value), isFinite(value), calls);
 log(Number.isNaN(value), Number.isFinite(value), calls);
 log(isNaN(''), isFinite('0x10'), isNaN(), isFinite());
 try { isNaN(1n); } catch (error) { log(error instanceof TypeError); }
 try { isFinite(Symbol()); } catch (error) { log(error instanceof TypeError); }
 log(Number(9007199254740993n), Number({ valueOf: function() { return 42n; } }));
"#,
        &[
            "false true 2",
            "false false 2",
            "false true true false",
            "true",
            "true",
            "9007199254740992 42",
        ],
    );
}

#[test]
fn parse_int_uses_prefixes_without_saturation_or_losing_negative_zero() {
    assert_output(
        r#"
 log(JSON.stringify([parseInt('0xff'), parseInt('-0X10'), parseInt('010'), parseInt('0b11'), parseInt('42tail'), parseInt('9223372036854775808')]));
 log(JSON.stringify([parseInt(1e21), parseInt(1e-7), parseInt('9007199254740993'), parseInt('9007199254740995')]));
 log(Object.is(parseInt('-0'), -0), Object.is(parseInt('-0x0'), -0), Object.is(parseInt(-0), 0));
 log(parseInt('9'.repeat(400)) === Infinity, parseInt('-' + '9'.repeat(400)) === -Infinity);
"#,
        &[
            "[255,-16,10,0,42,9223372036854776000]",
            "[1,1,9007199254740992,9007199254740996]",
            "true true true",
            "true true",
        ],
    );
}

#[test]
fn parse_int_coerces_input_before_radix_and_never_reorders_exceptions() {
    assert_output(
        r#"
 const seen = [];
 const radix = { value: 2, valueOf: function() { seen.push('radix'); return this.value; } };
 const text = { toString: function() { seen.push('text'); radix.value = 16; return 'ff'; } };
 log(parseInt(text, radix), seen.join('|'));
 seen.length = 0;
 try { parseInt(Symbol('bad'), radix); } catch (error) { log(error instanceof TypeError); }
 log(seen.length);
 radix.valueOf = function() { throw 'bad-radix'; };
 try { parseInt(text, radix); } catch (error) { log(error); }
 log(seen.join('|'));
"#,
        &["255 text|radix", "true", "0", "bad-radix", "text"],
    );
}

#[test]
fn parse_int_radix_uses_to_int32_and_aliases_share_semantics() {
    assert_output(
        r#"
 log(JSON.stringify([parseInt('11', '2'), parseInt('10', 4294967298), parseInt('10', -4294967294), parseInt('ff', Infinity), parseInt('0xff', NaN)]));
 log(Number.isNaN(parseInt('9', 8)), Number.isNaN(parseInt('10', 1)), Number.isNaN(parseInt('0x', 16)));
 log(Number.parseInt('9007199254740995'), Number.parseFloat('1e+'));
 try { parseInt('10', 2n); } catch (error) { log(error instanceof TypeError); }
"#,
        &[
            "[3,2,2,null,255]",
            "true true true",
            "9007199254740996 1",
            "true",
        ],
    );
}

#[test]
fn parse_float_consumes_the_longest_complete_decimal_prefix() {
    assert_output(
        r#"
 log(JSON.stringify([parseFloat('1e'), parseFloat('1e+'), parseFloat('1.25e-'), parseFloat('.5x'), parseFloat('0x10'), parseFloat('+Infinitymore')]));
 log(Number.isNaN(parseFloat(true)), Number.isNaN(parseFloat(false)), Number.isNaN(parseFloat(null)), Number.isNaN(parseFloat('')));
 log(Object.is(parseFloat('-0'), -0), Object.is(parseFloat('-0e+'), -0), Object.is(parseFloat(-0), 0));
 log(parseFloat({ toString: function() { return '  12.5e2tail'; } }));
 try { parseFloat(Symbol()); } catch (error) { log(error instanceof TypeError); }
"#,
        &[
            "[1,1,1.25,0.5,0,null]",
            "true true true true",
            "true true true",
            "1250",
            "true",
        ],
    );
}

#[test]
fn radix_integers_round_once_including_halfway_and_overflow_boundaries() {
    assert_output(
        r#"
 log(Number('0x20000000000001') === 9007199254740992);
 log(Number('0x20000000000003') === 9007199254740996);
 log(Number('0x1000000000000081') === 1152921504606847200);
 log(parseInt('1000000000000081', 16) === Number('0x1000000000000081'));
 log(Number('0x' + 'f'.repeat(256)) === Infinity);
 log(Number.isNaN(Number('0x' + 'f'.repeat(256) + 'z')));
 log(Number('0b' + '1' + '0'.repeat(1023)) === Number('8.98846567431158e307'));
"#,
        &["true", "true", "true", "true", "true", "true", "true"],
    );
}

#[test]
fn boolean_never_calls_conversion_hooks_and_handles_bigint_zero() {
    assert_output(
        r#"
 const value = { valueOf: function() { throw 'must-not-call'; }, toString: function() { throw 'must-not-call'; } };
 log(Boolean(value), Boolean([]), Boolean('0'), Boolean(Symbol()));
 log(Boolean(), Boolean(null), Boolean(undefined), Boolean(NaN), Boolean(-0), Boolean(0n), Boolean(1n));
"#,
        &[
            "true true true true",
            "false false false false false false true",
        ],
    );
}

#[test]
fn nested_conversions_and_lexical_shadowing_preserve_outer_context() {
    assert_output(
        r#"
 const seen = [];
 const value = { valueOf: function() { seen.push(String({ toString: function() { return 'inside'; } })); return '17'; } };
 log(Number(value), seen.join('|'));
 { const Number = function() { return 81; }; const Boolean = function() { return 'local'; }; log(Number(value), Boolean(0)); }
 log(Number('19'), Boolean(0));
"#,
        &["17 inside", "81 local", "19 false"],
    );
}

#[test]
fn arrays_use_live_string_conversion_and_symbols_still_throw_for_number() {
    assert_output(
        r#"
        log(Number([]), Number([7]), Number.isNaN(Number([1, 2])));
        log(String([1, null, 3]), String(1e-7), String(1e21));
        const value = { [Symbol.toPrimitive]: function() { return {}; } };
        try { Number(value); } catch (error) { log(error instanceof TypeError); }
        try { Number(Symbol()); } catch (error) { log(error instanceof TypeError); }
        log(String('after'));
        "#,
        &["0 7 true", "1,,3 1e-7 1e+21", "true", "true", "after"],
    );
}

#[test]
fn conversion_work_is_budgeted_and_scratch_is_released_on_refusal() {
    let source = format!("Number('{}');", "1".repeat(16_384));
    let module = lower(&source);
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.instruction_budget = 100;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "conversion-work-budget");
        assert!(matches!(
            core.execute(&module),
            Err(InterpreterError::BudgetExhausted { .. })
        ));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn primitive_results_preserve_secret_argument_provenance() {
    use frankenengine_engine::baseline_interpreter::{Float64, Value};
    use frankenengine_engine::ifc_artifacts::Label;
    use frankenengine_engine::ir_contract::{CapabilityTag, Ir3Instruction, RegRange};

    for (name, input, expected) in [
        ("Number", Value::str("0x2a"), Value::Int(42)),
        ("String", Value::Int(42), Value::str("42")),
        ("Boolean", Value::BigInt("0".into()), Value::Bool(false)),
        ("isNaN", Value::str("junk"), Value::Bool(true)),
        ("isFinite", Value::str(" 42 "), Value::Bool(true)),
        ("parseInt", Value::str("13tail"), Value::Int(13)),
        (
            "parseFloat",
            Value::str("2.5tail"),
            Value::Float(Float64::new(2.5)),
        ),
    ] {
        for mut core in cores() {
            core.seed_register(0, input.clone()).unwrap();
            core.set_register_label(0, Label::Secret).unwrap();
            let mut module = lower("0;");
            module.instructions = vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag(format!("builtin:{name}")),
                    args: RegRange { start: 0, count: 1 },
                    dst: 1,
                },
                Ir3Instruction::Return { value: 1 },
            ];
            let result = core.execute(&module).unwrap();
            assert_eq!(result.value, expected, "{name}");
            assert_eq!(result.completion_label, Label::Secret, "{name}");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn primitive_coercion_of_a_deep_graph_does_not_recurse_before_the_guest_hook() {
    assert_output(
        r#"
        const root = { valueOf: function() { return '0x2a'; }, toString: function() { return '12.5tail'; } };
        let cursor = root;
        for (let i = 0; i < 400; i++) { cursor.child = {}; cursor = cursor.child; }
        log(Number(root), parseFloat(root), parseInt(root), String(root));
        "#,
        &["42 12.5 12 12.5tail"],
    );
}
