//! Native JSON serialization through source parsing, lowering and both VM profiles.

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
                label: "json-stringify-execution.js".into(),
                text: format!("const log = console.log;\n{source}"),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("JSON stringify regression source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "json-stringify-execution.js"),
        &LoweringContext::new("json-trace", "json-decision", "json-policy"),
    )
    .expect("JSON stringify regression source must lower")
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
        InterpreterCore::new(config, "json-stringify-execution")
    })
}

fn assert_output(source: &str, expected: &[&str]) {
    let module = lower(source);
    for mut core in cores() {
        let result = core
            .execute(&module)
            .expect("native JSON execution must succeed");
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
fn root_omission_and_root_replacer_use_actual_undefined_and_a_holder() {
    assert_output(
        r#"
        log(JSON.stringify() === undefined, JSON.stringify(undefined) === undefined);
        log(JSON.stringify(Symbol('x')) === undefined, JSON.stringify(function() {}) === undefined);
        log(JSON.stringify(undefined, function(...args) {
            log(args[0] === '', args.length, this[''] === undefined, Object.getPrototypeOf(this) === Object.prototype);
            return 7;
        }));
        "#,
        &["true true", "true true", "true 2 true true", "7"],
    );
}

#[test]
fn to_json_precedes_replacer_and_uses_original_receiver_and_key() {
    assert_output(
        r#"
        const seen = [];
        const child = { toJSON: function(key) { seen.push('j:' + key); log(this === child); return { x: 2 }; } };
        const result = JSON.stringify({ a: child }, function(key, value) {
            seen.push('r:' + key);
            return key === 'x' ? value * 3 : value;
        });
        log(result);
        log(seen.join('|'));
        "#,
        &["true", "{\"a\":{\"x\":6}}", "r:|j:a|r:a|r:x"],
    );
}

#[test]
fn replacer_observes_later_mutations_but_does_not_add_keys_to_the_snapshot() {
    assert_output(
        r#"
        const source = { a: 1, b: 2, c: 3 };
        const seen = [];
        log(JSON.stringify(source, function(key, value) {
            seen.push(key);
            if (key === 'a') { delete this.b; this.c = 30; this.added = 99; }
            if (key === 'b') log(value === undefined);
            return value;
        }));
        log(seen.join('|'), source.added);
        "#,
        &["true", "{\"a\":1,\"c\":30}", "|a|b|c 99"],
    );
}

#[test]
fn getters_run_once_in_key_order_and_exceptions_preserve_prior_effects() {
    assert_output(
        r#"
        const seen = [];
        const source = { a: 1, b: 2, c: 3 };
        Object.defineProperty(source, 'b', { enumerable: true, configurable: true, get: function() { seen.push('b'); source.c = 30; return 20; } });
        log(JSON.stringify(source), seen.join('|'));
        Object.defineProperty(source, 'b', { enumerable: true, get: function() { seen.push('throw'); throw 'stop'; } });
        try { JSON.stringify(source); } catch (error) { log(error); }
        log(seen.join('|'), source.c, JSON.stringify({ after: true }));
        "#,
        &[
            "{\"a\":1,\"b\":20,\"c\":30} b",
            "stop",
            "b|throw 30 {\"after\":true}",
        ],
    );
}

#[test]
fn cycles_throw_but_shared_subtrees_and_callback_cycle_breaking_are_valid() {
    assert_output(
        r#"
        const root = { a: 1 }; root.self = root;
        try { JSON.stringify(root); } catch (error) { log(error instanceof TypeError); }
        log(JSON.stringify(root, function(key, value) { return key === 'self' ? undefined : value; }));
        const shared = { x: 2 };
        log(JSON.stringify({ a: shared, b: shared }));
        root.toJSON = function() { return 8; };
        log(JSON.stringify(root));
        "#,
        &[
            "true",
            "{\"a\":1}",
            "{\"a\":{\"x\":2},\"b\":{\"x\":2}}",
            "8",
        ],
    );
}

#[test]
fn bigint_requires_an_explicit_conversion_and_replacer_can_supply_it() {
    assert_output(
        r#"
        try { JSON.stringify({ amount: 12n }); } catch (error) { log(error instanceof TypeError); }
        log(JSON.stringify({ amount: 12n }, function(key, value) { return typeof value === 'bigint' ? String(value) : value; }));
        log(JSON.stringify(12n, function() { return undefined; }) === undefined);
        "#,
        &["true", "{\"amount\":\"12\"}", "true"],
    );
}

#[test]
fn property_list_is_ordered_deduplicated_and_applies_to_nested_and_inherited_properties() {
    assert_output(
        r#"
        const child = Object.create({ inherited: 9 }); child.a = 1; child.b = 2;
        log(JSON.stringify({ x: child }, ['b', 'x', 'a', 'b', 'inherited', {}, null, true]));
        log(JSON.stringify({ 2: 'two', 1: 'one', a: 3 }, [2, 1, '2', 'a']));
        log(JSON.stringify({ a: 1 }, []), JSON.stringify([1,2], []));
        "#,
        &[
            "{\"x\":{\"b\":2,\"a\":1,\"inherited\":9}}",
            "{\"2\":\"two\",\"1\":\"one\",\"a\":3}",
            "{} [1,2]",
        ],
    );
}

#[test]
fn replacer_list_reads_length_once_and_reads_each_index_live() {
    assert_output(
        r#"
        const list = ['a', 'b'];
        Object.defineProperty(list, '0', { get: function() { list[1] = 'c'; list.push('d'); return 'a'; } });
        log(JSON.stringify({ a: 1, b: 2, c: 3, d: 4 }, list));
        "#,
        &["{\"a\":1,\"c\":3}"],
    );
}

#[test]
fn arrays_snapshot_length_get_later_values_live_and_preserve_holes_as_null() {
    assert_output(
        r#"
        const source = [1,2,3];
        log(JSON.stringify(source, function(key, value) {
            if (key === '0') { delete this[1]; this[2] = 30; this.push(4); }
            return value;
        }));
        log(source.length, JSON.stringify([undefined, function() {}, Symbol('x'), NaN]));
        const inherited = Object.create(Array.prototype); inherited[1] = 7;
        const sparse = [1,2]; delete sparse[1]; Object.setPrototypeOf(sparse, inherited);
        log(JSON.stringify(sparse));
        "#,
        &["[1,null,30]", "4 [null,null,null,null]", "[1,7]"],
    );
}

#[test]
fn array_proxies_use_array_length_and_index_gets_not_own_keys() {
    assert_output(
        r#"
        const seen = [];
        const proxy = new Proxy([1,2], {
            get: function(target, key) { seen.push(String(key)); return key === 'length' ? 1 : Reflect.get(target, key); },
            ownKeys: function() { throw 'must not enumerate an array'; }
        });
        log(JSON.stringify(proxy), seen.join('|'));
        "#,
        &["[1] toJSON|length|0"],
    );
}

#[test]
fn object_proxies_preserve_own_keys_descriptor_and_get_order() {
    assert_output(
        r#"
        const seen = [];
        const proxy = new Proxy({ a: 1, b: 2 }, {
            ownKeys: function() { seen.push('keys'); return ['b', 'a']; },
            getOwnPropertyDescriptor: function(target, key) { seen.push('desc:' + key); return { enumerable: true, configurable: true }; },
            get: function(target, key) { seen.push('get:' + key); return Reflect.get(target, key); }
        });
        log(JSON.stringify(proxy));
        log(seen.join('|'));
        "#,
        &[
            "{\"b\":2,\"a\":1}",
            "get:toJSON|keys|desc:b|desc:a|get:b|get:a",
        ],
    );
}

#[test]
fn indentation_clamps_numbers_and_truncates_strings_by_code_unit() {
    assert_output(
        r#"
        log(JSON.stringify({ a: [1,2] }, null, 2) === '{\n  "a": [\n    1,\n    2\n  ]\n}');
        log(JSON.stringify({ a: 1 }, null, 99) === '{\n          "a": 1\n}');
        const space = '123456789' + String.fromCharCode(0xd800) + 'z';
        const result = JSON.stringify({ a: 1 }, null, space);
        log(result === '{\n' + space.slice(0,10) + '"a": 1\n}', result.charCodeAt(11) === 0xd800);
        log(JSON.stringify({ a: 1 }, null, { toString: function() { throw 'plain space ignored'; } }));
        "#,
        &["true", "true", "true true", "{\"a\":1}"],
    );
}

#[test]
fn exact_strings_and_keys_round_trip_without_losing_lone_surrogates() {
    assert_output(
        r#"
        const a = String.fromCharCode(0xd800), b = String.fromCharCode(0xd801);
        const source = {}; source[a] = a; source[b] = '\n\t"\\'; source.__user = 3;
        const serialized = JSON.stringify(source);
        const result = JSON.parse(serialized);
        log(Object.keys(result).length, result[a] === a, result[b] === source[b], result.__user);
        log(JSON.stringify('😀') === '"😀"');
        log(JSON.stringify(source, [b, a, b]) === '{"\\ud801":"\\n\\t\\"\\\\","\\ud800":"\\ud800"}');
        "#,
        &["3 true true 3", "true", "true"],
    );
}

#[test]
fn number_output_uses_js_exponents_negative_zero_and_nonfinite_rules() {
    assert_output(
        r#"
        log(JSON.stringify([NaN, Infinity, -Infinity, -0, 1e21, 1e-7, 1e-6]));
        log(JSON.stringify(JSON.parse('9007199254740993')));
        "#,
        &["[null,null,null,0,1e+21,1e-7,0.000001]", "9007199254740992"],
    );
}

#[test]
fn nested_serialization_does_not_replace_outer_replacer_holder_or_options() {
    assert_output(
        r#"
        const root = { a: 1, b: 2 };
        log(JSON.stringify(root, function(key, value) {
            if (key === 'a') { log(JSON.stringify({ x: 3 }, ['x'], 1)); log(this === root); }
            return value;
        }));
        log(JSON.stringify({ toJSON: function() { return JSON.parse(JSON.stringify([4,5])); } }));
        "#,
        &["{\n \"x\": 3\n}", "true", "{\"a\":1,\"b\":2}", "[4,5]"],
    );
}

#[test]
fn hook_results_are_not_reprocessed_as_a_second_to_json_call() {
    assert_output(
        r#"
        log(JSON.stringify({ toJSON: 4, a: 1 }));
        log(JSON.stringify({ toJSON: function() { return { x: 2, toJSON: function() { throw 'no second call'; } }; } }));
        log(JSON.stringify(1, function(key, value) { return key === '' ? { x: 2, toJSON: function() { throw 'no call on replacer result'; } } : value; }));
        "#,
        &["{\"toJSON\":4,\"a\":1}", "{\"x\":2}", "{\"x\":2}"],
    );
}

#[test]
fn deep_finite_serialization_uses_a_heap_work_stack() {
    assert_output(
        r#"
        let root = 1;
        for (let i = 0; i < 150; i++) root = [root];
        const text = JSON.stringify(root);
        log(text.length, text[0] === '[', text[text.length - 1] === ']');
        "#,
        &["301 true true"],
    );
}

#[test]
fn wide_output_reaches_the_runtime_string_limit_and_releases_scratch() {
    let module =
        lower("const a = []; for (let i = 0; i < 60; i++) a.push('abc'); JSON.stringify(a);");
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.max_string_size = 128;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "json-stringify-limit");
        assert!(matches!(
            core.execute(&module),
            Err(InterpreterError::StringLimitExceeded { .. })
        ));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn bigint_prototype_to_json_is_live_ordered_and_lexically_shadowable() {
    assert_output(
        r#"
        const seen = [];
        BigInt.prototype.toJSON = function(key) { seen.push(key); return String(this); };
        log(JSON.stringify({ amount: 12n }, function(key, value) { if (key === 'amount') log(typeof value); return value; }));
        log(seen.join('|'), Object.getPrototypeOf(BigInt.prototype) === Object.prototype);
        delete BigInt.prototype.toJSON;
        try { JSON.stringify(12n); } catch (error) { log(error instanceof TypeError); }
        { const BigInt = { prototype: { local: 7 } }; log(BigInt.prototype.local); }
        "#,
        &["string", "{\"amount\":\"12\"}", "amount true", "true", "7"],
    );
}

#[test]
fn exponent_signs_stay_inside_numeric_tokens_but_not_identifiers_or_hex_literals() {
    assert_output(
        r#"
        log(JSON.stringify([1e-7 + 1e-7, 2 * 1E+3, .5e-2, 1.25e-2 / 2.5e+1]));
        const name1e = 9, value = 8;
        log(name1e - 2, value-1, 0x1e-2, JSON.stringify([-1e-7, +1e+3]));
        "#,
        &["[2e-7,2000,0.005,0.0005]", "7 7 28 [-1e-7,1000]"],
    );
}

#[test]
fn overdeep_input_hits_the_host_guard_without_leaking_traversal_scratch() {
    let module =
        lower("let root = 1; for (let i = 0; i < 400; i++) root = [root]; JSON.stringify(root);");
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.instruction_budget = 500_000;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "json-stringify-depth");
        assert!(matches!(
            core.execute(&module),
            Err(InterpreterError::StackOverflow { max: 200, .. })
        ));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}
