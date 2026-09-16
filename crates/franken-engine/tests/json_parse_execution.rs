//! Native JSON.parse regressions through the source parser, lowering, and VM.
//!
//! These cases use guest functions, getters, mutations and exceptions rather
//! than a host-side substitute for the reviver. The contract here is ES2020;
//! the newer reviver context/source argument is not part of this implementation.

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
                label: "json-parse-execution.js".into(),
                text: format!("const log = console.log;\n{source}"),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("JSON regression source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "json-parse-execution.js"),
        &LoweringContext::new("json-trace", "json-decision", "json-policy"),
    )
    .expect("JSON regression source must lower")
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
        InterpreterCore::new(config, "json-parse-execution")
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
fn reviver_runs_postorder_with_holder_this_and_es_key_order() {
    assert_output(
        r#"
        const seen = [];
        const result = JSON.parse('{"b":{"x":1},"10":10,"2":2,"a":[3,4]}', function(...received) {
            const key = received[0];
            const value = received[1];
            seen.push(key);
            if (key === 'x') log('holder', this.x === 1, received.length);
            return typeof value === 'number' ? value * 2 : value;
        });
        log(seen.join('|'));
        log(result[2], result[10], result.b.x, result.a.join(','));
        "#,
        &["holder true 2", "2|10|x|b|0|1|a|", "4 20 2 6,8"],
    );
}

#[test]
fn root_wrapper_supports_replacement_deletion_and_noncallable_revivers() {
    assert_output(
        r#"
        let holder;
        const result = JSON.parse('3', function(key, value) {
            holder = this;
            log('root', key === '', this[key] === value);
            return { answer: value + 4 };
        });
        log(result.answer, holder[''], Object.getPrototypeOf(holder) === Object.prototype);
        log(JSON.parse('null', function() { return undefined; }) === undefined);
        log(JSON.parse('4', {}) === 4, JSON.parse('false', null) === false);
        "#,
        &["root true true", "7 3 true", "true", "true true"],
    );
}

#[test]
fn object_key_snapshot_observes_later_mutations_without_visiting_insertions() {
    assert_output(
        r#"
        const seen = [];
        const result = JSON.parse('{"a":1,"b":2,"c":3}', function(key, value) {
            seen.push(key);
            if (key === 'a') { delete this.b; this.c = 30; this.added = 99; }
            if (key === 'b') log('deleted', value === undefined);
            if (key === 'c') log('changed', value);
            return value;
        });
        log(seen.join('|'));
        log(result.a, 'b' in result, result.c, result.added);
        "#,
        &["deleted true", "changed 30", "a|b|c|", "1 false 30 99"],
    );
}

#[test]
fn array_length_is_snapshotted_and_undefined_results_leave_holes() {
    assert_output(
        r#"
        const seen = [];
        const result = JSON.parse('[1,2,3]', function(key, value) {
            if (key !== '') seen.push(key + ':' + String(value));
            if (key === '0') { this.length = 1; this[4] = 5; return undefined; }
            return value;
        });
        log(seen.join('|'));
        log(result.length, 0 in result, 1 in result, 2 in result, result[4]);
        log(Object.keys(result).join(','));
        "#,
        &["0:1|1:undefined|2:undefined", "5 false false false 5", "4"],
    );
}

#[test]
fn later_accessor_is_read_once_and_replaced_without_calling_its_setter() {
    assert_output(
        r#"
        let reads = 0;
        let writes = 0;
        const result = JSON.parse('{"a":1,"b":2}', function(key, value) {
            if (key === 'a') {
                Object.defineProperty(this, 'b', {
                    get: function() { reads++; return 7; },
                    set: function(value) { writes++; },
                    enumerable: true,
                    configurable: true
                });
            }
            return key === 'b' ? value + 1 : value;
        });
        log(result.b, reads, writes);
        "#,
        &["8 1 0"],
    );
}

#[test]
fn nested_json_parse_callbacks_restore_outer_holder_and_captures() {
    assert_output(
        r#"
        const seen = [];
        const offset = 10;
        const result = JSON.parse('{"a":2,"b":3}', function(key, value) {
            if (key === '') return value;
            const original = this[key];
            const nested = JSON.parse(String(value), function(innerKey, innerValue) {
                log('inner', innerKey === '', this[''] === innerValue);
                return innerValue + offset;
            });
            seen.push(key + ':' + original + ':' + this[key]);
            return nested;
        });
        log(seen.join('|'));
        log(result.a, result.b);
        "#,
        &["inner true true", "inner true true", "a:2:2|b:3:3", "12 13"],
    );
}

#[test]
fn a_throwing_reviver_keeps_its_effects_and_escaped_parsed_objects() {
    assert_output(
        r#"
        let escaped;
        let calls = 0;
        const token = {};
        try {
            JSON.parse('{"a":1,"b":2}', function(key, value) {
                calls++;
                escaped = this;
                this.kept = 9;
                throw token;
            });
        } catch (error) { log('same', error === token); }
        log(calls, escaped.a, escaped.b, escaped.kept);
        "#,
        &["same true", "1 1 2 9"],
    );
}

#[test]
fn coercion_runs_once_with_string_hint_and_preserves_prior_effects_on_syntax_error() {
    assert_output(
        r#"
        let count = 0;
        const source = { [Symbol.toPrimitive]: function(hint) {
            log('hint', hint);
            count++;
            return '{"x":7}';
        }};
        log(JSON.parse(source).x, count);
        let retained;
        const bad = { toString: function() { retained = { kept: 9 }; return '{'; } };
        try { JSON.parse(bad); } catch (error) { log(error instanceof SyntaxError); }
        log(retained.kept);
        "#,
        &["hint string", "7 1", "true", "9"],
    );
}

#[test]
fn syntax_and_coercion_exceptions_are_catchable_and_never_run_a_reviver() {
    assert_output(
        r#"
        let calls = 0;
        function reviver(key, value) { calls++; return value; }
        function invalid(text) {
            try { JSON.parse(text, reviver); }
            catch (error) { log(error instanceof SyntaxError, error.name); }
        }
        invalid('{"a":1} trailing');
        invalid('[1,]');
        invalid('01');
        invalid('');
        try { JSON.parse(); } catch (error) { log(error instanceof SyntaxError); }
        try { JSON.parse(Symbol('x')); } catch (error) { log(error instanceof TypeError); }
        const token = {};
        const throwingText = { toString: function() { throw token; } };
        try { JSON.parse(throwingText, reviver); }
        catch (error) { log(error === token); }
        log(calls);
        "#,
        &[
            "true SyntaxError",
            "true SyntaxError",
            "true SyntaxError",
            "true SyntaxError",
            "true",
            "true",
            "true",
            "0",
        ],
    );
}

#[test]
fn exact_utf16_keys_and_duplicate_replacements_reach_the_reviver_unchanged() {
    assert_output(
        r#"
        const seen = [];
        const result = JSON.parse('{"\\ud800":1,"\\ud801":2,"\\ufffd":3,"\\ud800":4}', function(key, value) {
            if (key === '') return value;
            seen.push(key.charCodeAt(0));
            return value + 10;
        });
        log(seen.join(','));
        log(Object.keys(result).length, result['\ud800'], result['\ud801'], result['\ufffd']);
        "#,
        &["55296,55297,65533", "3 14 12 13"],
    );
}

#[test]
fn parsed_proto_property_is_data_and_containers_use_intrinsic_prototypes() {
    assert_output(
        r#"
        const result = JSON.parse('{"__proto__":{"polluted":true},"items":[]}');
        log(Object.getPrototypeOf(result) === Object.prototype);
        log(Object.prototype.hasOwnProperty.call(result, '__proto__'), result.polluted === undefined);
        log(Array.isArray(result.items), Object.getPrototypeOf(result.items) === Array.prototype);
        log(JSON.parse(true), JSON.parse(null), JSON.parse(1n), Object.is(JSON.parse(-0), 0));
        log(Object.is(JSON.parse('-0'), -0), JSON.parse('1e400') === Infinity);
        "#,
        &[
            "true",
            "true true",
            "true true",
            "true null 1 true",
            "true true",
        ],
    );
}

#[test]
fn failed_delete_and_data_definition_on_a_frozen_holder_are_ignored() {
    assert_output(
        r#"
        const result = JSON.parse('{"a":1,"b":2}', function(key, value) {
            if (key === 'a') { Object.freeze(this); return 9; }
            if (key === 'b') return undefined;
            return value;
        });
        log(result.a, result.b, Object.isFrozen(result));
        "#,
        &["1 2 true"],
    );
}

#[test]
fn proxy_data_definition_reads_the_trap_once_and_uses_the_descriptor_protocol() {
    assert_output(
        r#"
        let reads = 0;
        let calls = 0;
        const handler = { get defineProperty() {
            reads++;
            return function(target, key, descriptor) {
                calls++;
                log('define', this === handler, key, descriptor.writable, descriptor.enumerable, descriptor.configurable);
                target[key] = descriptor.value;
                return true;
            };
        }};
        const result = JSON.parse('{"first":0,"later":null}', function(key, value) {
            if (key === 'first') this.later = new Proxy({ x: 3 }, handler);
            if (key === 'x') return value + 1;
            return value;
        });
        log(result.later.x, reads, calls);
        "#,
        &["define true x true true true", "4 1 1"],
    );
}

#[test]
fn reviver_introduced_cycles_hit_the_host_depth_guard_without_becoming_syntax_errors() {
    let module = lower(
        r#"
        JSON.parse('{"first":0,"later":{}}', function(key, value) {
            if (key === 'first') this.later.loop = this.later;
            return value;
        });
    "#,
    );
    for mut core in cores() {
        assert!(matches!(
            core.execute(&module),
            Err(InterpreterError::StackOverflow { .. })
        ));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn parsed_array_length_is_own_but_not_enumerable() {
    assert_output(
        r#"
        const array = JSON.parse('[2,3]');
        const entries = Object.entries(array);
        log(Object.keys(array).join(','), Object.values(array).join(','));
        log(entries.length, entries[0][0], entries[0][1], entries[1][0], entries[1][1]);
        log(Reflect.ownKeys(array).join(','));
        log(Object.prototype.propertyIsEnumerable.call(array, 'length'));
        const object = JSON.parse('{"length":7}');
        log(Object.keys(object).join(','), Object.prototype.propertyIsEnumerable.call(object, 'length'));
        "#,
        &["0,1 2,3", "2 0 2 1 3", "0,1,length", "false", "length true"],
    );
}

#[test]
fn reviver_proxy_enumeration_uses_real_descriptors_and_rejects_null_descriptors() {
    assert_output(
        r#"
        const seen = [];
        JSON.parse('{"first":0,"later":null}', function(key, value) {
            if (key === 'first') this.later = new Proxy({ x: 3 }, {
                ownKeys: function() { return ['missing', 'x']; }
            });
            seen.push(key);
            return value;
        });
        log(seen.join('|'));
        let reads = 0;
        try {
            JSON.parse('{"first":0,"later":null}', function(key, value) {
                if (key === 'first') this.later = new Proxy({ x: 3 }, {
                    getOwnPropertyDescriptor: function() { reads++; return null; }
                });
                return value;
            });
        } catch (error) { log(error instanceof TypeError, reads); }
        "#,
        &["first|x|later|", "true 1"],
    );
}

#[test]
fn deep_finite_reviver_walk_uses_the_heap_work_stack() {
    assert_output(
        r#"
        let source = '1';
        for (let i = 0; i < 128; i++) source = '{"x":' + source + '}';
        let calls = 0;
        const value = JSON.parse(source, function(key, value) { calls++; return value; });
        let leaf = value;
        for (let i = 0; i < 128; i++) leaf = leaf.x;
        log(leaf, calls);
        "#,
        &["1 129"],
    );
}

#[test]
fn intrinsic_prototype_reads_preserve_lexical_shadowing() {
    assert_output(
        r#"
        const Object = { prototype: { local: 3 } };
        const Array = { prototype: { local: 4 } };
        log(Object.prototype.local, Array['prototype'].local);
        "#,
        &["3 4"],
    );
}

#[test]
fn signed_zero_and_mixed_number_representations_survive_json_operations() {
    assert_output(
        r#"
        log(Object.is(JSON.parse('-0'), -0), Object.is(JSON.parse('0'), -0));
        log(Object.is(JSON.parse('1.0'), 1), Object.is(1, JSON.parse('1.0')));
        log(Object.is(-null, -0), 1 / -0 === -Infinity);
        "#,
        &["true false", "true true", "true true"],
    );
}

#[test]
fn multiline_exception_clauses_preserve_catch_finally_and_else_order() {
    assert_output(
        r#"
        const prefix = 1; try { JSON.parse('['); }
        catch (error) { log(error instanceof SyntaxError); }
        finally { log('finalized'); }
        if (prefix === 0) { log('wrong'); }
        else { log('else'); }
        log('after');
        "#,
        &["true", "finalized", "else", "after"],
    );
}

#[test]
fn negative_zero_source_spellings_match_parsed_negative_zero() {
    assert_output(
        r#"
        const negative = JSON.parse('-0');
        log(Object.is(-0, negative), Object.is(-0x0, negative), Object.is(-0o0, negative), Object.is(-0b0, negative));
        log(Object.is(-0.0, negative), Object.is(-0e0, negative), Object.is(-false, negative), Object.is(-null, negative));
        log(Object.is(0, negative), Object.is(+0, negative), 1 / negative === -Infinity, JSON.stringify(negative));
        "#,
        &[
            "true true true true",
            "true true true true",
            "false false true 0",
        ],
    );
}
