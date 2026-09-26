#![forbid(unsafe_code)]

//! Execute the public TypeScript ingestion path, not a support catalog or
//! a pre-normalized JavaScript fixture. Both native profiles share this lane.
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use frankenengine_engine::ts_normalization::prepare_source_entry_for_public_entrypoints;

fn assert_output(source: &str, expected: &[&str]) {
    let prepared = prepare_source_entry_for_public_entrypoints(
        source,
        "generic-execution.ts",
        "generic-trace",
        "generic-decision",
        "generic-policy",
    )
    .expect("TypeScript normalization must succeed");
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: prepared.source_label,
                text: prepared.prepared_source,
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("normalized source must parse as JavaScript");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "generic-execution.ts"),
        &LoweringContext::new("generic-trace", "generic-decision", "generic-policy"),
    )
    .expect("normalized program must lower")
    .ir3;
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "generic-execution");
        let result = core
            .execute(&module)
            .expect("native TypeScript execution must succeed");
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
fn generic_calls_accept_nested_types_and_do_not_evaluate_type_names() {
    assert_output(
        r#"
        function first<T, U>(left: T, right: U): T { return left; }
        const result = first<{item: number}, [string, number]>({item: 7}, ['x', 2]);
        const other = first<MissingType, Map<string, {item: number}[]>>(9, null);
        console.log(result.item, other);
        "#,
        &["7 9"],
    );
}

#[test]
fn generic_methods_keep_getter_order_and_the_original_receiver() {
    assert_output(
        r#"
        let reads = 0;
        let argumentsRun = 0;
        const object = {
            base: 10,
            get method() {
                console.log('get', ++reads);
                return function(value) { return this.base + value; };
            }
        };
        function argument() { console.log('arg', ++argumentsRun); return 3; }
        console.log(object.method<number>(argument()));
        console.log((object.method)<number>(4));
        console.log(object['method']<number>(5), reads, argumentsRun);
        "#,
        &["get 1", "arg 1", "13", "get 2", "14", "get 3", "15 3 1"],
    );
}

#[test]
fn optional_generic_calls_short_circuit_arguments_and_preserve_this() {
    assert_output(
        r#"
        let calls = 0;
        function argument() { calls++; return 4; }
        const absent = null;
        const object = {base: 6, method(value) { return this.base + value; }};
        console.log(absent?.<number>(argument()), calls);
        console.log(object.method?.<number>(argument()), calls);
        console.log(absent?.method<number>(argument()), calls);
        console.log(object.method<number>?.(argument()), calls);
        "#,
        &["undefined 0", "10 1", "undefined 1", "10 2"],
    );
}

#[test]
fn generic_constructors_and_returned_generic_functions_execute() {
    assert_output(
        r#"
        class Box<T> {
            constructor(value: T) { this.value = value; }
            get(): T { return this.value; }
        }
        function pair<T>(left: T) {
            return function<U>(right: U) { return {left, right}; };
        }
        const box = new Box<{x: number}>({x: 42});
        const result = pair<number>(3)<string>('ok');
        console.log(box.get().x, box instanceof Box, result.left, result.right);
        "#,
        &["42 true 3 ok"],
    );
}

#[test]
fn generic_tags_preserve_raw_segments_and_tag_receiver() {
    assert_output(
        r#"
        let reads = 0;
        let calls = 0;
        function identity<T>(value: T): T { return value; }
        const object = {
            prefix: 'p',
            get tag() {
                reads++;
                return function(parts, value) {
                    calls++;
                    console.log(this === object, parts.raw[0], value);
                    return this.prefix + value;
                };
            }
        };
        console.log(object.tag<number>`raw\n${identity<number>(4)}`, reads, calls);
        console.log(`outer ${`inner ${identity<number>(6) / 2}`} end`);
        "#,
        &["true raw\\n 4", "p4 1 1", "outer inner 3 end"],
    );
}

#[test]
fn comparison_and_shift_expressions_do_not_turn_into_generic_calls() {
    assert_output(
        r#"
        const a = 1, b = 2, c = 0;
        console.log(a < b > c, a < b > +c, a < b > -c);
        console.log(a < b >= c, a < b + c > (0), a < b >> (1));
        console.log(a as number < b > (c), a satisfies number < b > (c));
        function identity<T>(value: T): T { return value; }
        console.log(identity < number > (7));
        "#,
        &["true true true", "true true false", "true true", "7"],
    );
}

#[test]
fn generic_calls_preserve_abrupt_completion_and_exception_identity() {
    assert_output(
        r#"
        const failure = {reason: 'callee'};
        let calls = 0;
        function argument() { calls++; return 1; }
        const object = {get method() { throw failure; }};
        try { object.method<MissingType>(argument()); }
        catch (error) { console.log(error === failure, calls); }
        function fail<T>(value: T) { throw value; }
        try { fail<{reason: string}>(failure); }
        catch (error) { console.log(error === failure); }
        "#,
        &["true 0", "true"],
    );
}

#[test]
fn generic_type_arguments_can_span_comments_and_lines() {
    assert_output(
        r#"
        function invoke<T, U>(callback: (value: T) => U, value: T): U {
            return callback(value);
        }
        const result = invoke<
            /* value */ {name: string},
            /* output */ string,
        >(value => value.name, {name: 'kept'});
        console.log(result);
        "#,
        &["kept"],
    );
}

#[test]
fn generic_erasure_does_not_discard_hostcall_capability_intents() {
    let prepared = prepare_source_entry_for_public_entrypoints(
        r#"function identity<T>(value: T): T { return value; }
        const result = hostcall<"fs.read">();
        identity<number>(3);"#,
        "generic-capability.ts",
        "generic-trace",
        "generic-decision",
        "generic-policy",
    )
    .expect("generic calls and typed hostcalls must normalize together");
    let output = prepared.normalization_output.expect("TypeScript lane must run");
    assert_eq!(output.capability_intents.len(), 1);
    assert_eq!(output.capability_intents[0].symbol, "hostcall");
    assert_eq!(output.capability_intents[0].capability, "fs.read");
    assert_eq!(output.witness.capability_intents, output.capability_intents);
    assert!(prepared.prepared_source.contains("hostcall()"));
    assert!(!prepared.prepared_source.contains("<number>"));
}

#[test]
fn specialized_aliases_keep_function_identity_and_metadata() {
    assert_output(
        r#"
        function identity<T>(value: T): T { return value; }
        const numberIdentity = identity<number>;
        function select() { return identity<string>; }
        const stringIdentity = select();
        console.log(numberIdentity === identity, stringIdentity === identity);
        console.log(numberIdentity.name === identity.name, numberIdentity.length === identity.length);
        console.log(numberIdentity(7), stringIdentity('kept'));
        "#,
        &["true true", "true true", "7 kept"],
    );
}

#[test]
fn specialized_method_references_preserve_grouped_calls_and_detached_aliases() {
    assert_output(
        r#"
        let reads = 0;
        function method(value) {
            'use strict';
            return this === object ? this.base + value : value;
        }
        const object = {base: 8, get method() { reads++; return method; }};
        const alias = object.method<number>;
        console.log(alias === method, reads, alias(2));
        console.log((object.method<number>)(2), reads);
        "#,
        &["true 1 2", "10 2"],
    );
}

#[test]
fn specialized_constructors_support_new_without_argument_parentheses() {
    assert_output(
        r#"
        let constructed = 0;
        class Counter<T> { constructor() { constructed++; } }
        const Constructor = Counter<number>;
        console.log(Constructor === Counter, constructed);
        const first = new Constructor;
        const second = new Counter<string>;
        const NumberMap = Map<string, number>;
        const map = new NumberMap;
        map.set('answer', 42);
        console.log(first instanceof Counter, second instanceof Counter, constructed, map.get('answer'));
        "#,
        &["true 0", "true true 2 42"],
    );
}

#[test]
fn instantiation_operands_are_evaluated_once_without_invoking_the_result() {
    assert_output(
        r#"
        let factories = 0;
        let calls = 0;
        function make() {
            factories++;
            return function<T>(value: T): T { calls++; return value; };
        }
        const specialized = make()<number>;
        console.log(factories, calls);
        console.log(specialized(3), factories, calls);
        const methods = [specialized<number>, specialized<string>];
        console.log(methods[0] === specialized, methods[1] === specialized);
        "#,
        &["1 0", "3 1 1", "true true"],
    );
}

#[test]
fn instantiation_expressions_compose_with_conditionals_and_templates() {
    assert_output(
        r#"
        function first<T>(value: T): T { return value; }
        function second<T>(value: T): T { return value; }
        const chosen = true ? first<number> : second<number>;
        const alternate = first<number> || second<number>;
        console.log(chosen === first, alternate === first);
        console.log(`${(first<number>) === first}:${(second<string>)('ok')}`);
        console.log(first<number> === first, second<number> !== first);
        "#,
        &["true true", "true:ok", "true true"],
    );
}

#[test]
fn instantiation_lookahead_leaves_prefix_and_greater_equal_operations_live() {
    assert_output(
        r#"
        const a = 1, b = 2;
        let c = 0;
        console.log(a < b>=c, a < b >= c);
        console.log(a < b > ++c, a < b > --c, c);
        console.log(a < b > !c, a < b > ~c, a < b > [c]);
        "#,
        &["true true", "false true 0", "false true true"],
    );
}
