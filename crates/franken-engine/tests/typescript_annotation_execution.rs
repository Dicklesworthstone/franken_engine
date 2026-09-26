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
        "annotation-execution.ts",
        "annotation-trace",
        "annotation-decision",
        "annotation-policy",
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
        &Ir0Module::from_syntax_tree(tree, "annotation-execution.ts"),
        &LoweringContext::new("annotation-trace", "annotation-decision", "annotation-policy"),
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
        let mut core = InterpreterCore::new(config, "annotation-execution");
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
fn typed_objects_and_conditional_expressions_keep_their_runtime_colons() {
    assert_output(
        r#"
        const settings: { port: number; label: string } = {port: 8080, label: 'server'};
        function describe(enabled: boolean): string {
            const selected = enabled ? settings : {port: 0, label: 'offline'};
            return selected.label + ':' + selected.port;
        }
        console.log(describe(true), describe(false));
        "#,
        &["server:8080 offline:0"],
    );
}

#[test]
fn destructuring_aliases_and_typed_binding_patterns_are_distinct() {
    assert_output(
        r#"
        const {left: a, right: b}: {left: number; right: number} = {left: 3, right: 7};
        function total({left: x, right: y}: {left: number; right: number}): number {
            return x + y;
        }
        const [head, tail]: [number, number] = [a, b];
        console.log(a, b, total({left: head, right: tail}));
        "#,
        &["3 7 10"],
    );
}

#[test]
fn arrow_signatures_and_object_methods_erase_types_not_default_objects() {
    assert_output(
        r#"
        const add = (x: number, options: {increment: number} = {increment: 4}): number => x + options.increment;
        const helper = {
            scale(value: number, factor: number = 2): number { return value * factor; }
        };
        console.log(add(3), add(3, {increment: 8}), helper.scale(6));
        "#,
        &["7 11 12"],
    );
}

#[test]
fn labels_switch_cases_and_nested_ternaries_are_runtime_syntax() {
    assert_output(
        r#"
        let result: number = 0;
        outer: for (let index: number = 0; index < 4; index++) {
            switch (index) {
                case 0: result += 1; break;
                case 1: result += true ? 10 : 100; break;
                default: break outer;
            }
        }
        const value: number = false ? 1 : true ? 2 : 3;
        console.log(result, value);
        "#,
        &["11 2"],
    );
}

#[test]
fn nested_generic_union_tuple_and_function_types_do_not_leak_into_javascript() {
    assert_output(
        r#"
        const values: Array<{value: number} | null> = [{value: 5}, null];
        const apply: (value: number, pair: [number, number]) => number =
            (value: number, pair: [number, number]): number => value + pair[0] + pair[1];
        const fallback: string | null = null;
        console.log(apply(values[0].value, [2, 3]), fallback === null);
        "#,
        &["10 true"],
    );
}

#[test]
fn optional_parameters_and_receiver_parameters_are_erased_without_changing_arity() {
    assert_output(
        r#"
        function read(this: {base: number}, offset?: number): number {
            return this.base + (offset === undefined ? 0 : offset);
        }
        const object = {base: 9, read};
        console.log(object.read(), object.read(3), read.length);
        "#,
        &["9 12 1"],
    );
}

#[test]
fn class_fields_and_methods_keep_object_initializers_and_branch_values() {
    assert_output(
        r#"
        class Counter {
            state: {value: number} = {value: 1};
            extra: number = 2;
            add(amount: number): number {
                this.state.value += amount;
                return this.state.value > 5 ? this.state.value : this.extra;
            }
        }
        const counter: Counter = new Counter();
        console.log(counter.add(2), counter.add(4));
        "#,
        &["2 7"],
    );
}

#[test]
fn literals_comments_and_regex_bodies_are_not_type_syntax() {
    assert_output(
        r#"
        const label: string = 'key: value';
        const matches: boolean = /a:b/.test('a:b');
        // let imaginary: Wrong; const bad = {not: code};
        const text: string = `runtime ${true ? 'yes' : 'no'}: done`;
        console.log(label, matches, text);
        "#,
        &["key: value true runtime yes: done"],
    );
}

#[test]
fn object_shaped_return_types_do_not_eat_the_function_body() {
    assert_output(
        r#"
        function make(value: number): {value: number; nested: {enabled: boolean}} {
            return {value: value, nested: {enabled: value > 0 ? true : false}};
        }
        const first = make(7);
        const second = make(0);
        console.log(first.value, first.nested.enabled, second.nested.enabled);
        "#,
        &["7 true false"],
    );
}

#[test]
fn higher_order_return_annotations_preserve_returned_closures() {
    assert_output(
        r#"
        const make = (): ((value: number) => number) => value => value + 1;
        const makeConstant = (): () => number => () => 7;
        console.log(make()(3), makeConstant()());
        "#,
        &["4 7"],
    );
}

#[test]
fn conditional_arrow_branches_are_not_mistaken_for_return_annotations() {
    assert_output(
        r#"
        function identity(value: number): number { return value; }
        const first = true ? identity(3) : value => value;
        const second = false ? (3) : value => value + 1;
        const third = true ? (value: number): number => value + 2 : (value: number) => value;
        const fourth = false ? function(value: number): number { return value; }
            : function(value: number): number { return value + 3; };
        console.log(first, second(4), third(5), fourth(5));
        "#,
        &["3 5 7 8"],
    );
}

#[test]
fn generic_declarations_and_class_modifiers_use_the_native_runtime() {
    assert_output(
        r#"
        function identity<T extends {value: number}>(input: T): T { return input; }
        const take = <T>(value: T): T => value;
        class Box<T> {
            public value: T;
            constructor(value: T) { this.value = value; }
            public choose<U>(other: U): U { return other; }
        }
        const box = new Box(take(3));
        console.log(identity({value: 5}).value, box.value, box.choose('kept'));
        "#,
        &["5 3 kept"],
    );
}

#[test]
fn expression_assertions_preserve_values_and_do_not_cast_or_check() {
    assert_output(
        r#"
        const original: unknown = '41';
        const asserted = original as number;
        const settings = {port: 80} satisfies {port: number};
        const same = settings as unknown as {port: number};
        console.log(typeof asserted, asserted, same === settings, same.port);
        "#,
        &["string 41 true 80"],
    );
}

#[test]
fn asserted_method_calls_preserve_the_original_receiver() {
    assert_output(
        r#"
        const receiver = {
            base: 8,
            method(offset: number): number { return this.base + offset; }
        };
        console.log((receiver.method as (offset: number) => number)(4));
        console.log(receiver!.method(5));
        "#,
        &["12", "13"],
    );
}

#[test]
fn non_null_assertions_are_not_runtime_guards_or_boolean_negations() {
    assert_output(
        r#"
        const value: {count: number} | null = null;
        console.log(value!, !value, !!value);
        try { console.log(value!.count); }
        catch (error) { console.log(error.name); }
        const object = {count: 7};
        console.log(object!!.count, object !== null);
        "#,
        &["null true false", "TypeError", "7 true"],
    );
}

#[test]
fn asserted_assignment_targets_are_evaluated_once_in_source_order() {
    assert_output(
        r#"
        let reads: number = 0;
        const state = {value: 1};
        function target(): {value: number} { reads++; return state; }
        (target() as {value: number}).value += 2;
        target()!.value++;
        console.log(reads, state.value);
        let keys: number = 0;
        function key(): string { keys++; return 'value'; }
        state[key()]! += 3;
        console.log(keys, state.value);
        "#,
        &["2 4", "1 7"],
    );
}

#[test]
fn assertions_preserve_comparisons_conditional_branches_and_statement_boundaries() {
    assert_output(
        r#"
        const first: unknown = 3;
        const second = false ? 1 as number : first as number;
        console.log(second, first as number < 5, first as number === 3);
        const value = first as number
        const next = 7;
        console.log(value, next);
        "#,
        &["3 true true", "3 7"],
    );
}

#[test]
fn runtime_properties_and_functions_named_as_and_satisfies_remain_callable() {
    assert_output(
        r#"
        function as(value: number): number { return value + 1; }
        function satisfies(value: number): number { return value * 2; }
        const object = {as: as, satisfies: satisfies};
        console.log(object.as(4), object.satisfies(4));
        console.log((object.as as (value: number) => number)(5));
        "#,
        &["5 8", "6"],
    );
}

#[test]
fn assertions_accept_nested_types_while_preserving_live_object_identity() {
    assert_output(
        r#"
        const entries = {items: [{value: 3}, {value: 7}]};
        const typed = entries as Record<string, Array<{value: number} | null>>;
        const checked = typed satisfies {items: Array<{value: number}>};
        typed.items[0]!.value = 9;
        console.log(checked === entries, entries.items[0].value, typed.items[1]!.value);
        "#,
        &["true 9 7"],
    );
}

#[test]
fn template_interpolations_execute_assertions_without_changing_literal_text() {
    assert_output(
        r#"
        const value: unknown = {count: 4};
        const text = `as number: ${(value as {count: number}).count}: done`;
        console.log(text);
        console.log(`escaped \${notCode as Type}: ${(value satisfies unknown) === value}`);
        "#,
        &["as number: 4: done", "escaped ${notCode as Type}: true"],
    );
}

#[test]
fn typed_template_callbacks_keep_statements_defaults_and_object_properties() {
    assert_output(
        r#"
        const first = `${((value: number, options: {increment: number} = {increment: 2}): number => value + options.increment)(3)}`;
        const second = `${(() => { const value: {x: number} = {x: 7}; return value.x; })()}`;
        console.log(first, second);
        "#,
        &["5 7"],
    );
}

#[test]
fn nested_templates_preserve_evaluation_order_and_live_getters() {
    assert_output(
        r#"
        let reads: number = 0;
        const source = {get value() { reads++; return reads; }};
        const text = `outer ${`inner ${source!.value as number}`} then ${source!.value}`;
        console.log(text, reads);
        "#,
        &["outer inner 1 then 2 2"],
    );
}

#[test]
fn template_boundaries_keep_division_and_regular_expression_braces_distinct() {
    assert_output(
        r#"
        const value: unknown = 8;
        console.log(`${(value as number) / 2}: slash / raw`);
        console.log(`${/a}b/.test('a}b') ? value! : 0}`);
        console.log(`${(() => { if (true) /}/.test('}'); return value as number; })()}`);
        const object = { if(input: number): number { return input; } };
        console.log(`${object.if(value as number) / 2}: slash / raw`);
        "#,
        &["4: slash / raw", "8", "8", "4: slash / raw"],
    );
}

#[test]
fn tagged_templates_keep_the_tag_receiver_and_raw_segments() {
    assert_output(
        r#"
        const object = {
            prefix: 'tag',
            tag(parts, value) {
                console.log(this.prefix, parts.raw[0], value);
                return parts[1];
            }
        };
        const value: unknown = 3;
        console.log(object.tag`line\n${value as number}:tail`);
        "#,
        &["tag line\\n 3", ":tail"],
    );
}
