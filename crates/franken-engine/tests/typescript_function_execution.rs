#![forbid(unsafe_code)]

//! Public TS ingestion must erase signatures, not replace runtime functions.
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use frankenengine_engine::ts_normalization::prepare_source_entry_for_public_entrypoints;

fn assert_output(source: &str, expected: &[&str]) {
    assert_output_goal(source, expected, ParseGoal::Script);
}

fn assert_module_output(source: &str, expected: &[&str]) {
    assert_output_goal(source, expected, ParseGoal::Module);
}

fn assert_output_goal(source: &str, expected: &[&str], goal: ParseGoal) {
    let prepared = prepare_source_entry_for_public_entrypoints(
        source,
        "function-execution.ts",
        "function-trace",
        "function-decision",
        "function-policy",
    )
    .expect("TypeScript normalization must succeed");
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: prepared.source_label,
                text: prepared.prepared_source,
            },
            goal,
            &ParserOptions::default(),
        )
        .expect("normalized source must parse as JavaScript");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "function-execution.ts"),
        &LoweringContext::new("function-trace", "function-decision", "function-policy"),
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
            RuntimeCapability::Timer,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "function-execution");
        let result = core
            .execute(&module)
            .expect("native TS execution must succeed");
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
fn overloads_keep_implementation_hoisting_and_identity() {
    assert_output(
        r#"
        console.log(choose(3), choose('ok'));
        function choose(value: number): number;
        function choose(value: string): string;
        function choose(value: number | string) {
            return typeof value === 'number' ? value + 1 : value + '!';
        }
        const same = choose;
        console.log(same === choose, choose.name, choose.length);
        "#,
        &["4 ok!", "true choose 1"],
    );
}

#[test]
fn overloads_do_not_run_defaults_or_add_arguments() {
    assert_output(
        r#"
        let defaults = 0;
        function sum(first?: number, ...rest: number[]): number;
        function sum(first: number = (++defaults, 10), ...rest: number[]) {
            return first + rest.length;
        }
        console.log(defaults, sum.length);
        console.log(sum(), defaults, sum(2, 3, 4), defaults);
        "#,
        &["0 0", "10 1 4 1"],
    );
}

#[test]
fn nested_overloads_keep_per_invocation_closure_state() {
    assert_output(
        r#"
        function make(start: number): (step?: number) => number {
            function next(step?: number): number;
            function next(step: number = 1): number { start += step; return start; }
            return next;
        }
        const first = make(2), second = make(10);
        console.log(first(), first(3), second(), first());
        "#,
        &["3 6 11 7"],
    );
}

#[test]
fn receiver_and_destructured_overloads_keep_real_call_semantics() {
    assert_output(
        r#"
        function add(this: {base: number}, {offset}: {offset: number}): number;
        function add(this: {base: number}, {offset}: {offset: number}) {
            return this.base + offset;
        }
        const object = {base: 5, add};
        console.log(object.add({offset: 3}), add.length);
        "#,
        &["8 1"],
    );
}

#[test]
fn ambient_function_declarations_never_shadow_builtins_or_create_stubs() {
    assert_output(
        r#"
        declare function parseInt(source: string, radix?: number): number;
        declare function missingExternal(): number;
        console.log(parseInt('2a', 16), typeof missingExternal);
        try { missingExternal(); }
        catch (error) { console.log(error.name); }
        "#,
        &["42 undefined", "ReferenceError"],
    );
}

#[test]
fn generic_overloads_and_object_return_types_reach_the_implementation() {
    assert_output(
        r#"
        function wrap<T extends {count: number}>(value: T): {value: T};
        function wrap<T extends {count: number}>(value: T): {value: T} {
            return {value};
        }
        const input = {count: 4};
        const result = wrap<{count: number}>(input);
        console.log(result.value === input, result.value.count);
        "#,
        &["true 4"],
    );
}

#[test]
fn semicolonless_overloads_do_not_consume_following_bodies_or_statements() {
    assert_output(
        r#"
        function read(value: number): number
        function read(value: number): number
        { return value + 2; }
        console.log(read(3));
        "#,
        &["5"],
    );
}

#[test]
fn async_overloads_keep_promise_settlement_order_and_rejection_identity() {
    assert_output(
        r#"
        const failure = {code: 7};
        async function load(value: number): Promise<number>;
        async function load(value: number): Promise<number> {
            if (value < 0) { throw failure; }
            return value + 1;
        }
        load(3).then(value => console.log(value));
        load(-1).catch(error => console.log(error === failure));
        console.log('sync');
        "#,
        &["sync", "4", "true"],
    );
}

#[test]
fn template_callback_overloads_preserve_text_and_evaluation_count() {
    assert_output(
        r#"
        let calls = 0;
        const text = `value:${(() => {
            function read(value: number): number;
            function read(value: number): number { calls++; return value; }
            return read(4);
        })()}:tail`;
        console.log(text, calls);
        "#,
        &["value:4:tail 1"],
    );
}

#[test]
fn exported_signatures_are_removed_but_implementation_exports_still_parse() {
    let prepared = prepare_source_entry_for_public_entrypoints(
        "export function read(value: number): number;\nexport function read(value: number) { return value; }",
        "exported-overload.ts", "t", "d", "p",
    ).expect("exported overload should normalize");
    assert_eq!(
        prepared
            .prepared_source
            .matches("export function read")
            .count(),
        1
    );
    assert!(prepared.prepared_source.starts_with("export{};"));
    assert!(prepared.prepared_source.contains("export function read"));
    CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: prepared.source_label,
                text: prepared.prepared_source,
            },
            ParseGoal::Module,
            &ParserOptions::default(),
        )
        .expect("remaining runtime export must parse as a JavaScript module");
}

#[test]
fn ambient_host_bindings_do_not_shadow_real_runtime_builtins() {
    assert_output(
        r#"
        declare const console: {log(...values: unknown[]): void};
        declare var Math: {max(...values: number[]): number};
        declare let JSON: {stringify(value: unknown): string};
        console.log(Math.max(2, 5, 3), JSON.stringify({value: 7}));
        "#,
        &["5 {\"value\":7}"],
    );
}

#[test]
fn ambient_binding_kinds_create_no_undefined_slots_or_literal_values() {
    assert_output(
        r#"
        declare var absentVar: number;
        declare let absentLet: string;
        declare const absentConst = 42, absentString = 'text', absentFlag = true;
        console.log(typeof absentVar, typeof absentLet, typeof absentConst);
        console.log(typeof absentString, typeof absentFlag);
        try { absentConst; } catch (error) { console.log(error.name); }
        "#,
        &[
            "undefined undefined undefined",
            "undefined undefined",
            "ReferenceError",
        ],
    );
}

#[test]
fn ambient_declarations_preserve_existing_variable_values_and_literal_text() {
    assert_output(
        r#"
        var supplied = 12;
        declare var supplied: number;
        const text = 'declare const missing: number;';
        console.log(supplied, text);
        "#,
        &["12 declare const missing: number;"],
    );
}

#[test]
fn an_erased_exported_ambient_binding_keeps_module_this_and_strict_functions() {
    assert_module_output(
        r#"
        export declare const providedByHost: {value: number};
        function receiver() { return this; }
        console.log(this === undefined, receiver() === undefined, typeof providedByHost);
        "#,
        &["true true undefined"],
    );
}

#[test]
fn an_ambient_only_exported_source_is_an_executable_empty_module() {
    assert_module_output(
        r#"
        export declare function external(value: number): number;
        export declare const externalValue: {value: number};
        "#,
        &[],
    );
}

#[test]
fn invalid_ambient_initializers_are_preserved_for_diagnostics() {
    let prepared = prepare_source_entry_for_public_entrypoints(
        "declare const valid: number, invalid = effect();\nconsole.log('after');",
        "invalid-ambient.ts",
        "t",
        "d",
        "p",
    )
    .expect("unsupported initializer is retained for the parser");
    assert!(prepared.prepared_source.contains("declare const valid"));
    assert!(prepared.prepared_source.contains("invalid = effect()"));
    assert!(prepared.prepared_source.contains("console.log('after')"));
}

#[test]
fn newline_separated_declare_identifiers_still_execute() {
    assert_output(
        r#"
        try {
            declare
            const value: number = 1;
            console.log('wrong');
        } catch (error) { console.log(error.name); }
        try {
            declare
            function read(value: number): number;
            function read(value: number) { return value; }
            console.log('wrong');
        } catch (error) { console.log(error.name); }
        console.log('after');
        "#,
        &["ReferenceError", "ReferenceError", "after"],
    );
}

#[test]
fn namespace_exported_variables_share_live_property_storage() {
    assert_output(
        r#"
        namespace Counter {
            export let value: number = 1;
            export var step: number = 2;
            export function inc() { return value += step; }
            export function read() { return value; }
            export function post() { return value++; }
        }
        Counter.step = 3;
        console.log(Counter.inc(), Counter.value);
        Counter.value = 10;
        console.log(Counter.read(), Counter.inc(), Counter.value);
        console.log(Counter.post(), Counter.value);
        const descriptor = Object.getOwnPropertyDescriptor(Counter, 'value')!;
        console.log(descriptor.value, descriptor.writable, descriptor.enumerable,
            descriptor.configurable, typeof descriptor.get);
        "#,
        &["4 4", "10 13 13", "13 14", "14 true true true undefined"],
    );
}

#[test]
fn namespace_merged_bodies_keep_source_order_and_private_scopes() {
    assert_output(
        r#"
        let trace = '';
        namespace Ordered {
            const privateValue = 'left';
            export const first = (trace += 'a');
            export function left() { return privateValue; }
        }
        trace += 'b';
        namespace Ordered {
            const privateValue = 'right';
            export const second = (trace += 'c');
            export function right() { return privateValue; }
        }
        console.log(trace, Ordered.first, Ordered.second, Ordered.left(), Ordered.right());
        "#,
        &["abc a abc left right"],
    );
}

#[test]
fn namespace_functions_keep_local_identity_and_resolve_other_bodies() {
    assert_output(
        r#"
        namespace Actions {
            export function factorial(value: number): number {
                return value <= 1 ? 1 : value * factorial(value - 1);
            }
            export function original() { return 'local'; }
            export function local() { return original(); }
            export function callLater() { return later(); }
        }
        namespace Actions {
            export function later() { return 'late'; }
            export function other() { return original(); }
        }
        const original = Actions.original;
        Actions.original = function () { return 'replacement'; };
        console.log(Actions.factorial(4), Actions.local(), Actions.other(),
            Actions.callLater(), original === Actions.original);
        "#,
        &["24 local replacement late false"],
    );
}

#[test]
fn namespace_wrappers_preserve_user_names_and_initialize_self_references() {
    assert_output(
        r#"
        const ns = 40;
        namespace Hygiene {
            export const outer = ns;
            export const self: object = Hygiene;
            export function same() { return self === Hygiene; }
        }
        namespace Member {
            export let ns = 3;
            export function inc() { return ++ns; }
        }
        console.log(Hygiene.outer, Hygiene.self === Hygiene, Hygiene.same(),
            Member.inc(), Member.ns);
        "#,
        &["40 true true 4 4"],
    );
}

#[test]
fn namespace_references_respect_parameter_block_and_loop_scopes() {
    assert_output(
        r#"
        namespace Scoped {
            export let value = 10;
            export function withDefault(input = value) {
                var value = 99;
                return input;
            }
            export function parameter(value: number) { return ++value; }
            export function hoisted() {
                if (false) { var value = 88; }
                return typeof value;
            }
            export function caught() {
                try { throw 4; } catch (value) { return (value as number) + 1; }
            }
            export function loop() {
                let total = 0;
                for (let value of [1, 2]) { total += value; }
                return total + value;
            }
            export function block() {
                let total = 0;
                { const value = 7; total = value; }
                return total + value;
            }
            export function temporal() {
                let blocked = false;
                const read = () => value;
                try { read(); } catch (error) { blocked = error instanceof ReferenceError; }
                let value = 50;
                return blocked && read() === 50;
            }
        }
        console.log(Scoped.withDefault(), Scoped.parameter(2), Scoped.hoisted(),
            Scoped.caught(), Scoped.loop(), Scoped.block(), Scoped.temporal(), Scoped.value);
        "#,
        &["10 3 undefined 5 13 17 true 10"],
    );
}

#[test]
fn namespace_references_preserve_property_names_and_template_expressions() {
    assert_output(
        r#"
        namespace Snapshots {
            export let value = 2;
            export function summary() {
                const object = {
                    value,
                    fixed: {value: 8},
                    read(value: number) { return value + 1; }
                };
                return `${object.value}:${object.fixed.value}:${object.read(3)}:${value}:${/value/.test('value')}`;
            }
        }
        Snapshots.value = 6;
        console.log(Snapshots.summary());
        "#,
        &["6:8:4:6:true"],
    );
}

#[test]
fn namespace_exports_execute_as_module_bindings() {
    assert_module_output(
        r#"
        export namespace Public {
            export let value = 1;
            export function inc() { return ++value; }
        }
        export namespace Public {
            export function read() { return value; }
        }
        const same = Public;
        console.log(this === undefined, Public.inc(), Public.read(), same === Public);
        Public.value = 8;
        console.log(same.read());
        "#,
        &["true 2 2 true", "8"],
    );
}

#[test]
fn namespace_augmentation_preserves_callable_and_constructor_identity() {
    assert_output(
        r#"
        function make(value: number) { return value + 1; }
        const originalFactory = make;
        namespace make {
            export let version = 1;
            export function describe() { return version; }
        }
        class Box {
            value = 0;
            constructor(value: number) { this.value = value; }
        }
        const OriginalBox = Box;
        namespace Box {
            export const label = 'box';
            export function create(value: number) { return new Box(value); }
        }
        console.log(make(3), make.version, make.describe(), make === originalFactory);
        make.version = 2;
        const instance = Box.create(7);
        console.log(make.describe(), Box.label, instance.value,
            instance instanceof OriginalBox, Box === OriginalBox);
        "#,
        &["4 1 1 true", "2 box 7 true true"],
    );
}

#[test]
fn namespace_functions_preserve_object_return_types_and_values() {
    assert_output(
        r#"
        namespace Factory {
            export function make(value: number): {value: number; nested: {valid: boolean}} {
                return {value, nested: {valid: value > 0}};
            }
        }
        const result = Factory.make(7);
        console.log(result.value, result.nested.valid, Factory.make(-1).nested.valid);
        "#,
        &["7 true false"],
    );
}

#[test]
fn namespace_local_classes_preserve_parameter_properties_and_live_defaults() {
    assert_output(
        r#"
        namespace Factory {
            export let initial: number = 3;
            export function make() {
                class Box { constructor(public readonly value: number = initial) {}
                    read(): number { return this.value + initial; }
                }
                return Box;
            }
        }
        const Box = Factory.make();
        const first = new Box();
        Factory.initial = 7;
        const second = new Box();
        const explicit = new Box(2);
        console.log(first.value, second.value, explicit.value,
            first.read(), second.read(), Factory.initial);
        "#,
        &["3 7 2 10 14 7"],
    );
}

#[test]
fn constructor_parameter_properties_preserve_regex_defaults_and_modifier_comments() {
    assert_output(
        r#"
        class Pattern { constructor(public matches: boolean = /[)]/.test(")")) {} }
        class Commented { constructor(public /* property */ value: number = 3) {} }
        const pattern = new Pattern();
        const explicit = new Pattern(false);
        const commented = new Commented();
        console.log(pattern.matches, explicit.matches, commented.value);
        "#,
        &["true false 3"],
    );
}

#[test]
fn constructor_parameter_properties_distinguish_modifier_words_from_names() {
    assert_output(
        r#"
        class Ordinary {
            constructor(readonly: number = 4, public value: number = readonly) {}
        }
        class Properties {
            constructor(public readonly: number = 6, public override: number = 7) {}
        }
        const first = new Ordinary();
        const second = new Ordinary(9);
        const properties = new Properties();
        console.log(first.value, second.value, 'readonly' in first,
            properties.readonly, properties.override);
        "#,
        &["4 9 false 6 7"],
    );
}

#[test]
fn constructor_parameter_properties_follow_real_super_and_preserve_early_returns() {
    assert_output(
        r#"
        let trace = '';
        class Base { constructor() { trace += 'B'; } }
        class Derived extends Base {
            constructor(skip: boolean, public value: number = 3) {
                /* super(0); */
                trace += 'P';
                if (skip) { trace += 'R'; return {value: 99}; }
                const text = 'super(0);';
                super();
                trace += 'D' + this.value;
            }
        }
        const skipped = new Derived(true);
        console.log(skipped.value, trace);
        const normal = new Derived(false);
        console.log(normal.value, trace);
        "#,
        &["99 PR", "3 PRPBD3"],
    );
}

#[test]
fn constructor_parameter_properties_keep_directives_and_parenthesized_super_asi() {
    assert_output(
        r#"
        class Base {
            constructor(public base: number) {
                'use strict';
                console.log('base', this.base);
            }
        }
        class Derived extends Base {
            constructor(public value: number) {
                /* super(1000); */
                (super(5)) // the real call ends before this comment
                /* retain this comment too */
                console.log('derived', this.base, this.value);
            }
        }
        new Derived(7);
        "#,
        &["base 5", "derived 5 7"],
    );
}

#[test]
fn constructor_parameter_properties_keep_supported_jsx_before_super() {
    assert_output(
        r#"
        let trace = '';
        function createElement(...args: any[]) { trace += 'J'; return null; }
        function Widget() { return null; }
        class Base { constructor() { trace += 'B'; } }
        class Derived extends Base {
            constructor(public value: number = 3) {
                <Widget />
                super();
                trace += 'D' + this.value;
            }
        }
        const instance = new Derived();
        console.log(instance.value, trace);
        "#,
        &["3 JBD3"],
    );
}
