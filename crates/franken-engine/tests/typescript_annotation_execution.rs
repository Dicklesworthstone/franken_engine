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
