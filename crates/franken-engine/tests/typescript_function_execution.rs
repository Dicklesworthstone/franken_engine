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
            ParseGoal::Script,
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
        let result = core.execute(&module).expect("native TS execution must succeed");
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
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
    assert_eq!(prepared.prepared_source.matches("export").count(), 1);
    assert!(prepared.prepared_source.contains("export function read"));
    CanonicalEs2020Parser.parse_with_options(
        ParserSource { label: prepared.source_label, text: prepared.prepared_source },
        ParseGoal::Module, &ParserOptions::default(),
    ).expect("remaining runtime export must parse as a JavaScript module");
}
