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
        "class-execution.ts",
        "class-trace",
        "class-decision",
        "class-policy",
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
        &Ir0Module::from_syntax_tree(tree, "class-execution.ts"),
        &LoweringContext::new("class-trace", "class-decision", "class-policy"),
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
        let mut core = InterpreterCore::new(config, "class-execution");
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
fn generic_subclasses_keep_constructor_super_and_method_dispatch() {
    assert_output(
        r#"
        class Base<T> {
            constructor(value: T) { this.value = value; }
            read(): T { return this.value; }
        }
        class Child extends Base<{count: number}> implements Readable<{count: number}> {
            constructor(value: {count: number}) { super(value); }
            total(offset: number): number { return this.read().count + offset; }
        }
        const child = new Child({count: 7});
        console.log(child.total(2), child instanceof Base, child instanceof Child);
        "#,
        &["9 true true"],
    );
}

#[test]
fn generic_mixin_heritage_evaluates_the_factory_once() {
    assert_output(
        r#"
        let calls = 0;
        class Base { read() { return 3; } }
        function mixin<T>(base: any) {
            calls++;
            return class extends base { tag(): string { return 'mixed'; } };
        }
        class Child extends mixin<number>(Base)<{value: number}> {
            read(): number { return super.read() + 4; }
        }
        const first = new Child();
        const second = new Child();
        console.log(calls, first.tag(), first.read(), second instanceof Base);
        "#,
        &["1 mixed 7 true"],
    );
}

#[test]
fn computed_heritage_retains_getter_and_key_evaluation_order() {
    assert_output(
        r#"
        const seen = [];
        class Base { read() { return 11; } }
        const namespace = { get Base() { seen.push('get'); return Base; } };
        function key() { seen.push('key'); return 'Base'; }
        class Child extends namespace[key()]<number> implements Named {
            read(): number { return super.read() + 1; }
        }
        console.log(seen.join(','), new Child().read());
        "#,
        &["key,get 12"],
    );
}

#[test]
fn throwing_heritage_preserves_exception_identity() {
    assert_output(
        r#"
        const failure = {code: 9};
        let reads = 0;
        const namespace = { get Base() { reads++; throw failure; } };
        try {
            class Child extends namespace.Base<{value: number}> implements Named {}
            console.log('wrong');
        } catch (error) { console.log(error === failure, reads); }
        "#,
        &["true 1"],
    );
}

#[test]
fn anonymous_and_conditional_heritage_remain_runtime_expressions() {
    assert_output(
        r#"
        class First { read() { return 'first'; } }
        class Second { read() { return 'second'; } }
        const Child = class extends (1 < 2 ? First : Second)<number> implements Named {};
        const child = new Child();
        console.log(child.read(), child instanceof First, child instanceof Second);
        "#,
        &["first true false"],
    );
}

#[test]
fn nested_class_expression_does_not_hide_the_outer_members() {
    assert_output(
        r#"
        class Child extends class Base<T> { read(): number { return 6; } } {
            total(value: number): number { return this.read() + value; }
        }
        console.log(new Child().total(4));
        "#,
        &["10"],
    );
}

#[test]
fn multiline_implements_types_are_not_read_as_values() {
    assert_output(
        r#"
        let reads = 0;
        const Types = { get Named() { reads++; throw 'types are not values'; } };
        class Base { read() { return 8; } }
        class Child extends Base<number>
            implements
                Types.Named,
                Storage<{value: number}, readonly [number, string]>
        {
            read(): number { return super.read() + 2; }
        }
        console.log(new Child().read(), reads);
        "#,
        &["10 0"],
    );
}

#[test]
fn inheritance_inside_template_interpolation_uses_the_class_pass() {
    assert_output(
        r#"
        class Base { read() { return 4; } }
        const text = `raw: ${new (class extends Base<number> implements Named {
            read(): number { return super.read() + 3; }
        })().read()}: done`;
        console.log(text);
        "#,
        &["raw: 7: done"],
    );
}

#[test]
fn constructor_overloads_create_only_the_implementation_constructor() {
    assert_output(
        r#"
        let calls = 0;
        class Box {
            constructor(value: number);
            constructor(value: string);
            constructor(value: number | string) { calls++; this.value = value; }
        }
        const first = new Box(7);
        const second = new Box('value');
        console.log(calls, first.value, second.value, first instanceof Box);
        "#,
        &["2 7 value true"],
    );
}

#[test]
fn method_and_static_generic_overloads_keep_their_single_implementation() {
    assert_output(
        r#"
        let calls = 0;
        class Converter {
            convert(value: number): number;
            convert(value: string): string;
            convert(value: unknown) { calls++; return value; }
            static choose<T>(value: T): T;
            static choose(value: unknown) { return value; }
        }
        const converter = new Converter();
        console.log(converter.convert(4), converter.convert('x'), Converter.choose(8), calls);
        "#,
        &["4 x 8 2"],
    );
}

#[test]
fn abstract_methods_and_accessors_dispatch_to_concrete_subclasses() {
    assert_output(
        r#"
        abstract class Base {
            abstract read(): number;
            abstract get size(): number;
            constructor() { this.value = 7; }
        }
        class Child extends Base {
            declare value: number;
            read(): number { return this.value; }
            get size(): number { return this.value + 1; }
        }
        const child = new Child();
        console.log(child.read(), child.size, typeof Base.prototype.read);
        "#,
        &["7 8 undefined"],
    );
}

#[test]
fn declared_fields_do_not_shadow_inherited_accessors() {
    assert_output(
        r#"
        class Base { get value() { return 9; } }
        class Child extends Base { declare value: number; }
        const child = new Child();
        console.log(child.value, Object.prototype.hasOwnProperty.call(child, 'value'));
        "#,
        &["9 false"],
    );
}

#[test]
fn declared_computed_and_static_members_never_evaluate_their_keys() {
    assert_output(
        r#"
        let reads = 0;
        const Keys = {get item() { reads++; return Symbol.iterator; }};
        class Child {
            declare [Keys.item]: () => Iterator<number>;
            declare static flag: number;
            constructor() { this.ready = true; }
        }
        const child = new Child();
        console.log(reads, child.ready, typeof Child.flag,
            Object.prototype.hasOwnProperty.call(Child, 'flag'));
        "#,
        &["0 true undefined false"],
    );
}

#[test]
fn class_index_signatures_create_no_runtime_binding_or_property() {
    assert_output(
        r#"
        class Store {
            [key: string]: unknown;
            readonly [key: symbol]: unknown;
            constructor() { this.answer = 42; }
            read(): number { return this.answer; }
        }
        const store = new Store();
        console.log(store.read(), Object.prototype.hasOwnProperty.call(store, 'key'));
        "#,
        &["42 false"],
    );
}

#[test]
fn methods_named_abstract_declare_and_readonly_are_real_members() {
    assert_output(
        r#"
        class Value {
            abstract<T>(value: T): T { return value; }
            declare() { return 2; }
            get readonly() { return 3; }
        }
        const value = new Value();
        console.log(value.abstract(6), value.declare(), value.readonly);
        "#,
        &["6 2 3"],
    );
}

#[test]
fn semicolonless_declarations_do_not_consume_the_following_implementation() {
    assert_output(
        r#"
        class Value {
            declare absent: number
            read(value: number): number
            read(value: unknown) { return value; }
        }
        const value = new Value();
        console.log(value.read(8), Object.prototype.hasOwnProperty.call(value, 'absent'));
        "#,
        &["8 false"],
    );
}

#[test]
fn overloaded_method_keeps_its_thrown_object_identity() {
    assert_output(
        r#"
        const failure = {code: 5};
        class Value {
            run(value: number): never;
            run(value: unknown) { throw failure; }
        }
        try { new Value().run(3); console.log('wrong'); }
        catch (error) { console.log(error === failure); }
        "#,
        &["true"],
    );
}

#[test]
fn template_class_declarations_use_the_same_type_only_member_rules() {
    assert_output(
        r#"
        const text = `value: ${new (class {
            declare absent: number;
            read(value: number): number;
            read(value: unknown) { return value; }
        })().read(5)}`;
        console.log(text);
        "#,
        &["value: 5"],
    );
}
