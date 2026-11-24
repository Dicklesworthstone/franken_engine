//! Generator methods execute through the public parser, lowering, and runtime.

use std::collections::BTreeSet;

use frankenengine_core::ast::{Expression, MethodKind, ParseGoal, Statement};
use frankenengine_core::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser, ParseErrorCode};

fn assert_output(source: &str, expected: &[&str]) {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("parse generator methods");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "generator-methods.js"),
        &LoweringContext::new(
            "generator-methods",
            "generator-methods",
            "generator-methods",
        ),
    )
    .expect("lower generator methods")
    .ir3;
    for throughput in [false, true] {
        let mut config = if throughput {
            InterpreterConfig::v8_defaults()
        } else {
            InterpreterConfig::quickjs_defaults()
        };
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        let result = InterpreterCore::new(config, "generator-methods")
            .execute(&module)
            .expect("execute generator methods");
        let output: Vec<_> = result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(output, expected, "throughput={throughput}: {source}");
    }
}

#[test]
fn computed_object_methods_preserve_receiver_parameters_and_resumption() {
    assert_output(
        r#"
        let keys = 0;
        function key() { keys++; return 'values'; }
        const object = {
            base: 4,
            *[key()](start = 2, ...rest) {
                const sent = yield this.base + start;
                yield rest[0] + sent;
                return this.base;
            }
        };
        console.log(keys);
        const iterator = object.values(undefined, 7);
        console.log(iterator.next().value);
        console.log(iterator.next(3).value);
        const last = iterator.next();
        console.log(last.value + ':' + last.done);
        console.log(object.values.call({ base: 10 }, 5).next().value);
        "#,
        &["1", "6", "10", "4:true", "15"],
    );
}

#[test]
fn class_declarations_and_expressions_preserve_static_and_generator_kinds() {
    assert_output(
        r#"
        class Values {
            constructor(value) { this.value = value; }
            *items() { yield this.value; return 9; }
            static *['items'](value) { yield value; return 11; }
        }
        const Other = class { *items() { yield 13; } };
        const instance = new Values(7);
        const iterator = instance.items();
        console.log(iterator.next().value);
        console.log(iterator.next().value);
        const statics = Values.items(10);
        console.log(statics.next().value);
        console.log(statics.next().value);
        console.log((new Other()).items().next().value);
        "#,
        &["7", "9", "10", "11", "13"],
    );
}

#[test]
fn generator_methods_retain_home_object_with_a_borrowed_receiver() {
    assert_output(
        r#"
        const base = { read() { return this.value; } };
        const object = {
            __proto__: base,
            *items() { yield super.read(); yield super.read() + 1; }
        };
        const iterator = object.items.call({ value: 21 });
        console.log(iterator.next().value);
        console.log(iterator.next().value);
        class Base { read() { return this.value; } }
        class Derived extends Base {
            *items() { yield super.read(); }
        }
        const instance = new Derived();
        instance.value = 31;
        console.log(instance.items().next().value);
        "#,
        &["21", "22", "31"],
    );
}

#[test]
fn async_generator_methods_await_and_keep_method_receivers() {
    assert_output(
        r#"
        const object = {
            value: 7,
            async *items(add = 2) {
                yield await Promise.resolve(this.value + add);
                return this.value;
            }
        };
        class Values {
            static async *['items'](value) { yield value; return 12; }
        }
        const Other = class { async *items() { yield 13; } };
        async function check() {
            const iterator = object.items();
            console.log((await iterator.next()).value);
            const last = await iterator.next();
            console.log(last.value + ':' + last.done);
            const statics = Values.items(11);
            console.log((await statics.next()).value);
            console.log((await statics.next()).value);
            console.log((await (new Other()).items().next()).value);
        }
        check();
        "#,
        &["9", "7:true", "11", "12", "13"],
    );
}

#[test]
fn generator_method_contextual_names_comments_and_regex_goals_are_preserved() {
    assert_output(
        r#"
        const object = {
            * /* star trivia */ get() { yield 1; },
            * async() { yield 2; },
            async /* modifier trivia */ * set() { yield 3; }
        };
        console.log(object.get().next().value);
        console.log(object.async().next().value);
        object.set().next().then(result => console.log(result.value));
        "#,
        &["1", "2", "3"],
    );
    for source in [
        "({ *items() { yield /[{}]/; } })",
        "({ async *items() { yield /[{}]/; await /[{}]/; } })",
        "class C { *items() { yield /[{}]/; } }",
        "class C { async *items() { yield /[{}]/; await /[{}]/; } }",
    ] {
        CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source}: {error}"));
    }
}

#[test]
fn generator_method_early_errors_do_not_leak_grammar_context() {
    for source in [
        "({ *items(yield) {} })",
        "({ *items(value = yield 1) {} })",
        "({ async *items(await) {} })",
        "({ async *items(value = await 1) {} })",
        "({ *items(value, value) {} })",
        "({ async\n*items() {} })",
        "({ get *items() {} })",
        "class C { *constructor() {} }",
        "class C { async *constructor() {} }",
        "class C { *items(yield) {} }",
        "class C { async *items(await) {} }",
        "class C { async\n*items() {} }",
        "({ *items() { function ordinary() { yield 1; } } })",
        "({ *items() {}, ordinary() { yield 1; } })",
    ] {
        let error = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect_err(source);
        assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source}");
    }

    let tree = CanonicalEs2020Parser
        .parse(
            "class C { *one() {} async *two() {} static *constructor() {} ['constructor']() {} }",
            ParseGoal::Script,
        )
        .unwrap();
    let Statement::ClassDeclaration(class) = &tree.body[0] else {
        panic!("expected class declaration");
    };
    assert_eq!(class.body[0].kind, MethodKind::GeneratorMethod);
    assert_eq!(class.body[1].kind, MethodKind::AsyncGeneratorMethod);
    assert!(class.body[2].is_static);
    assert_eq!(class.body[2].kind, MethodKind::GeneratorMethod);
    assert!(class.body[3].computed);
    assert_eq!(class.body[3].kind, MethodKind::Method);
    assert!(matches!(&class.body[2].key, Expression::Identifier(name) if name == "constructor"));
}
