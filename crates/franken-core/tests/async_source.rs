//! Source async functions retain their execution kind, suspend at every await,
//! and resume with their registers, lexical cells and abrupt completions intact.

use std::collections::BTreeSet;
use std::path::PathBuf;

use frankenengine_core::ast::{MethodKind, ParseGoal, Statement};
use frankenengine_core::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::{Ir0Module, Ir1Op, Ir3Instruction};
use frankenengine_core::lowering_pipeline::{
    LoweringContext, LoweringPipelineError, lower_ir0_to_ir1, lower_ir0_to_ir3,
};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/modules")
        .canonicalize()
        .unwrap()
}

fn assert_output(source: &str, expected: &[&str]) {
    let root = fixture_root();
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Module)
        .expect("parse async source");
    let ir0 = Ir0Module::from_syntax_tree(tree, root.join("async-entry.mjs").display().to_string());
    let module = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("async-source", "async-source", "async-source"),
    )
    .expect("lower async source")
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
            RuntimeCapability::ModuleLoad,
        ]);
        config.module_root = Some(root.display().to_string());
        let result = InterpreterCore::new(config, "async-source")
            .execute(&module)
            .expect("execute async source");
        let output: Vec<_> = result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(output, expected, "throughput={throughput}: {source}");
    }
}

#[test]
fn settled_and_primitive_awaits_always_defer() {
    assert_output(
        r#"
        async function task(name, value) {
            console.log(name + ':start');
            const result = await value;
            console.log(name + ':' + result);
        }
        task('null', null);
        task('number', 7);
        task('promise', Promise.resolve(9));
        console.log('sync');
        "#,
        &[
            "null:start",
            "number:start",
            "promise:start",
            "sync",
            "null:null",
            "number:7",
            "promise:9",
        ],
    );
}

#[test]
fn awaited_thenables_read_getters_synchronously_and_invoke_them_with_the_receiver() {
    assert_output(
        r#"
        let reads = 0;
        class Waitable {
            constructor(value) { this.value = value; }
            get then() {
                reads += 1;
                console.log('getter');
                return function(resolve) {
                    console.log(this === thenable);
                    resolve(this.value);
                };
            }
        }
        const thenable = new Waitable(41);
        async function task() {
            const value = await thenable;
            return value + 1;
        }
        task().then(value => console.log(value));
        console.log('sync:' + reads);
        "#,
        &["getter", "sync:1", "true", "42"],
    );
}

#[test]
fn pending_native_timer_resolution_returns_to_the_caller() {
    assert_output(
        r#"
        async function task() {
            console.log('start');
            const value = await new Promise(resolve => setTimeout(resolve, 0, 21));
            return value * 2;
        }
        task().then(value => console.log(value));
        console.log('sync');
        "#,
        &["start", "sync", "42"],
    );
}

#[test]
fn nested_async_declarations_expressions_and_loop_activations_resume() {
    assert_output(
        r#"
        function makeTask() {
            async function next(value) {
                return await new Promise(resolve => setTimeout(resolve, 0, value));
            }
            return async function run() {
                let total = 0;
                for (let index = 0; index < 3; index++) {
                    total += await next(index + 1);
                }
                return total;
            };
        }
        makeTask()().then(value => console.log(value));
        console.log('sync');
        "#,
        &["sync", "6"],
    );
}

#[test]
fn async_arrows_preserve_lexical_this_and_block_fallthrough() {
    assert_output(
        r#"
        function Receiver() {
            this.value = 40;
            this.result = (async delta => {
                await 0;
                return this.value + delta;
            })(2);
        }
        const receiver = new Receiver();
        receiver.result.then(value => console.log(value));
        (async () => { await 1; 99; })().then(value => console.log(value === undefined));
        console.log('sync');
        "#,
        &["sync", "42", "true"],
    );
}

#[test]
fn object_async_methods_preserve_receiver_and_computed_keys() {
    assert_output(
        r#"
        const key = 'read';
        const object = {
            value: 40,
            async [key](delta) {
                await new Promise(resolve => setTimeout(resolve, 0));
                return this.value + delta;
            },
            async() { return 'ordinary'; }
        };
        object.read(2).then(value => console.log(value));
        console.log(object.async());
        "#,
        &["ordinary", "42"],
    );
}

#[test]
fn class_async_instance_static_and_expression_methods_keep_their_kind() {
    assert_output(
        r#"
        class Reader {
            constructor(value) { this.value = value; }
            async read(delta) { await 0; return this.value + delta; }
            static async result() { await 0; return 9; }
            async() { return 'ordinary'; }
        }
        const Named = class Self {
            static async identity() { await 0; return Self === Named; }
        };
        const reader = new Reader(40);
        Promise.all([reader.read(2), Reader.result(), Named.identity()]).then(values => {
            console.log(values[0] + ':' + values[1] + ':' + values[2]);
        });
        console.log(reader.async());
        "#,
        &["ordinary", "42:9:true"],
    );
}

#[test]
fn derived_async_methods_preserve_instance_and_static_super_across_await() {
    assert_output(
        r#"
        class Base {
            constructor(value) { this.value = value; }
            read(delta) { return this.value + delta; }
            static read() { return 10; }
        }
        class Derived extends Base {
            constructor(value) { super(value); }
            async read(delta) {
                await 0;
                return super.read(delta) + 1;
            }
            static async read() {
                await 0;
                return super.read() + 1;
            }
        }
        Promise.all([new Derived(40).read(1), Derived.read()]).then(values => {
            console.log(values[0] + ':' + values[1]);
        });
        console.log('sync');
        "#,
        &["sync", "42:11"],
    );
}

#[test]
fn async_named_expressions_retain_their_private_recursive_binding() {
    assert_output(
        r#"
        const count = async function recur(value) {
            if (value === 0) return 1;
            return 1 + await recur(value - 1);
        };
        async function unrelated() { return 0; }
        console.log(count == count);
        console.log(count == unrelated);
        count(2).then(value => console.log(value));
        console.log('sync');
        "#,
        &["true", "false", "sync", "3"],
    );
}

#[test]
fn async_return_adopts_promises_and_early_throws_reject() {
    assert_output(
        r#"
        const ready = Promise.resolve(42);
        async function adopt() { return ready; }
        const adopted = adopt();
        console.log(adopted === ready);
        adopted.then(value => console.log(value));
        const token = { marker: 7 };
        async function fail() { throw token; }
        fail().catch(error => console.log(error === token));
        async function nativeFailure() { undefined.value; }
        nativeFailure().catch(error => console.log(error.name));
        console.log('sync');
        "#,
        &["false", "sync", "true", "TypeError", "42"],
    );
}

#[test]
fn async_parameter_initialization_errors_reject_without_running_the_body() {
    assert_output(
        r#"
        async function task(first = second, second = 1) {
            console.log('unexpected body');
        }
        task().catch(error => console.log(error.name));
        console.log('sync');
        "#,
        &["sync", "ReferenceError"],
    );
}

#[test]
fn await_rejection_and_finally_suspension_preserve_the_completion_value() {
    assert_output(
        r#"
        const token = { marker: 7 };
        async function task() {
            try {
                try { return await Promise.reject(token); }
                catch (error) { console.log(error === token); return 42; }
            } finally {
                await new Promise(resolve => setTimeout(resolve, 0));
                console.log('cleanup');
            }
        }
        task().then(value => console.log(value));
        console.log('sync');
        "#,
        &["sync", "true", "cleanup", "42"],
    );
}

#[test]
fn rejection_after_a_suspended_finally_preserves_exception_identity() {
    assert_output(
        r#"
        const token = { marker: 7 };
        async function task() {
            try { throw token; }
            finally { await 0; console.log('cleanup'); }
        }
        task().catch(error => console.log(error === token));
        console.log('sync');
        "#,
        &["sync", "cleanup", "true"],
    );
}

#[test]
fn async_promise_and_timer_callbacks_park_independent_activations() {
    assert_output(
        r#"
        Promise.resolve(20).then(async value => {
            await new Promise(resolve => setTimeout(resolve, 0));
            return value + 1;
        }).then(value => console.log(value));
        setTimeout(async value => { await 0; console.log(value); }, 0, 42);
        console.log('sync');
        "#,
        &["sync", "42", "21"],
    );
}

#[test]
fn imported_async_functions_resume_using_their_defining_module() {
    assert_output(
        r#"
        import { delayed } from './async_operations.mjs';
        function unrelated() { return -900; }
        async function caller() { return 1 + await delayed(40); }
        caller().then(value => console.log(value));
        console.log('sync');
        "#,
        &["sync", "42"],
    );
}

#[test]
fn async_markers_survive_ir1_serialization_without_changing_sync_functions() {
    let tree = CanonicalEs2020Parser
        .parse(
            "function sync() { return 1; } async function task() { return await 2; }",
            ParseGoal::Script,
        )
        .unwrap();
    let ir0 = Ir0Module::from_syntax_tree(tree, "async-contract.js");
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap().module;
    let restored = serde_json::from_str::<frankenengine_core::ir_contract::Ir1Module>(
        &serde_json::to_string(&ir1).unwrap(),
    )
    .unwrap();
    assert_eq!(ir1, restored);
    for operation in &ir1.ops {
        if let Ir1Op::DeclareFunction { name, body_ops, .. } = operation {
            assert_eq!(
                matches!(body_ops.first(), Some(Ir1Op::AsyncFunctionStart)),
                name == "task",
            );
        }
    }
    let module = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("async", "async", "async"),
    )
    .unwrap()
    .ir3;
    assert_eq!(
        module.instructions.iter()
            .filter(|op| matches!(op, Ir3Instruction::CreateAsyncFunction { .. }))
            .count(),
        1,
    );
    assert_eq!(
        module.instructions.iter()
            .filter(|op| matches!(op, Ir3Instruction::AwaitValue { .. }))
            .count(),
        1,
    );
}

#[test]
fn class_async_grammar_distinguishes_modifiers_and_rejects_invalid_parameters() {
    let tree = CanonicalEs2020Parser
        .parse(
            "class C { async task() { await 0; } async() { return 1; } }",
            ParseGoal::Script,
        )
        .unwrap();
    let Statement::ClassDeclaration(class) = &tree.body[0] else {
        panic!("class declaration")
    };
    assert_eq!(class.body[0].kind, MethodKind::AsyncMethod);
    assert_eq!(class.body[1].kind, MethodKind::Method);
    for source in [
        "class C { async constructor() {} }",
        "class C { async task(await) {} }",
        "class C { async task(value = await 1) {} }",
        "const object = { async task(await) {} };",
    ] {
        assert!(
            CanonicalEs2020Parser.parse(source, ParseGoal::Script).is_err(),
            "{source}",
        );
    }
}

#[test]
fn unsupported_async_contexts_fail_explicitly_instead_of_becoming_identity_moves() {
    for source in [
        "await Promise.resolve(1);",
        "async function* values() { yield* [1]; }",
    ] {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Module)
            .unwrap();
        let ir0 = Ir0Module::from_syntax_tree(tree, "unsupported-async.mjs");
        assert!(matches!(
            lower_ir0_to_ir3(&ir0, &LoweringContext::new("async", "async", "async")),
            Err(LoweringPipelineError::UnsupportedSyntax(_)),
        ));
    }
}
