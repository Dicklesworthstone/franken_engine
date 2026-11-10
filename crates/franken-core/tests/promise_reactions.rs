//! Executable source and IR Promise jobs, including closure state, exceptions,
//! pending chains, and both core interpreter profiles.

use std::collections::BTreeSet;

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionResult, ExecutionSeed, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::hash_tiers::ContentHash;
use frankenengine_core::ifc_artifacts::Label;
use frankenengine_core::ir_contract::{
    CapabilityTag, Ir0Module, Ir3FunctionDesc, Ir3Instruction as Op, Ir3Module, RegRange,
};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn run_source(source: &str) -> Vec<String> {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("parse source");
    let ir0 = Ir0Module::from_syntax_tree(tree, "promise-source.js");
    let context = LoweringContext::new("promise-source", "promise-source", "promise-source");
    let module = lower_ir0_to_ir3(&ir0, &context).expect("lower source").ir3;
    let quickjs = lines(core().execute(&module).expect("execute QuickJS source"));
    let v8 = lines(
        core_with_config(InterpreterConfig::v8_defaults())
            .execute(&module)
            .expect("execute V8 source"),
    );
    assert_eq!(
        quickjs, v8,
        "Promise behavior must agree between core profiles"
    );
    quickjs
}

#[test]
fn source_promise_values_preserve_captured_functions_and_returned_closures() {
    assert_eq!(
        run_source(
            r#"
        const offset = 40;
        const original = value => value + offset;
        Promise.resolve(original).then(callback => {
            console.log(callback === original);
            console.log(callback(2));
            return value => original(value) + 1;
        }).then(callback => console.log(callback(2)));
    "#
        ),
        ["true", "42", "43"]
    );
}

#[test]
fn source_promise_rejection_and_finally_preserve_callable_identity() {
    assert_eq!(
        run_source(
            r#"
        const original = () => 7;
        Promise.reject(original).finally(() => original).catch(reason => {
            console.log(reason === original);
            console.log(reason());
        });
    "#
        ),
        ["true", "7"]
    );
}

#[test]
fn source_promise_values_preserve_native_and_bound_resolving_functions() {
    assert_eq!(
        run_source(
            r#"
        const native = Array.isArray;
        Promise.resolve(native).then(callback => {
            console.log(callback === native);
            console.log(callback([]));
        });
        new Promise(resolve => {
            Promise.resolve(resolve).then(deliver => deliver(8));
        }).then(value => console.log(value));
    "#
        ),
        ["true", "true", "8"]
    );
}

#[test]
fn source_promise_values_preserve_generator_state() {
    assert_eq!(
        run_source(
            r#"
        function* sequence() { yield 3; return 5; }
        const iterator = sequence();
        Promise.resolve(iterator).then(value => {
            console.log(value === iterator);
            console.log(value.next().value);
            return value;
        }).then(value => console.log(value.next().value));
    "#
        ),
        ["true", "3", "5"]
    );
}

#[test]
fn source_promise_combinator_results_preserve_callable_payloads() {
    assert_eq!(
        run_source(
            r#"
        const original = value => value + 1;
        Promise.all([original, Promise.resolve(original)]).then(values => {
            console.log(values[0] === original);
            console.log(values[1](9));
        });
        Promise.allSettled([Promise.reject(original)]).then(values => {
            console.log(values[0].reason === original);
            console.log(values[0].reason(10));
        });
    "#
        ),
        ["true", "10", "true", "11"]
    );
}

#[test]
fn source_promises_execute_a_deferred_chain_with_catch_and_finally() {
    assert_eq!(
        run_source(
            r#"
        let offset = 1;
        Promise.resolve(20)
            .then(value => value + offset)
            .then(value => { throw { marker: value * 2 }; })
            .catch(error => error.marker)
            .finally(() => console.log('cleanup'))
            .then(value => console.log(value));
        console.log('sync');
    "#
        ),
        ["sync", "cleanup", "42"]
    );
}

#[test]
fn source_promises_adopt_thenables_and_aggregate_callback_results() {
    assert_eq!(
        run_source(
            r#"
        const first = Promise.resolve({ then(resolve) { resolve(3); } });
        const second = Promise.reject(4).catch(value => value + 1);
        Promise.all([first, second]).then(values => console.log(values[0] + values[1]));
        Promise.resolve(9).finally(() => Promise.reject('override')).catch(error => console.log(error));
    "#
        ),
        ["8", "override"]
    );
}

#[test]
fn lexical_promise_bindings_shadow_the_static_intrinsic_in_nested_functions() {
    assert_eq!(
        run_source(
            r#"
        function outer(Promise) {
            return function inner() { return Promise.resolve(6); };
        }
        const custom = { resolve(value) { return value + 1; } };
        console.log(outer(custom)());
    "#
        ),
        ["7"]
    );
}

#[test]
fn source_promise_adoption_preserves_microtask_order_and_identity() {
    assert_eq!(
        run_source(
            r#"
        const original = Promise.resolve(1);
        console.log(Promise.resolve(original) === original);
        original.then(() => { console.log('a'); return Promise.resolve('value'); })
            .then(value => console.log(value));
        Promise.resolve().then(() => console.log('b'))
            .then(() => console.log('c')).then(() => console.log('d'));
    "#
        ),
        ["true", "a", "b", "c", "d", "value"]
    );
}

#[test]
fn source_promise_self_resolution_rejects_and_native_handlers_are_callable() {
    assert_eq!(
        run_source(
            r#"
        let cyclic = Promise.resolve(1).then(() => cyclic);
        cyclic.catch(error => console.log(error.name));
        Promise.resolve([]).then(Array.isArray).then(value => console.log(value));
    "#
        ),
        ["TypeError", "true"]
    );
}

#[test]
fn source_promise_executors_run_synchronously_and_ignore_later_completions() {
    assert_eq!(
        run_source(
            r#"
        console.log('before');
        new Promise((resolve, reject) => {
            console.log('executor');
            resolve(2);
            reject(3);
            throw 4;
        }).then(value => console.log(value));
        new Promise(() => { throw { marker: 5 }; }).catch(error => console.log(error.marker));
        new Promise(() => 99).then(() => console.log('must stay pending'));
        console.log('after');
    "#
        ),
        ["before", "executor", "after", "2", "5"]
    );
}

#[test]
fn source_resolving_pairs_lock_in_pending_adoption_and_escape_to_timers() {
    assert_eq!(
        run_source(
            r#"
        let release;
        const pending = new Promise(resolve => { release = resolve; });
        new Promise((resolve, reject) => {
            resolve(pending);
            reject('late');
            throw 'ignored';
        }).then(value => console.log(value), error => console.log(error));
        Promise.resolve({ then(resolve, reject) {
            resolve(pending);
            reject('late thenable');
            throw 'ignored thenable';
        } }).then(value => console.log(value), error => console.log(error));
        setTimeout(() => { release(21); release(99); }, 0);
    "#
        ),
        ["21", "21"]
    );
}

#[test]
fn source_finally_waits_for_a_pending_executor_before_restoring_rejection() {
    assert_eq!(
        run_source(
            r#"
        Promise.reject('original').finally(() => new Promise(resolve => {
            setTimeout(() => { console.log('finalizer'); resolve(99); }, 0);
        })).catch(error => console.log(error));
        console.log('sync');
    "#
        ),
        ["sync", "finalizer", "original"]
    );
}

#[test]
fn source_promise_constructor_rejects_invalid_executors_and_respects_shadowing() {
    assert_eq!(
        run_source(
            r#"
        try { new Promise(); } catch (error) { console.log(error.name); }
        try { new Promise(42); } catch (error) { console.log(error.name); }
        function outer(Promise) {
            return function inner() { return new Promise(9); };
        }
        function Custom(value) { this.value = value; }
        console.log(outer(Custom)().value);
    "#
        ),
        ["TypeError", "TypeError", "9"]
    );
}

#[test]
fn source_identity_handlers_and_adoption_resolve_newly_added_thenables() {
    assert_eq!(
        run_source(
            r#"
        const value = {};
        const original = Promise.resolve(value);
        value.then = resolve => resolve(42);
        original.then().then(result => console.log(result));
        original.catch(() => 0).then(result => console.log(result));
        original.finally(undefined).then(result => console.log(result));
        original.then(() => original).then(result => console.log(result));
    "#
        ),
        ["42", "42", "42", "42"]
    );
}

#[test]
fn source_native_callback_and_executor_failures_reject_with_error_objects() {
    assert_eq!(
        run_source(
            r#"
        Promise.resolve().then(value => value.x).catch(error => console.log(error.name));
        new Promise(() => { const value = undefined; return value.x; })
            .catch(error => console.log(error.name));
        Promise.resolve({ then(resolve) { const value = undefined; return value.x; } })
            .catch(error => console.log(error.name));
    "#
        ),
        ["TypeError", "TypeError", "TypeError"]
    );
}

fn host(capability: &str, start: u32, count: u32, dst: u32) -> Op {
    Op::HostCall {
        capability: CapabilityTag(capability.to_string()),
        args: RegRange { start, count },
        dst,
    }
}

fn promise(method: &str, start: u32, count: u32, dst: u32) -> Op {
    host(&format!("promise:{method}"), start, count, dst)
}

fn closure(dst: u32, function_index: u32) -> Op {
    Op::CreateClosure {
        dst,
        function_index,
        capture_count: 0,
    }
}

fn module(mut main: Vec<Op>, functions: Vec<(u32, Vec<Op>)>) -> Ir3Module {
    main.push(Op::Halt);
    let mut module = Ir3Module::new(
        ContentHash::compute(b"promise-reactions"),
        "promise-reactions",
    );
    module.instructions = main;
    module.constant_pool = ["saved", "then", "value", "marker", "sync"]
        .into_iter()
        .map(Into::into)
        .collect();
    for (index, (arity, body)) in functions.into_iter().enumerate() {
        module.function_table.push(Ir3FunctionDesc {
            entry: module.instructions.len() as u32,
            arity,
            frame_size: 16,
            name: Some(format!("reaction_{index}")),
            is_generator: false,
            rest_param_index: None,
        });
        module.instructions.extend(body);
    }
    module
}

fn core() -> InterpreterCore {
    core_with_config(InterpreterConfig::quickjs_defaults())
}

fn core_with_config(mut config: InterpreterConfig) -> InterpreterCore {
    config.instruction_budget = 100_000;
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    InterpreterCore::new(config, "promise-reactions")
}

fn log_body() -> (u32, Vec<Op>) {
    (
        1,
        vec![host("console:log", 0, 1, 1), Op::Return { value: 0 }],
    )
}

fn lines(result: ExecutionResult) -> Vec<String> {
    result
        .console_output
        .into_iter()
        .map(|line| line.message)
        .collect()
}

fn log_result(main: &mut Vec<Op>, source: u32, logger: u32, rejected_too: bool) {
    main.extend([
        Op::Move {
            dst: 10,
            src: source,
        },
        Op::Move {
            dst: 11,
            src: logger,
        },
        Op::Move {
            dst: 12,
            src: logger,
        },
        promise("then", 10, if rejected_too { 3 } else { 2 }, 13),
    ]);
}

#[test]
fn fulfillment_handler_transforms_the_value_after_synchronous_code() {
    let mut main = vec![
        Op::LoadInt { dst: 0, value: 21 },
        promise("resolve", 0, 1, 1),
        closure(2, 0),
        promise("then", 1, 2, 3),
        closure(4, 1),
    ];
    log_result(&mut main, 3, 4, false);
    main.extend([
        Op::LoadStr {
            dst: 6,
            pool_index: 4,
        },
        host("console:log", 6, 1, 7),
    ]);
    let module = module(
        main,
        vec![
            (
                1,
                vec![
                    Op::LoadInt { dst: 1, value: 2 },
                    Op::Mul {
                        dst: 0,
                        lhs: 0,
                        rhs: 1,
                    },
                    Op::Return { value: 0 },
                ],
            ),
            log_body(),
        ],
    );
    assert_eq!(lines(core().execute(&module).unwrap()), ["sync", "42"]);
}

#[test]
fn rejection_handlers_recover_and_non_callable_handlers_propagate() {
    for method in ["then", "catch"] {
        let mut main = vec![
            Op::LoadInt { dst: 0, value: 41 },
            promise("reject", 0, 1, 1),
            Op::LoadInt { dst: 2, value: 123 },
            promise("then", 1, 2, 4),
            Op::Move { dst: 1, src: 4 },
            closure(if method == "then" { 3 } else { 2 }, 0),
            promise(method, 1, if method == "then" { 3 } else { 2 }, 5),
            closure(6, 1),
        ];
        log_result(&mut main, 5, 6, false);
        let module = module(
            main,
            vec![
                (
                    1,
                    vec![
                        Op::LoadInt { dst: 1, value: 1 },
                        Op::Add {
                            dst: 0,
                            lhs: 0,
                            rhs: 1,
                        },
                        Op::Return { value: 0 },
                    ],
                ),
                log_body(),
            ],
        );
        assert_eq!(lines(core().execute(&module).unwrap()), ["42"], "{method}");
    }
}

#[test]
fn callback_throw_preserves_the_exact_exception_object() {
    let mut main = vec![
        Op::NewObject { dst: 0 },
        Op::LoadStr {
            dst: 7,
            pool_index: 3,
        },
        Op::LoadInt { dst: 8, value: 77 },
        Op::SetProperty {
            obj: 0,
            key: 7,
            val: 8,
        },
        promise("resolve", 0, 1, 1),
        closure(2, 0),
        promise("then", 1, 2, 3),
        Op::Move { dst: 1, src: 3 },
        closure(2, 1),
        promise("catch", 1, 2, 4),
        closure(5, 2),
    ];
    log_result(&mut main, 4, 5, false);
    let module = module(
        main,
        vec![
            (1, vec![Op::Throw { value: 0 }]),
            (
                1,
                vec![
                    Op::LoadStr {
                        dst: 1,
                        pool_index: 3,
                    },
                    Op::GetProperty {
                        obj: 0,
                        key: 1,
                        dst: 0,
                    },
                    Op::Return { value: 0 },
                ],
            ),
            log_body(),
        ],
    );
    assert_eq!(lines(core().execute(&module).unwrap()), ["77"]);
}

#[test]
fn a_returned_promise_is_adopted_instead_of_delivered_as_a_handle() {
    for method in ["resolve", "reject"] {
        let mut main = vec![
            Op::LoadInt { dst: 0, value: 23 },
            promise("resolve", 0, 1, 1),
            closure(2, 0),
            promise("then", 1, 2, 3),
            closure(4, 1),
        ];
        log_result(&mut main, 3, 4, true);
        let module = module(
            main,
            vec![
                (1, vec![promise(method, 0, 1, 1), Op::Return { value: 1 }]),
                log_body(),
            ],
        );
        assert_eq!(lines(core().execute(&module).unwrap()), ["23"], "{method}");
    }
}

#[test]
fn finally_has_no_arguments_and_preserves_both_completion_kinds() {
    for method in ["resolve", "reject"] {
        let mut main = vec![
            Op::LoadInt { dst: 0, value: 7 },
            promise(method, 0, 1, 1),
            closure(2, 0),
            promise("finally", 1, 2, 3),
            closure(4, 1),
        ];
        log_result(&mut main, 3, 4, true);
        let module = module(
            main,
            vec![
                (
                    1,
                    vec![
                        host("console:log", 0, 1, 1),
                        Op::LoadInt { dst: 0, value: 999 },
                        Op::Return { value: 0 },
                    ],
                ),
                log_body(),
            ],
        );
        assert_eq!(
            lines(core().execute(&module).unwrap()),
            ["undefined", "7"],
            "{method}"
        );
    }
}

#[test]
fn finally_waits_for_its_returned_promise_and_replaces_completion_on_failure() {
    for original in ["resolve", "reject"] {
        for finalizer in ["resolve", "reject"] {
            let mut main = vec![
                Op::LoadInt { dst: 0, value: 7 },
                promise(original, 0, 1, 1),
                closure(2, 0),
                promise("finally", 1, 2, 3),
                closure(4, 1),
            ];
            log_result(&mut main, 3, 4, true);
            let module = module(
                main,
                vec![
                    (
                        0,
                        vec![
                            Op::LoadInt { dst: 0, value: 99 },
                            promise(finalizer, 0, 1, 1),
                            Op::Return { value: 1 },
                        ],
                    ),
                    log_body(),
                ],
            );
            let expected = if finalizer == "resolve" { "7" } else { "99" };
            assert_eq!(
                lines(core().execute(&module).unwrap()),
                [expected],
                "{original}/{finalizer}"
            );
        }
    }
}

#[test]
fn callback_closure_observes_updated_captured_bindings() {
    let mut main = vec![
        Op::DeclareBinding {
            name_pool_index: 0,
            kind: 0,
        },
        Op::LoadInt { dst: 0, value: 1 },
        Op::StoreScoped {
            src: 0,
            name_pool_index: 0,
        },
        promise("resolve", 0, 1, 1),
        closure(2, 0),
        promise("then", 1, 2, 3),
        Op::LoadInt { dst: 0, value: 81 },
        Op::StoreScoped {
            src: 0,
            name_pool_index: 0,
        },
        closure(4, 1),
    ];
    log_result(&mut main, 3, 4, false);
    let module = module(
        main,
        vec![
            (
                1,
                vec![
                    Op::LoadScoped {
                        dst: 0,
                        name_pool_index: 0,
                    },
                    Op::Return { value: 0 },
                ],
            ),
            log_body(),
        ],
    );
    assert_eq!(lines(core().execute(&module).unwrap()), ["81"]);
}

#[test]
fn a_chain_waits_for_a_pending_thenable_settled_from_a_timer() {
    let mut main = vec![
        Op::DeclareBinding {
            name_pool_index: 0,
            kind: 0,
        },
        Op::NewObject { dst: 0 },
        Op::LoadStr {
            dst: 7,
            pool_index: 1,
        },
        closure(8, 0),
        Op::SetProperty {
            obj: 0,
            key: 7,
            val: 8,
        },
        promise("resolve", 0, 1, 1),
        closure(2, 1),
        promise("then", 1, 2, 3),
        closure(4, 2),
    ];
    log_result(&mut main, 3, 4, false);
    main.extend([
        closure(5, 3),
        Op::LoadInt { dst: 6, value: 0 },
        host("timer:setTimeout", 5, 2, 7),
    ]);
    let module = module(
        main,
        vec![
            (
                2,
                vec![
                    Op::StoreScoped {
                        src: 0,
                        name_pool_index: 0,
                    },
                    Op::Return { value: 0 },
                ],
            ),
            (
                1,
                vec![
                    Op::LoadInt { dst: 1, value: 2 },
                    Op::Mul {
                        dst: 0,
                        lhs: 0,
                        rhs: 1,
                    },
                    Op::Return { value: 0 },
                ],
            ),
            log_body(),
            (
                0,
                vec![
                    Op::LoadScoped {
                        dst: 1,
                        name_pool_index: 0,
                    },
                    Op::LoadInt { dst: 2, value: 21 },
                    Op::Call {
                        callee: 1,
                        args: RegRange { start: 2, count: 1 },
                        dst: 0,
                    },
                    Op::Return { value: 0 },
                ],
            ),
        ],
    );
    assert_eq!(lines(core().execute(&module).unwrap()), ["42"]);
}

#[test]
fn a_reaction_cannot_swallow_the_instruction_budget() {
    let module = module(
        vec![
            Op::LoadInt { dst: 0, value: 1 },
            promise("resolve", 0, 1, 1),
            closure(2, 0),
            promise("then", 1, 2, 3),
        ],
        vec![(1, vec![Op::Jump { target: 5 }])],
    );
    let error = core()
        .execute(&module)
        .expect_err("infinite callback must stop");
    assert!(
        matches!(error, InterpreterError::BudgetExhausted { .. }),
        "{error:?}"
    );
}

#[test]
fn a_promise_executor_cannot_swallow_the_instruction_budget() {
    let module = module(
        vec![closure(0, 0), promise("constructor", 0, 1, 1)],
        vec![(2, vec![Op::Jump { target: 3 }])],
    );
    let error = core()
        .execute(&module)
        .expect_err("infinite executor must stop");
    assert!(
        matches!(error, InterpreterError::BudgetExhausted { .. }),
        "{error:?}"
    );
}

#[test]
fn reaction_arguments_keep_their_labels_when_guest_code_stores_them() {
    let module = module(
        vec![
            promise("resolve", 0, 1, 1),
            closure(2, 0),
            promise("then", 1, 2, 3),
        ],
        vec![(
            1,
            vec![
                Op::NewObject { dst: 1 },
                Op::LoadStr {
                    dst: 2,
                    pool_index: 2,
                },
                Op::SetProperty {
                    obj: 1,
                    key: 2,
                    val: 0,
                },
                Op::Return { value: 1 },
            ],
        )],
    );
    let mut core = core();
    core.write_register(0, Value::Int(42));
    let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
    wire["register_labels"][0] = serde_json::to_value(Label::Secret).unwrap();
    let seed: ExecutionSeed = serde_json::from_value(wire).unwrap();
    core.reset_execution_state_from_seed(&seed).unwrap();
    core.execute(&module).unwrap();
    let object = core
        .get_heap()
        .iter()
        .find(|object| object.properties.get("value") == Some(&Value::Int(42)))
        .expect("callback created its object");
    let wire = serde_json::to_value(object).unwrap();
    assert_eq!(
        wire["property_labels"]["value"],
        serde_json::to_value(Label::Secret).unwrap()
    );
}
