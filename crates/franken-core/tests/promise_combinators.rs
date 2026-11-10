//! Source-level Promise combinators share the ordinary resolution and reaction
//! machinery, including thenable adoption and observable microtask ordering.

use std::collections::BTreeSet;

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::checkpoint::CancellationToken;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn assert_output(source: &str, expected: &[&str]) {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("parse Promise combinator source");
    let ir0 = Ir0Module::from_syntax_tree(tree, "promise-combinators.js");
    let module = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("combinators", "combinators", "combinators"),
    )
    .expect("lower Promise combinator source")
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
        let result = InterpreterCore::new(config, "combinators")
            .execute(&module)
            .expect("execute Promise combinator source");
        let output: Vec<_> = result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(output, expected, "throughput={throughput}: {source}");
    }
}

#[test]
fn all_adopts_thenables_and_preserves_input_order() {
    assert_output(
        r#"
        const delayed = {
            then(resolve) { Promise.resolve().then(() => resolve(5)); }
        };
        Promise.all([delayed, 2, Promise.resolve(3)]).then(values => {
            console.log(values[0] + ',' + values[1] + ',' + values[2]);
        });
        "#,
        &["5,2,3"],
    );
}

#[test]
fn nonempty_combinators_settle_after_their_element_reaction_jobs() {
    assert_output(
        r#"
        Promise.all([1]).then(() => console.log('all'));
        Promise.race([Promise.resolve(2)]).then(() => console.log('race'));
        Promise.any([3]).then(() => console.log('any'));
        Promise.allSettled([Promise.reject(4)]).then(() => console.log('settled'));
        Promise.resolve().then(() => console.log('tick'));
        "#,
        &["tick", "all", "race", "any", "settled"],
    );
}

#[test]
fn race_uses_resolution_order_and_still_processes_later_thenables() {
    assert_output(
        r#"
        const slower = { then(resolve) { resolve(1); } };
        Promise.race([slower, 2]).then(value => console.log('winner:' + value));
        let visited = 0;
        const later = { then(resolve) { visited += 1; resolve(9); } };
        Promise.race([3, later]).then(value => console.log(value + ':' + visited));
        "#,
        &["winner:2", "3:1"],
    );
}

#[test]
fn all_settled_adopts_each_input_and_records_its_completion_kind() {
    assert_output(
        r#"
        const fulfilled = { then(resolve) { resolve(4); } };
        const rejected = { then(resolve, reject) { reject('no'); } };
        Promise.allSettled([fulfilled, rejected, 7]).then(values => {
            console.log(values[0].status + ':' + values[0].value);
            console.log(values[1].status + ':' + values[1].reason);
            console.log(values[2].status + ':' + values[2].value);
        });
        "#,
        &["fulfilled:4", "rejected:no", "fulfilled:7"],
    );
}

#[test]
fn any_waits_for_rejections_and_preserves_error_input_order() {
    assert_output(
        r#"
        const first = {
            then(resolve, reject) { Promise.resolve().then(() => reject('first')); }
        };
        const second = { then(resolve, reject) { reject('second'); } };
        Promise.any([first, second]).catch(error => {
            console.log(error.name + ':' + error.errors[0] + ',' + error.errors[1]);
        });
        "#,
        &["AggregateError:first,second"],
    );
}

#[test]
fn all_propagates_thenable_rejection() {
    assert_output(
        r#"
        const rejected = { then(resolve, reject) { reject('failed'); } };
        Promise.all([Promise.resolve(1), rejected]).then(
            () => console.log('unexpected fulfillment'),
            reason => console.log(reason)
        );
        "#,
        &["failed"],
    );
}

#[test]
fn aggregate_elements_preserve_identity_while_race_and_any_resolve_the_winner() {
    assert_output(
        r#"
        const value = {};
        const ready = Promise.resolve(value);
        value.then = resolve => resolve(99);
        Promise.all([ready]).then(values => console.log('all:' + (values[0] === value)));
        Promise.race([ready]).then(result => console.log('race:' + result));
        Promise.any([ready]).then(result => console.log('any:' + result));
        "#,
        &["all:true", "race:99", "any:99"],
    );
}

#[test]
fn empty_combinators_preserve_their_distinct_settlement_rules() {
    assert_output(
        r#"
        Promise.all([]).then(values => console.log('all:' + values.length));
        Promise.allSettled([]).then(values => console.log('settled:' + values.length));
        Promise.any([]).catch(error => console.log('any:' + error.name + ':' + error.errors.length));
        Promise.race([]).then(
            () => console.log('unexpected fulfillment'),
            () => console.log('unexpected rejection')
        );
        Promise.resolve().then(() => console.log('tick'));
        "#,
        &["all:0", "settled:0", "any:AggregateError:0", "tick"],
    );
}

#[test]
fn combinators_consume_custom_iterables_and_ignore_extra_arguments() {
    assert_output(
        r#"
        const iterable = {
            [Symbol.iterator]() {
                let index = 0;
                return {
                    next() {
                        index += 1;
                        return { value: index * 2, done: index > 2 };
                    }
                };
            }
        };
        Promise.all(iterable, ['ignored']).then(values => console.log(values[0] + ',' + values[1]));
        Promise.race(iterable).then(value => console.log('race:' + value));
        Promise.any(iterable).then(value => console.log('any:' + value));
        Promise.allSettled(iterable).then(values => console.log(values[1].status + ':' + values[1].value));
        "#,
        &["2,4", "race:2", "any:2", "fulfilled:4"],
    );
}

#[test]
fn string_iteration_uses_code_points_and_empty_strings_are_empty_iterables() {
    assert_output(
        r#"
        Promise.all('A\uD83D\uDE00\uD800').then(values => {
            console.log(values.length + ':' + values[1].length + ':' + values[2].length);
        });
        Promise.all('').then(values => console.log('empty:' + values.length));
        "#,
        &["empty:0", "3:2:1"],
    );
}

#[test]
fn non_iterables_reject_the_returned_promise_without_synchronous_throw() {
    assert_output(
        r#"
        Promise.all().catch(error => console.log('missing:' + error.name));
        Promise.race(null).catch(error => console.log('null:' + error.name));
        Promise.any(4).catch(error => console.log('number:' + error.name));
        Promise.allSettled({ 0: 1, length: 1 }).catch(error => console.log('object:' + error.name));
        const overridden = [];
        overridden[Symbol.iterator] = undefined;
        Promise.all(overridden).catch(error => console.log('override:' + error.name));
        console.log('sync');
        "#,
        &[
            "sync",
            "missing:TypeError",
            "null:TypeError",
            "number:TypeError",
            "object:TypeError",
            "override:TypeError",
        ],
    );
}

#[test]
fn iterator_failures_reject_with_exact_identity_and_do_not_call_return() {
    assert_output(
        r#"
        const reason = {};
        let closed = 0;
        const iterable = {
            [Symbol.iterator]() {
                let index = 0;
                return {
                    next() {
                        index += 1;
                        if (index === 2) throw reason;
                        return { value: 1, done: false };
                    },
                    return() { closed += 1; return {}; }
                };
            }
        };
        Promise.all(iterable).catch(error => console.log((error === reason) + ':' + closed));
        Promise.race(iterable).catch(error => console.log('race:' + (error === reason)));
        console.log('sync');
        "#,
        &["sync", "true:0", "race:true"],
    );
}

#[test]
fn iteration_resolves_each_element_before_requesting_the_next() {
    assert_output(
        r#"
        let trace = '';
        class Thenable {
            get then() {
                trace += 'get;';
                return resolve => resolve(8);
            }
        }
        const iterable = {
            [Symbol.iterator]() {
                let index = 0;
                return {
                    next() {
                        trace += 'next' + index + ';';
                        index += 1;
                        return { value: new Thenable(), done: index > 1 };
                    }
                };
            }
        };
        Promise.all(iterable).then(values => console.log(values[0]));
        console.log(trace);
        "#,
        &["next0;get;next1;", "8"],
    );
}

#[test]
fn array_iteration_observes_holes_and_length_changes_during_resolution() {
    assert_output(
        r#"
        const values = [0, 2];
        class First {
            get then() {
                values[1] = 7;
                values.push(9);
                return undefined;
            }
        }
        values[0] = new First();
        Promise.all(values).then(result => console.log(result.length + ':' + result[1] + ':' + result[2]));
        const sparse = [1, 2, 3];
        delete sparse[1];
        Promise.all(sparse).then(result => console.log(result.length + ':' + result[1]));
        "#,
        &["3:7:9", "3:undefined"],
    );
}

#[test]
fn iterator_next_getter_is_captured_once_and_preserves_its_receiver() {
    assert_output(
        r#"
        let reads = 0;
        class Cursor {
            constructor() { this.index = 0; }
            get next() {
                reads += 1;
                return function() {
                    this.index += 1;
                    return { value: this.index, done: this.index > 2 };
                };
            }
        }
        const iterable = { [Symbol.iterator]() { return new Cursor(); } };
        Promise.all(iterable).then(values => console.log(reads + ':' + values[0] + ',' + values[1]));
        "#,
        &["1:1,2"],
    );
}

#[test]
fn generators_are_consumed_synchronously_and_resolved_through_jobs() {
    assert_output(
        r#"
        function* values() {
            console.log('start');
            yield Promise.resolve(3);
            yield 5;
            console.log('end');
        }
        Promise.all(values()).then(result => console.log(result[0] + ',' + result[1]));
        console.log('sync');
        "#,
        &["start", "end", "sync", "3,5"],
    );
}

#[test]
fn custom_iterable_may_return_a_generator_and_empty_generators_are_empty() {
    assert_output(
        r#"
        function* values() { yield 4; yield 6; }
        function* empty() {}
        const iterable = { [Symbol.iterator]() { return values(); } };
        Promise.all(iterable).then(result => console.log(result[0] + ',' + result[1]));
        Promise.all(empty()).then(result => console.log('empty:' + result.length));
        "#,
        &["empty:0", "4,6"],
    );
}

#[test]
fn shared_generator_iteration_closes_through_finally_on_break_and_throw() {
    assert_output(
        r#"
        function* values() {
            try { yield 1; yield 2; }
            finally { console.log('closed'); }
        }
        for (const value of values()) { console.log(value); break; }
        const original = {};
        function* failingCleanup() {
            try { yield 1; }
            finally { throw 'cleanup'; }
        }
        try {
            for (const value of failingCleanup()) { throw original; }
        } catch (error) { console.log(error === original); }
        "#,
        &["1", "closed", "true"],
    );
}

#[test]
fn iterator_protocol_getter_errors_keep_the_original_thrown_value() {
    assert_output(
        r#"
        const reason = {};
        const brokenIterable = {
            get [Symbol.iterator]() { throw reason; }
        };
        class BrokenStep {
            get done() { throw reason; }
        }
        const iterable = {
            [Symbol.iterator]() { return { next() { return new BrokenStep(); } }; }
        };
        Promise.all(brokenIterable).catch(error => console.log('iterator:' + (error === reason)));
        Promise.all(iterable).catch(error => console.log('step:' + (error === reason)));
        "#,
        &["iterator:true", "step:true"],
    );
}

#[test]
fn native_iterable_steps_obey_instruction_budgets_and_cancellation() {
    let tree = CanonicalEs2020Parser
        .parse(
            "const values = []; values.length = 10000; Promise.all(values);",
            ParseGoal::Script,
        )
        .expect("parse sparse-array budget source");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "iterable-budget.js"),
        &LoweringContext::new("budget", "budget", "budget"),
    )
    .expect("lower sparse-array budget source")
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
        config.instruction_budget = 128;
        let failure = InterpreterCore::new(config.clone(), "iterable-budget")
            .execute(&module)
            .expect_err("native iteration must consume the instruction budget");
        assert!(
            matches!(
                failure,
                InterpreterError::BudgetExhausted {
                    executed: 128,
                    budget: 128
                }
            ),
            "throughput={throughput}: {failure:?}",
        );

        let token = CancellationToken::new();
        token.cancel();
        config.cancellation_token = Some(token);
        config.checkpoint_density = u64::MAX;
        let failure = InterpreterCore::new(config, "iterable-cancel")
            .execute(&module)
            .expect_err("native iteration must poll cancellation");
        assert!(
            matches!(failure, InterpreterError::Cancelled),
            "throughput={throughput}: {failure:?}",
        );
    }
}
