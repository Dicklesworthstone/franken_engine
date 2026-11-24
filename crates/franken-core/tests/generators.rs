//! Synchronous generator protocols execute through the public core pipeline.

use std::collections::BTreeSet;
use std::path::PathBuf;

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn assert_output(source: &str, expected: &[&str]) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/modules")
        .canonicalize()
        .unwrap();
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Module)
        .unwrap();
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, root.join("generator-entry.mjs").display().to_string()),
        &LoweringContext::new("generators", "generators", "generators"),
    )
    .unwrap()
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
        let result = InterpreterCore::new(config, "generators")
            .execute(&module)
            .unwrap_or_else(|error| panic!("throughput={throughput}: {error:?}\n{source}"));
        let output: Vec<_> = result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(output, expected, "throughput={throughput}: {source}");
    }
}

#[test]
fn throw_resumes_catch_and_yielding_finally_with_exact_identity() {
    assert_output(
        r#"
        const token = {};
        function* values() {
            try { yield 1; }
            catch (error) { console.log(error === token); yield 2; }
            finally { yield 3; }
            return 4;
        }
        const iterator = values();
        console.log(iterator[Symbol.iterator]() === iterator);
        console.log(iterator.next().value);
        console.log(iterator.throw(token).value);
        console.log(iterator.next().value);
        const last = iterator.next();
        console.log(last.value, last.done);
        try { iterator.throw(token); } catch (error) { console.log(error === token); }
        "#,
        &["true", "1", "true", "2", "3", "4 true", "true"],
    );
}

#[test]
fn abrupt_resume_before_start_does_not_run_body() {
    assert_output(
        r#"
        let entered = 0;
        function* values() { entered++; try { yield 1; } finally { entered++; } }
        const first = values();
        const token = {};
        try { first.throw(token); } catch (error) { console.log(error === token); }
        console.log(first.next().done);
        const second = values();
        const last = second.return(42);
        console.log(last.value, last.done, entered);
        "#,
        &["true", "true", "42 true 0"],
    );
}

#[test]
fn yield_star_flattens_iterables_and_preserves_delegate_completion() {
    assert_output(
        r#"
        function* inner() { yield 2; yield 3; return 7; }
        function* outer() {
            yield* [1];
            const result = yield* inner();
            console.log('completion:' + result);
            yield* 'ab';
            return 9;
        }
        const iterator = outer();
        for (let i = 0; i < 6; i++) {
            const result = iterator.next();
            console.log(result.value, result.done);
        }
        "#,
        &[
            "1 false",
            "2 false",
            "3 false",
            "completion:7",
            "a false",
            "b false",
            "9 true",
        ],
    );
}

#[test]
fn yield_star_forwards_arguments_and_captures_next_only_once() {
    assert_output(
        r#"
        let calls = 0;
        const result = { value: 'first', done: false };
        const delegate = {
            [Symbol.iterator]() { return this; },
            next(value) {
                console.log('next:' + value);
                calls++;
                this.next = function() { throw 'replacement'; };
                return calls === 1 ? result : { value: value + 1, done: true };
            }
        };
        function* values() { return yield* delegate; }
        const iterator = values();
        console.log(iterator.next(99) === result);
        const last = iterator.next(8);
        console.log(last.value, last.done);
        "#,
        &["next:undefined", "true", "next:8", "9 true"],
    );
}

#[test]
fn delegated_return_can_yield_before_completing_outer_finally() {
    assert_output(
        r#"
        function* inner() { try { yield 1; } finally { yield 2; console.log('inner'); } }
        function* outer() { try { return yield* inner(); } finally { console.log('outer'); } }
        const iterator = outer();
        console.log(iterator.next().value);
        const during = iterator.return(9);
        console.log(during.value, during.done);
        const last = iterator.next();
        console.log(last.value, last.done);
        "#,
        &["1", "2 false", "inner", "outer", "9 true"],
    );
}

#[test]
fn missing_delegate_throw_closes_and_throws_inside_outer_generator() {
    assert_output(
        r#"
        let closed = 0;
        const delegate = {
            [Symbol.iterator]() { return this; },
            next() { return { value: 1, done: false }; },
            return() { closed++; return { done: true }; }
        };
        function* values() { try { yield* delegate; } catch (error) { yield error.name; } }
        const iterator = values();
        console.log(iterator.next().value);
        console.log(iterator.throw('original').value, closed);
        console.log(iterator.next().done);
        "#,
        &["1", "TypeError 1", "true"],
    );
}

#[test]
fn imported_generator_keeps_its_executable_owner() {
    assert_output(
        r#"
        import { importedValues } from './generators.mjs';
        function unrelated() { throw 'wrong module'; }
        const iterator = importedValues(20);
        console.log(iterator.next().value);
        console.log(iterator.next(4).value);
        const last = iterator.next();
        console.log(last.value, last.done);
        "#,
        &["owner:20", "24", "25 true"],
    );
}

#[test]
fn delegated_throw_can_yield_or_complete_normally() {
    assert_output(
        r#"
        const token = {};
        let throws = 0;
        const delegate = {
            [Symbol.iterator]() { return this; },
            next() { return { value: 1, done: false }; },
            throw(error) {
                console.log(this === delegate, error === token);
                throws++;
                return { value: throws + 1, done: throws === 2 };
            }
        };
        function* values() { const result = yield* delegate; yield result + 10; return 99; }
        const iterator = values();
        console.log(iterator.next().value);
        console.log(iterator.throw(token).value);
        console.log(iterator.throw(token).value);
        const last = iterator.next();
        console.log(last.value, last.done);
        "#,
        &["1", "true true", "2", "true true", "13", "99 true"],
    );
}

#[test]
fn delegated_yield_does_not_read_value_before_the_consumer() {
    assert_output(
        r#"
        let doneReads = 0;
        let valueReads = 0;
        const result = {
            get done() { doneReads++; return false; },
            get value() { valueReads++; return 7; }
        };
        const delegate = {
            [Symbol.iterator]() { return this; },
            next() { return result; }
        };
        function* values() { yield* delegate; }
        const iterator = values();
        const first = iterator.next();
        console.log(first === result, doneReads, valueReads);
        console.log(first.value, valueReads);
        const last = iterator.return(9);
        console.log(last.value, last.done, doneReads, valueReads);
        "#,
        &["true 1 0", "7 1", "9 true 1 1"],
    );
}

#[test]
fn delegated_protocol_errors_reach_generator_catch_with_close_precedence() {
    assert_output(
        r#"
        const token = {};
        const delegate = {
            [Symbol.iterator]() { return this; },
            next() { return { value: 1, done: false }; },
            return() { throw token; }
        };
        function* closing() {
            try { yield* delegate; } catch (error) { yield error === token; }
        }
        const iterator = closing();
        console.log(iterator.next().value);
        console.log(iterator.throw('original').value);
        console.log(iterator.next().done);
        const malformed = {
            [Symbol.iterator]() { return this; },
            next() { return 42; }
        };
        function* invalid() {
            try { yield* malformed; } catch (error) { yield error.name; }
        }
        console.log(invalid().next().value);
        function* nonIterable() {
            try { yield* 42; } catch (error) { yield error.name; }
        }
        console.log(nonIterable().next().value);
        "#,
        &["1", "true", "true", "TypeError", "TypeError"],
    );
}

#[test]
fn reentrant_resume_is_catchable_and_leaves_the_generator_usable() {
    assert_output(
        r#"
        let iterator;
        function* values() {
            try { iterator.next(); } catch (error) { yield error.name; }
            try { iterator.throw(1); } catch (error) { yield error.name; }
            try { iterator.return(2); } catch (error) { yield error.name; }
            return 9;
        }
        iterator = values();
        console.log(iterator.next().value);
        console.log(iterator.next().value);
        console.log(iterator.next().value);
        const last = iterator.next();
        console.log(last.value, last.done);
        "#,
        &["TypeError", "TypeError", "TypeError", "9 true"],
    );
}

#[test]
fn delegated_return_that_yields_resumes_outer_body_normally() {
    assert_output(
        r#"
        function* inner() {
            try { yield 1; } finally { yield 2; console.log('inner'); }
        }
        function* outer() {
            try {
                const result = yield* inner();
                console.log('continued:' + result);
                yield 3;
                return 4;
            } finally { console.log('outer'); }
        }
        const iterator = outer();
        console.log(iterator.next().value);
        const during = iterator.return(9);
        console.log(during.value, during.done);
        const resumed = iterator.next();
        console.log(resumed.value, resumed.done);
        const last = iterator.next();
        console.log(last.value, last.done);
        "#,
        &[
            "1",
            "2 false",
            "inner",
            "continued:9",
            "3 false",
            "outer",
            "4 true",
        ],
    );
}
