//! Boundary tests for async function support in franken-core.
//!
//! This test suite verifies that async functions, async closures, and related
//! async primitives work correctly across the franken-core crate boundary.
//! These tests exercise the public API to ensure async function support passes
//! all boundary checks for the extracted franken-core crate.

use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterError, LaneRouter, RoutedResult,
};
use frankenengine_core::ir_contract::{Ir3Instruction, Reg};
use frankenengine_core::lowering_pipeline::{LoweringError, LoweringPipeline};
use frankenengine_core::object_model::JsValue;
use frankenengine_core::parser::{CanonicalEs2020Parser, ParseError};
use frankenengine_core::promise_model::{PromiseHandle, PromiseState, PromiseStore};
use frankenengine_core::runtime_config::RuntimeConfig;

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Test utilities
// ---------------------------------------------------------------------------

fn create_test_config() -> RuntimeConfig {
    RuntimeConfig::new()
        .with_async_support(true)
        .with_promise_microtask_queue(true)
}

fn parse_and_lower(source: &str) -> Result<Vec<Ir3Instruction>, Box<dyn std::error::Error>> {
    let parser = CanonicalEs2020Parser::new();
    let ast = parser.parse(source)?;

    let mut pipeline = LoweringPipeline::new();
    let ir3_program = pipeline.lower(ast)?;

    Ok(ir3_program.instructions)
}

fn execute_async_program(
    instructions: Vec<Ir3Instruction>,
) -> Result<ExecutionResult, InterpreterError> {
    let config = create_test_config();
    let mut router = LaneRouter::new(config);
    router.execute(instructions)
}

// ---------------------------------------------------------------------------
// Basic async function tests
// ---------------------------------------------------------------------------

#[test]
fn test_async_function_declaration() {
    let source = r#"
        async function testAsync() {
            return 42;
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::CreateAsyncFunction { .. })),
        "async function should generate CreateAsyncFunction instruction"
    );
}

#[test]
fn test_async_function_invocation() {
    let source = r#"
        async function getValue() {
            return 100;
        }
        getValue();
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let result = execute_async_program(instructions).expect("execution should succeed");

    // Async function should return a Promise
    assert!(
        result.return_value.is_promise(),
        "async function should return a Promise"
    );
}

#[test]
fn test_async_function_await_simple() {
    let source = r#"
        async function main() {
            async function getValue() {
                return 42;
            }
            const result = await getValue();
            return result;
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. })),
        "await should generate AwaitValue instruction"
    );
}

#[test]
fn test_async_function_await_chaining() {
    let source = r#"
        async function step1() {
            return 10;
        }
        async function step2(x) {
            return x * 2;
        }
        async function main() {
            const a = await step1();
            const b = await step2(a);
            return b;
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let await_count = instructions
        .iter()
        .filter(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. }))
        .count();
    assert_eq!(await_count, 2, "should have two await operations");
}

#[test]
fn test_async_function_return() {
    let source = r#"
        async function testReturn() {
            if (true) {
                return "early";
            }
            return "late";
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AsyncReturn { .. })),
        "async return should generate AsyncReturn instruction"
    );
}

#[test]
fn test_async_function_throw() {
    let source = r#"
        async function testThrow() {
            throw new Error("async error");
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AsyncThrow { .. })),
        "async throw should generate AsyncThrow instruction"
    );
}

// ---------------------------------------------------------------------------
// Async closure tests
// ---------------------------------------------------------------------------

#[test]
fn test_async_arrow_function() {
    let source = r#"
        const asyncArrow = async () => {
            return "arrow result";
        };
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::CreateAsyncFunction { .. })),
        "async arrow function should create async function"
    );
}

#[test]
fn test_async_closure_capture() {
    let source = r#"
        function createAsyncClosure(x) {
            return async () => {
                return x + 10;
            };
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::CreateAsyncFunction { capture_count, .. } if *capture_count > 0
        )),
        "async closure should capture variables"
    );
}

#[test]
fn test_async_closure_multiple_captures() {
    let source = r#"
        function createComplexAsyncClosure(a, b, c) {
            return async (x) => {
                return a + b + c + x;
            };
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            Ir3Instruction::CreateAsyncFunction { capture_count, .. } if *capture_count >= 3
        )),
        "async closure should capture multiple variables"
    );
}

#[test]
fn test_async_closure_invocation() {
    let source = r#"
        const asyncFn = async (value) => value * 2;
        asyncFn(21);
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let result = execute_async_program(instructions).expect("execution should succeed");

    assert!(
        result.return_value.is_promise(),
        "async closure should return Promise"
    );
}

// ---------------------------------------------------------------------------
// Promise and Future shapes tests
// ---------------------------------------------------------------------------

#[test]
fn test_await_resolved_promise() {
    let source = r#"
        async function testAwaitResolved() {
            const promise = Promise.resolve(123);
            const result = await promise;
            return result;
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. })),
        "should await resolved promise"
    );
}

#[test]
fn test_await_rejected_promise() {
    let source = r#"
        async function testAwaitRejected() {
            try {
                const promise = Promise.reject(new Error("test error"));
                await promise;
            } catch (e) {
                return e.message;
            }
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. })),
        "should await rejected promise with try-catch"
    );
}

#[test]
fn test_await_promise_chain() {
    let source = r#"
        async function testPromiseChain() {
            const promise = Promise.resolve(10)
                .then(x => x * 2)
                .then(x => x + 5);
            return await promise;
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. })),
        "should await promise chain"
    );
}

#[test]
fn test_await_multiple_promises() {
    let source = r#"
        async function testMultiplePromises() {
            const p1 = Promise.resolve(1);
            const p2 = Promise.resolve(2);
            const p3 = Promise.resolve(3);

            const r1 = await p1;
            const r2 = await p2;
            const r3 = await p3;

            return r1 + r2 + r3;
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let await_count = instructions
        .iter()
        .filter(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. }))
        .count();
    assert_eq!(await_count, 3, "should have three await operations");
}

#[test]
fn test_promise_all_await() {
    let source = r#"
        async function testPromiseAll() {
            const promises = [
                Promise.resolve(1),
                Promise.resolve(2),
                Promise.resolve(3)
            ];
            const results = await Promise.all(promises);
            return results;
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. })),
        "should await Promise.all"
    );
}

// ---------------------------------------------------------------------------
// Dynamic dispatch tests
// ---------------------------------------------------------------------------

#[test]
fn test_async_function_dynamic_call() {
    let source = r#"
        const funcs = {
            asyncMethod: async function(x) {
                return x * 2;
            }
        };
        funcs.asyncMethod(10);
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let result = execute_async_program(instructions).expect("execution should succeed");

    assert!(
        result.return_value.is_promise(),
        "dynamic async call should return Promise"
    );
}

#[test]
fn test_async_method_call() {
    let source = r#"
        class AsyncClass {
            async process(data) {
                return data.toUpperCase();
            }
        }
        const instance = new AsyncClass();
        instance.process("hello");
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let result = execute_async_program(instructions).expect("execution should succeed");

    assert!(
        result.return_value.is_promise(),
        "async method call should return Promise"
    );
}

#[test]
fn test_async_function_apply() {
    let source = r#"
        async function asyncSum(a, b) {
            return a + b;
        }
        asyncSum.apply(null, [5, 10]);
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let result = execute_async_program(instructions).expect("execution should succeed");

    assert!(
        result.return_value.is_promise(),
        "async function apply should return Promise"
    );
}

#[test]
fn test_async_function_call() {
    let source = r#"
        async function asyncMultiply(a, b) {
            return a * b;
        }
        asyncMultiply.call(null, 3, 7);
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let result = execute_async_program(instructions).expect("execution should succeed");

    assert!(
        result.return_value.is_promise(),
        "async function call should return Promise"
    );
}

// ---------------------------------------------------------------------------
// Async iterator tests
// ---------------------------------------------------------------------------

#[test]
fn test_async_generator_creation() {
    let source = r#"
        async function* asyncGenerator() {
            yield 1;
            yield 2;
            yield 3;
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::CreateAsyncGenerator { .. })),
        "async generator should generate CreateAsyncGenerator instruction"
    );
}

#[test]
fn test_async_generator_yield() {
    let source = r#"
        async function* yieldingGenerator() {
            const value = await Promise.resolve(42);
            yield value;
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::Yield { .. })),
        "async generator should have yield instruction"
    );
}

#[test]
fn test_async_iterator_protocol() {
    let source = r#"
        async function testAsyncIterator() {
            async function* gen() {
                yield 1;
                yield 2;
            }

            for await (const value of gen()) {
                console.log(value);
            }
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::ForOfNext { .. })),
        "for-await-of should generate ForOfNext instruction"
    );
}

#[test]
fn test_async_iterator_manual() {
    let source = r#"
        async function testManualAsyncIterator() {
            async function* gen() {
                yield "a";
                yield "b";
                yield "c";
            }

            const iterator = gen();
            const first = await iterator.next();
            const second = await iterator.next();
            return [first.value, second.value];
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. })),
        "manual async iterator should await next() calls"
    );
}

// ---------------------------------------------------------------------------
// Error propagation tests
// ---------------------------------------------------------------------------

#[test]
fn test_async_error_propagation_throw() {
    let source = r#"
        async function throwingFunction() {
            throw new Error("async error");
        }

        async function catchingFunction() {
            try {
                await throwingFunction();
            } catch (error) {
                return error.message;
            }
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AsyncThrow { .. })),
        "should have async throw instruction"
    );
}

#[test]
fn test_async_error_propagation_await() {
    let source = r#"
        async function testAwaitErrorPropagation() {
            try {
                const promise = Promise.reject(new Error("rejected promise"));
                const result = await promise;
                return result;
            } catch (e) {
                return "caught: " + e.message;
            }
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. })),
        "should await promise that can reject"
    );
}

#[test]
fn test_async_error_chain_propagation() {
    let source = r#"
        async function level3() {
            throw new Error("level 3 error");
        }

        async function level2() {
            return await level3();
        }

        async function level1() {
            try {
                return await level2();
            } catch (e) {
                throw new Error("level 1: " + e.message);
            }
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    let await_count = instructions
        .iter()
        .filter(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. }))
        .count();
    assert!(
        await_count >= 2,
        "should have multiple await operations in error chain"
    );
}

#[test]
fn test_async_finally_block() {
    let source = r#"
        async function testAsyncFinally() {
            let cleanupCalled = false;
            try {
                await Promise.resolve(42);
                return "success";
            } finally {
                cleanupCalled = true;
            }
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. })),
        "should await in try block with finally"
    );
}

// ---------------------------------------------------------------------------
// Complex async patterns tests
// ---------------------------------------------------------------------------

#[test]
fn test_async_parallel_execution() {
    let source = r#"
        async function parallelExecution() {
            async function task1() { return 1; }
            async function task2() { return 2; }
            async function task3() { return 3; }

            const [result1, result2, result3] = await Promise.all([
                task1(),
                task2(),
                task3()
            ]);

            return result1 + result2 + result3;
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::CreateAsyncFunction { .. })),
        "should create multiple async functions"
    );
}

#[test]
fn test_async_recursive_function() {
    let source = r#"
        async function asyncFactorial(n) {
            if (n <= 1) {
                return 1;
            }
            const result = await asyncFactorial(n - 1);
            return n * result;
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. })),
        "recursive async function should await recursive call"
    );
}

#[test]
fn test_async_timeout_pattern() {
    let source = r#"
        async function withTimeout(promise, ms) {
            const timeout = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Timeout')), ms)
            );

            return Promise.race([promise, timeout]);
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        !instructions.is_empty(),
        "timeout pattern should generate valid instructions"
    );
}

#[test]
fn test_async_pipeline_pattern() {
    let source = r#"
        async function asyncPipeline(value, ...transforms) {
            let result = value;
            for (const transform of transforms) {
                result = await transform(result);
            }
            return result;
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. })),
        "async pipeline should await transform functions"
    );
}

#[test]
fn test_async_boundary_comprehensive() {
    // This test combines multiple async patterns to verify comprehensive boundary support
    let source = r#"
        async function comprehensiveAsyncTest() {
            // 1. Basic async function
            async function fetchData(id) {
                return `data-${id}`;
            }

            // 2. Async closure with capture
            const processData = async (data, multiplier) => {
                return data.length * multiplier;
            };

            // 3. Promise construction and awaiting
            const promise = new Promise(async (resolve) => {
                const data = await fetchData(123);
                resolve(data);
            });

            // 4. Error handling with async
            try {
                const rawData = await promise;
                const processed = await processData(rawData, 2);

                // 5. Async iteration
                async function* dataGenerator() {
                    for (let i = 0; i < 3; i++) {
                        yield await fetchData(i);
                    }
                }

                const results = [];
                for await (const item of dataGenerator()) {
                    results.push(item);
                }

                return { processed, results };
            } catch (error) {
                return { error: error.message };
            }
        }
    "#;

    let instructions = parse_and_lower(source).expect("parsing and lowering should succeed");

    // Verify presence of all major async constructs
    let has_async_function = instructions
        .iter()
        .any(|inst| matches!(inst, Ir3Instruction::CreateAsyncFunction { .. }));
    let has_await = instructions
        .iter()
        .any(|inst| matches!(inst, Ir3Instruction::AwaitValue { .. }));
    let has_async_generator = instructions
        .iter()
        .any(|inst| matches!(inst, Ir3Instruction::CreateAsyncGenerator { .. }));

    assert!(has_async_function, "should have async function creation");
    assert!(has_await, "should have await operations");
    assert!(has_async_generator, "should have async generator creation");
}
