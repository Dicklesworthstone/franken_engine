//! Regression tests for bd-my5ar — engine<->core completion-value divergence
//! on a loop-accumulate function, surfaced by the bd-fqlfw.2.3.1 internal
//! differential oracle.
//!
//! Two independent franken-core defects conspired to make
//! `(function () { var s = 0; for (var i = 0; i < 5; i++) { s += i; } return s; })()`
//! return `0` instead of `10`:
//!
//!  1. **Function-body conditional/loop polarity.** The IR2->IR3 deferred
//!     function-body loop lowered `JumpIfFalsy` to a single `JumpIf`, but the
//!     interpreter's `JumpIf` jumps on TRUTHY — so every function-body `if`,
//!     ternary, `while`, and `for` test was inverted (the loop body / `if`
//!     consequent was skipped whenever the condition was true). The
//!     module-level loop already used the correct two-instruction
//!     "skip-on-truthy then jump-to-label" pattern; the fix gives the
//!     function-body loop the same pattern (and resolves its
//!     `PendingJump::JumpIfFalsy` targets).
//!
//!  2. **No `++` / `--` parser support.** The string-based parser mis-split
//!     postfix `i++` into `i + Raw("+")` and collapsed prefix `++i` into
//!     `+(+i)`, so the loop counter never advanced. Both forms now desugar to
//!     the equivalent compound assignment (`i += 1` / `i -= 1`).
//!
//! These tests pin both fixes across module-level and function-body contexts.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, QuickJsLane, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

use std::collections::BTreeSet;

/// Parse -> IR0 -> IR3 -> execute on the QuickJS lane with the minimal
/// execution capabilities, returning the full execution result.
fn run(source: &str) -> ExecutionResult {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_my5ar");
    let context = LoweringContext::new("bd-my5ar-trace", "bd-my5ar-decision", "bd-my5ar-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config)
        .execute(&module, "bd-my5ar-trace")
        .expect("execution should succeed")
}

/// Completion value of a script whose final statement is an expression.
fn completion(source: &str) -> Value {
    run(source).value
}

// --- The bead repro and its near neighbours. ---------------------------------

#[test]
fn iife_for_loop_accumulate_returns_ten() {
    // The exact bd-my5ar corpus case: 0+1+2+3+4 == 10.
    let src = "(function () { var s = 0; for (var i = 0; i < 5; i++) { s += i; } return s; })();";
    assert_eq!(completion(src), Value::Int(10));
}

#[test]
fn iife_for_loop_accumulate_explicit_assign_returns_ten() {
    // Same loop with `s = s + i` / `i = i + 1` instead of `+=` / `++`: isolates
    // the function-body polarity fix from the `++` parser fix.
    let src = "(function () { var s = 0; for (var i = 0; i < 5; i = i + 1) { s = s + i; } return s; })();";
    assert_eq!(completion(src), Value::Int(10));
}

#[test]
fn iife_while_loop_accumulate_returns_ten() {
    let src = "(function () { var s = 0; var i = 0; while (i < 5) { s += i; i++; } return s; })();";
    assert_eq!(completion(src), Value::Int(10));
}

// --- Function-body conditional polarity. -------------------------------------

#[test]
fn iife_if_true_enters_body() {
    let src = "(function () { var s = 5; if (s > 0) { s = 99; } return s; })();";
    assert_eq!(completion(src), Value::Int(99));
}

#[test]
fn iife_if_false_skips_body() {
    let src = "(function () { var s = 5; if (s < 0) { s = 99; } return s; })();";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn iife_if_else_takes_then_branch_when_true() {
    let src = "(function () { var s = 5; if (s > 0) { s = 1; } else { s = 2; } return s; })();";
    assert_eq!(completion(src), Value::Int(1));
}

#[test]
fn iife_ternary_true_branch() {
    let src = "(function () { return (1 > 0) ? 11 : 22; })();";
    assert_eq!(completion(src), Value::Int(11));
}

#[test]
fn iife_while_false_does_not_run() {
    let src = "(function () { var s = 5; while (s > 100) { s = 0; } return s; })();";
    assert_eq!(completion(src), Value::Int(5));
}

// --- `++` / `--` parser support, prefix and postfix, both contexts. ----------

#[test]
fn module_level_for_postfix_increment() {
    // Module-level (main loop) `i++` — exercises the parser fix where the
    // main-loop polarity was already correct.
    let src = "var s = 0; for (var i = 0; i < 5; i++) { s += i; } s;";
    assert_eq!(completion(src), Value::Int(10));
}

#[test]
fn prefix_increment_in_loop() {
    let src = "(function () { var s = 0; for (var i = 0; i < 5; ++i) { s += i; } return s; })();";
    assert_eq!(completion(src), Value::Int(10));
}

#[test]
fn postfix_decrement_counts_down() {
    let src = "(function () { var n = 0; for (var i = 5; i > 0; i--) { n += 1; } return n; })();";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn prefix_increment_statement_mutates_binding() {
    // `++i` as a statement must increment the binding (was `+(+i)` = no-op).
    let src = "(function () { var i = 7; ++i; return i; })();";
    assert_eq!(completion(src), Value::Int(8));
}

#[test]
fn postfix_increment_statement_mutates_binding() {
    let src = "(function () { var i = 7; i++; return i; })();";
    assert_eq!(completion(src), Value::Int(8));
}

// --- Controls: nested loop + accumulation across both contexts. --------------

#[test]
fn nested_iife_loops_multiply() {
    let src = "(function () { var t = 0; for (var i = 0; i < 3; i++) { for (var j = 0; j < 4; j++) { t += 1; } } return t; })();";
    assert_eq!(completion(src), Value::Int(12));
}

// --- IteratorClose parity (bd-t9n3s). --------------------------------------

#[test]
fn custom_iterator_break_calls_return_on_the_iterator_bd_t9n3s() {
    let src = r#"
        let nextCount = 0;
        let closeCount = 0;
        let iterator = {
            next: function () {
                nextCount = nextCount + 1;
                return nextCount === 1
                    ? { value: 7, done: false }
                    : { done: true };
            },
            return: function () {
                closeCount = closeCount + 1;
                return {};
            }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        let value = 0;
        for (const item of iterable) { value = item; break; }
        value * 10 + closeCount;
    "#;
    assert_eq!(completion(src), Value::Int(71));
}

#[test]
fn iterator_methods_receive_their_ordinary_receivers_bd_t9n3s() {
    let src = r#"
        let iterator = {
            count: 0,
            closed: 0,
            next: function () {
                this.count = this.count + 1;
                return { value: 7, done: false };
            },
            return: function () {
                this.closed = this.closed + 1;
                return {};
            }
        };
        let iterable = {
            calls: 0,
            [Symbol.iterator]: function () {
                this.calls = this.calls + 1;
                return iterator;
            }
        };
        let seen = 0;
        for (const value of iterable) { seen = value; break; }
        seen * 1000 + iterable.calls * 100 + iterator.count * 10 + iterator.closed;
    "#;
    assert_eq!(completion(src), Value::Int(7111));
}

#[test]
fn primitive_next_result_is_catchable_without_iterator_close_bd_t9n3s() {
    let src = r#"
        let closeCount = 0;
        let iterator = {
            next: function () { return 1; },
            return: function () { closeCount = closeCount + 1; return {}; }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        let caught = "";
        try { for (const value of iterable) { value; } }
        catch (error) { caught = error.name; }
        caught + ":" + closeCount;
    "#;
    assert_eq!(completion(src), Value::str("TypeError:0"));
}

#[test]
fn generator_function_is_a_callable_iterator_return_method_bd_t9n3s() {
    let src = r#"
        let iterator = {
            next: function () { return { value: 7, done: false }; },
            return: function* () { throw "body is lazy"; }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        let value = 0;
        let caught = false;
        try { for (const item of iterable) { value = item; break; } }
        catch (error) { caught = true; }
        value + ":" + caught;
    "#;
    assert_eq!(completion(src), Value::str("7:false"));
}

#[test]
fn body_throw_closes_once_and_original_throw_wins_bd_t9n3s() {
    let src = r#"
        let closeCount = 0;
        let iterator = {
            next: function () { return { value: 1, done: false }; },
            return: function () { closeCount = closeCount + 1; throw "close"; }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        let caught = "";
        try { for (const value of iterable) { throw "body"; } }
        catch (error) { caught = error; }
        caught + ":" + closeCount;
    "#;
    assert_eq!(completion(src), Value::str("body:1"));
}

#[test]
fn successful_function_return_closes_once_and_preserves_value_bd_t9n3s() {
    let src = r#"
        let closeCount = 0;
        let iterator = {
            next: function () { return { value: 7, done: false }; },
            return: function () { closeCount = closeCount + 1; return {}; }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        function f() {
            for (const value of iterable) { return value; }
            return 0;
        }
        f() + ":" + closeCount;
    "#;
    assert_eq!(completion(src), Value::str("7:1"));
}

#[test]
fn return_close_primitive_replaces_return_and_is_catchable_bd_t9n3s() {
    let src = r#"
        let iterator = {
            next: function () { return { value: 1, done: false }; },
            return: function () { return 0; }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        function f() {
            try { for (const value of iterable) { return "old"; } }
            catch (error) { return error.name; }
        }
        f();
    "#;
    assert_eq!(completion(src), Value::str("TypeError"));
}

#[test]
fn next_throw_is_catchable_without_iterator_close_bd_t9n3s() {
    let src = r#"
        let closeCount = 0;
        let iterator = {
            next: function () { throw "step"; },
            return: function () { closeCount = closeCount + 1; return {}; }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        let caught = "";
        try { for (const value of iterable) { value; } }
        catch (error) { caught = error; }
        caught + ":" + closeCount;
    "#;
    assert_eq!(completion(src), Value::str("step:0"));
}

#[test]
fn labelled_break_closes_nested_iterators_innermost_first_bd_t9n3s() {
    let src = r#"
        let log = "";
        let outerIterator = {
            next: function () { return { value: 1, done: false }; },
            return: function () { log = log + "o"; return {}; }
        };
        let innerIterator = {
            next: function () { return { value: 1, done: false }; },
            return: function () { log = log + "i"; return {}; }
        };
        let outerValues = { [Symbol.iterator]: function () { return outerIterator; } };
        let innerValues = { [Symbol.iterator]: function () { return innerIterator; } };
        outer: for (const x of outerValues) {
            for (const y of innerValues) { break outer; }
        }
        log;
    "#;
    assert_eq!(completion(src), Value::str("io"));
}

#[test]
fn inner_close_throw_still_closes_outer_and_keeps_inner_error_bd_t9n3s() {
    let src = r#"
        let log = "";
        let outerIterator = {
            next: function () { return { value: 1, done: false }; },
            return: function () { log = log + "o"; throw "outer-close"; }
        };
        let innerIterator = {
            next: function () { return { value: 1, done: false }; },
            return: function () { log = log + "i"; throw "inner-close"; }
        };
        let outerValues = { [Symbol.iterator]: function () { return outerIterator; } };
        let innerValues = { [Symbol.iterator]: function () { return innerIterator; } };
        let caught = "";
        try {
            outer: for (const x of outerValues) {
                for (const y of innerValues) { break outer; }
            }
        } catch (error) { caught = error; }
        log + ":" + caught;
    "#;
    assert_eq!(completion(src), Value::str("io:inner-close"));
}

#[test]
fn fallback_array_return_property_is_not_an_iterator_close_hook_bd_t9n3s() {
    let src = r#"
        let closeCount = 0;
        let values = [7];
        values.return = function () { closeCount = closeCount + 1; return {}; };
        for (const value of values) { break; }
        closeCount;
    "#;
    assert_eq!(completion(src), Value::Int(0));
}

#[test]
fn same_loop_continue_and_exhaustion_do_not_close_bd_t9n3s() {
    let src = r#"
        let index = 0;
        let closeCount = 0;
        let iterator = {
            next: function () {
                index = index + 1;
                return index < 3
                    ? { value: index, done: false }
                    : { done: true };
            },
            return: function () { closeCount = closeCount + 1; return {}; }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        let sum = 0;
        for (const value of iterable) { sum = sum + value; continue; }
        sum * 10 + closeCount;
    "#;
    assert_eq!(completion(src), Value::Int(30));
}

#[test]
fn labelled_continue_closes_inner_but_not_target_outer_iterator_bd_t9n3s() {
    let src = r#"
        let outerIndex = 0;
        let log = "";
        let outerIterator = {
            next: function () {
                outerIndex = outerIndex + 1;
                return outerIndex < 3
                    ? { value: outerIndex, done: false }
                    : { done: true };
            },
            return: function () { log = log + "o"; return {}; }
        };
        let innerIterator = {
            next: function () { return { value: 1, done: false }; },
            return: function () { log = log + "i"; return {}; }
        };
        let outerValues = { [Symbol.iterator]: function () { return outerIterator; } };
        let innerValues = { [Symbol.iterator]: function () { return innerIterator; } };
        outer: for (const x of outerValues) {
            for (const y of innerValues) { continue outer; }
        }
        log;
    "#;
    assert_eq!(completion(src), Value::str("ii"));
}

#[test]
fn source_finally_runs_before_iterator_close_bd_t9n3s() {
    let src = r#"
        let log = "";
        let iterator = {
            next: function () { return { value: 1, done: false }; },
            return: function () { log = log + "r"; return {}; }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        for (const value of iterable) {
            try { break; } finally { log = log + "f"; }
        }
        log;
    "#;
    assert_eq!(completion(src), Value::str("fr"));
}

#[test]
fn caught_close_failure_inside_finally_preserves_outer_return_bd_t9n3s() {
    let src = r#"
        let closeCount = 0;
        let iterator = {
            next: function () { return { value: 1, done: false }; },
            return: function () { closeCount = closeCount + 1; throw "close"; }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        function f() {
            try { return "old"; }
            finally {
                try { for (const value of iterable) { break; } }
                catch (error) { error; }
            }
        }
        f() + ":" + closeCount;
    "#;
    assert_eq!(completion(src), Value::str("old:1"));
}

#[test]
fn uncaught_close_failure_inside_finally_replaces_outer_return_bd_t9n3s() {
    let src = r#"
        let closeCount = 0;
        let iterator = {
            next: function () { return { value: 1, done: false }; },
            return: function () { closeCount = closeCount + 1; throw "close"; }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        function f() {
            try { return "old"; }
            finally { for (const value of iterable) { break; } }
        }
        let caught = "";
        try { f(); } catch (error) { caught = error; }
        caught + ":" + closeCount;
    "#;
    assert_eq!(completion(src), Value::str("close:1"));
}

// --- Loop-head assignment error routing (bd-dp12f). ------------------------

#[test]
fn const_for_of_head_error_closes_once_bd_dp12f() {
    let src = r#"
        let closeCount = 0;
        let iterator = {
            step: 0,
            next: function () {
                this.step = this.step + 1;
                return this.step === 1
                    ? { value: 7, done: false }
                    : { done: true };
            },
            return: function () { closeCount = closeCount + 1; return {}; }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        const fixed = 1;
        function run() {
            try { for (fixed of iterable) {} }
            catch (error) { return error.name; }
            return "miss";
        }
        run() + ":" + closeCount;
    "#;
    assert_eq!(completion(src), Value::str("TypeError:1"));
}

#[test]
fn tdz_for_of_head_error_closes_once_bd_dp12f() {
    let src = r#"
        let closeCount = 0;
        let step = 0;
        let iterator = {
            next: function () {
                step = step + 1;
                return step === 1
                    ? { value: 7, done: false }
                    : { done: true };
            },
            return: function () { closeCount = closeCount + 1; return {}; }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        function run() {
            try { for (future of iterable) {} }
            catch (error) { return error.name; }
            return "miss";
        }
        let observed = run();
        let future;
        observed + ":" + closeCount;
    "#;
    assert_eq!(completion(src), Value::str("ReferenceError:1"));
}

#[test]
fn destructuring_for_of_head_errors_close_once_bd_dp12f() {
    for (case, before, captured, target, yielded, after, expected) in [
        (
            "const array",
            "const fixed = 1;",
            "fixed",
            "[fixed]",
            "[7]",
            "",
            "TypeError:1",
        ),
        (
            "TDZ array",
            "",
            "future",
            "[future]",
            "[7]",
            "let future;",
            "ReferenceError:1",
        ),
        (
            "const object",
            "const fixed = 1;",
            "fixed",
            "{ value: fixed }",
            "{ value: 7 }",
            "",
            "TypeError:1",
        ),
    ] {
        let src = r#"
            let closeCount = 0;
            let step = 0;
            let iterator = {
                next: function () {
                    step = step + 1;
                    return step === 1
                        ? { value: __YIELDED__, done: false }
                        : { done: true };
                },
                return: function () { closeCount = closeCount + 1; return {}; }
            };
            let iterable = { [Symbol.iterator]: function () { return iterator; } };
            __BEFORE__
            function readCaptured() { return __CAPTURED__; }
            let observed = "miss";
            try { for (__TARGET__ of iterable) {} }
            catch (error) { observed = error.name; }
            __AFTER__
            observed + ":" + closeCount;
        "#
        .replace("__BEFORE__", before)
        .replace("__CAPTURED__", captured)
        .replace("__TARGET__", target)
        .replace("__YIELDED__", yielded)
        .replace("__AFTER__", after);
        assert_eq!(
            completion(&src),
            Value::str(expected),
            "{case} destructuring head"
        );
    }
}

#[test]
fn unresolved_destructuring_for_of_target_stays_lenient_bd_dp12f() {
    let src = r#"
        function readMissing() { return missing; }
        for ([missing] of [[7]]) {}
        readMissing();
    "#;
    assert_eq!(completion(src), Value::Int(7));
}

#[test]
fn for_of_head_error_wins_over_return_failures_bd_dp12f() {
    for (case, return_body) in [
        ("primitive return", "return 0;"),
        ("throwing return", "throw 'close-error';"),
    ] {
        let src = r#"
            let closeCount = 0;
            let step = 0;
            let iterator = {
                next: function () {
                    step = step + 1;
                    return step === 1
                        ? { value: 7, done: false }
                        : { done: true };
                },
                return: function () {
                    closeCount = closeCount + 1;
                    __RETURN_BODY__
                }
            };
            let iterable = { [Symbol.iterator]: function () { return iterator; } };
            const fixed = 1;
            function run() {
                try { for (fixed of iterable) {} }
                catch (error) { return error.name; }
                return "miss";
            }
            run() + ":" + closeCount;
        "#
        .replace("__RETURN_BODY__", return_body);
        assert_eq!(
            completion(&src),
            Value::str("TypeError:1"),
            "{case}: the original loop-head failure must retain precedence"
        );
    }
}
