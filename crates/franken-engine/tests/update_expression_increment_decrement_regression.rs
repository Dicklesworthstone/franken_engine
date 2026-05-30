//! Regression: `++` / `--` update expressions must write back to their target.
//!
//! Primary bead: bd-um9a3 (parser drops ++/--). Surfaced while investigating
//! bd-bg9l1.27.8 (DISC-010, per-iteration lexical environment for C-style
//! `for (let i ...)` loops).
//!
//! ROOT CAUSE (empirically pinned at HEAD via `HybridRouter::eval`): the parser
//! (`crates/franken-engine/src/parser.rs`) has no handling for the `++` / `--`
//! update operators, and there is no `UpdateExpression` AST node anywhere. So
//! `i++`, `++i`, `i--`, `--i` parse as the bare operand `i` — no parse error,
//! but the increment/decrement side effect is silently dropped. Assignment
//! forms (`i = i + 1`, `i += 1`) work, because they lower through real stores.
//!
//! USER-VISIBLE CONSEQUENCE: every idiomatic C-style loop `for (let i = 0; i < n;
//! i++) { ... }` NEVER TERMINATES — the update is a no-op, the condition stays
//! true, and evaluation dies with "instruction budget exhausted". This is why
//! the iteration-statements conformance cases that use `i++` fail.
//!
//! All tests are `#[ignore]`d until the operators are implemented. Un-ignore
//! them (and flip the corresponding conformance cases to EXPECTED_PASS) when
//! bd-um9a3 lands. The per-iteration-environment case at the bottom is gated
//! behind bd-um9a3 *and* bd-bg9l1.27.8: it can only be observed once `i++`
//! actually advances the loop.

use frankenengine_engine::HybridRouter;

/// Evaluate `source` and return the result value as the engine stringifies it,
/// or `ERR:<message>` if evaluation faults (e.g. the budget-exhaustion that an
/// infinite loop produces).
fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
#[ignore = "bd-um9a3: parser drops postfix ++ (i++ parses as bare i, no write-back)"]
fn postfix_increment_writes_back_to_binding() {
    assert_eq!(eval_value("let i = 0; i++; i;"), "1");
}

#[test]
#[ignore = "bd-um9a3: parser drops prefix ++ (++i parses as bare i, no write-back)"]
fn prefix_increment_writes_back_to_binding() {
    assert_eq!(eval_value("let i = 0; ++i; i;"), "1");
}

#[test]
#[ignore = "bd-um9a3: parser drops postfix -- (i-- parses as bare i, no write-back)"]
fn postfix_decrement_writes_back_to_binding() {
    assert_eq!(eval_value("let i = 3; i--; i;"), "2");
}

/// Postfix `++` evaluates to the OLD value while still writing back the new one.
/// (The old-value half is already correct today because `i++` currently *is*
/// just `i`; this test guards against a fix that returns the new value.)
#[test]
#[ignore = "bd-um9a3: postfix ++ must return the pre-increment value AND write back"]
fn postfix_increment_returns_old_value_and_writes_back() {
    // j captures the pre-increment value (5); i is left at 6.
    assert_eq!(eval_value("let i = 5; let j = i++; j;"), "5");
    assert_eq!(eval_value("let i = 5; let j = i++; i;"), "6");
}

/// The headline consequence: a C-style `for` loop with an `i++` update must
/// terminate. Today this faults with "instruction budget exhausted" because the
/// update never advances `i`.
#[test]
#[ignore = "bd-um9a3: for(;;i++) infinite-loops because ++ never advances i"]
fn c_style_for_loop_with_postfix_increment_terminates() {
    let sum = eval_value("let s = 0; for (let i = 0; i < 3; i++) { s = s + i; } s;");
    assert_eq!(sum, "3", "expected 0+1+2=3; got {sum}");
}

/// Per-iteration lexical environment (bd-bg9l1.27.8 / DISC-010). Gated behind
/// bd-um9a3: only observable once `i++` actually advances the loop. ES2020
/// §13.7.4.7 (CreatePerIterationEnvironment) requires each iteration to get a
/// FRESH binding, so the three closures capture 0, 1, 2 (sum 3). A single shared
/// binding makes them all observe the final `i` (sum 9). Written array-free to
/// isolate per-iteration-env from Array.prototype.push/.length (bd-bg9l1.27.9).
#[test]
#[ignore = "bd-bg9l1.27.8 (blocked by bd-um9a3): C-style for(let) needs per-iteration lexical env"]
fn for_let_closures_capture_distinct_per_iteration_bindings() {
    let total = eval_value(
        r#"
        let a; let b; let c;
        for (let i = 0; i < 3; i++) {
            if (i === 0) { a = () => i; }
            else if (i === 1) { b = () => i; }
            else { c = () => i; }
        }
        a() + b() + c();
        "#,
    );
    assert_eq!(
        total, "3",
        "per-iteration env: expected 0+1+2=3; got {total}"
    );
}
