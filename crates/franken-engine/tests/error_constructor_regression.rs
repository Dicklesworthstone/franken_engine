//! Regression: global error constructors (`Error`, `TypeError`, …) must be
//! usable in the `HybridRouter::eval` path.
//!
//! Bead: bd-bg9l1.27.10. Before the fix, bare `Error` (like `Math`/`Symbol`)
//! resolved to `undefined` on the eval scope path, so `new Error(msg)` and
//! `throw new Error(msg)` faulted with "type error: expected function, got
//! undefined". The constructors are now recognized at lowering and routed to the
//! `builtin:<Name>` hostcall (`error_constructor_capability` in
//! `lowering_pipeline.rs`), producing a real error object with `name` + `message`.
//!
//! The inline `new X(args).prop` form (member/call/index directly on a `new`
//! result) is covered by `inline_member_on_new_result` /
//! `inline_call_and_index_on_new_result` — that was a separate parse-precedence
//! gap fixed under bd-if9uy (`parse_new_expression` re-groups the trailing chain
//! per ES2020 §13.3 `new X(a).b` == `(new X(a)).b`).

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn new_error_constructs_object_with_message() {
    assert_eq!(
        eval_value(r#"let e = new Error("boom"); e.message"#),
        "boom"
    );
    assert_eq!(eval_value(r#"let e = new Error("boom"); e.name"#), "Error");
    assert_eq!(
        eval_value(r#"let e = new Error("boom"); typeof e"#),
        "object"
    );
}

#[test]
fn new_error_with_no_argument_has_empty_message() {
    assert_eq!(eval_value("let e = new Error(); e.message"), "");
    assert_eq!(eval_value("let e = new Error(); e.name"), "Error");
}

#[test]
fn throw_new_error_is_catchable() {
    // The thrown Error is caught and bound; the catch block's value is returned.
    assert_eq!(
        eval_value(r#"try { throw new Error("x"); 1; } catch (e) { 42; }"#),
        "42"
    );
}

#[test]
fn catch_binds_thrown_error_message() {
    assert_eq!(
        eval_value(r#"try { throw new Error("kaboom"); } catch (e) { e.message; }"#),
        "kaboom"
    );
}

#[test]
fn error_subclasses_carry_their_own_name() {
    assert_eq!(
        eval_value(r#"let e = new TypeError("t"); e.name"#),
        "TypeError"
    );
    assert_eq!(
        eval_value(r#"let e = new RangeError("r"); e.name"#),
        "RangeError"
    );
    assert_eq!(
        eval_value(r#"let e = new ReferenceError("ref"); e.name"#),
        "ReferenceError"
    );
    assert_eq!(
        eval_value(r#"let e = new SyntaxError("s"); e.name"#),
        "SyntaxError"
    );
    assert_eq!(eval_value(r#"let e = new TypeError("t"); e.message"#), "t");
}

/// A throwing subclass propagates and is catchable, binding the right name.
#[test]
fn throw_subclass_is_catchable_with_name() {
    assert_eq!(
        eval_value(r#"try { throw new TypeError("bad"); } catch (e) { e.name; }"#),
        "TypeError"
    );
}

/// `new X(args).prop` (a member/call/index chain directly on a `new` result)
/// must parse as `(new X(args)).prop` per ES2020 §13.3 (bd-if9uy). This was
/// previously a parse-precedence gap (the trailing chain was absorbed into the
/// constructor callee, faulting); `parse_new_expression` now re-groups it.
#[test]
fn inline_member_on_new_result() {
    // Builtin constructor + member.
    assert_eq!(eval_value(r#"new Error("boom").message"#), "boom");
    assert_eq!(eval_value(r#"new TypeError("t").name"#), "TypeError");
    // User constructor + member.
    assert_eq!(
        eval_value(r#"let C = function () { this.x = 5; }; new C().x"#),
        "5"
    );
    // No-arg builtin + member.
    assert_eq!(eval_value(r#"new Error().name"#), "Error");
    // Parenthesised form stays correct (regression guard for the regrouping).
    assert_eq!(eval_value(r#"(new Error("boom")).message"#), "boom");
}

/// Trailing call and index chains on a `new` result also bind to the
/// constructed object (`new X(a).m()`, `new X(a)[k]`).
#[test]
fn inline_call_and_index_on_new_result() {
    // Member-then-call on the constructed object.
    assert_eq!(
        eval_value(r#"let C = function () { this.go = function () { return 9; }; }; new C().go()"#),
        "9"
    );
    // Index access on the constructed object.
    assert_eq!(
        eval_value(r#"let C = function () { this[0] = 7; }; new C()[0]"#),
        "7"
    );
}

/// bd-8enww.4.5 (YTBG-D5) AC3: string coercion of error objects is
/// deterministic and follows Error.prototype.toString — `"<name>: <message>"`,
/// or just the name when the message is empty. Covers concatenation (both
/// operand orders) and template literals.
#[test]
fn error_object_string_coercion_is_deterministic() {
    // Concatenation, both directions.
    assert_eq!(eval_value(r#""" + new Error("boom")"#), "Error: boom");
    assert_eq!(eval_value(r#"new Error("boom") + """#), "Error: boom");
    // Template literal.
    assert_eq!(eval_value(r#"`${new Error("boom")}`"#), "Error: boom");
    // Subclasses carry their own name.
    assert_eq!(
        eval_value(r#"`${new TypeError("bad type")}`"#),
        "TypeError: bad type"
    );
    assert_eq!(
        eval_value(r#""" + new RangeError("out")"#),
        "RangeError: out"
    );
    assert_eq!(
        eval_value(r#"`${new ReferenceError("nope")}`"#),
        "ReferenceError: nope"
    );
    // No message -> just the name (ES2020 §20.5.3.4).
    assert_eq!(eval_value(r#""" + new Error()"#), "Error");
    // Deterministic: identical inputs -> identical output.
    assert_eq!(
        eval_value(r#"`${new TypeError("x")}`"#),
        eval_value(r#"`${new TypeError("x")}`"#)
    );
}

/// A native runtime error, once caught as a JS value, coerces to a string that
/// begins with its error name (`indexOf` avoids pinning the engine's exact
/// diagnostic message text).
#[test]
fn caught_native_error_string_coercion_carries_name() {
    assert_eq!(
        eval_value(
            r#"let r = -1; try { let o = null; o.p; } catch (e) { r = ("" + e).indexOf("TypeError"); } r"#
        ),
        "0"
    );
}

/// Like V8, `stack` begins with the `Name: message` summary, then one
/// `    at ...` line per frame, so `console.error(err.stack)` shows what went
/// wrong. The summary line was missing: `stack` held only the frame lines.
/// Expected values are what Node v22.2.0 prints.
#[test]
fn stack_starts_with_name_and_message() {
    assert_eq!(
        eval_value(
            r#"var e = new TypeError("bad input"); var f = new Error(); var g = new RangeError("");
               [e.stack.split("\n")[0], f.stack.split("\n")[0], g.stack.split("\n")[0],
                e.stack.split("\n").length > 1].join("|")"#
        ),
        "TypeError: bad input|Error|RangeError|true"
    );
    assert_eq!(
        eval_value(
            r#"function thrower() { throw new Error("deep"); } var s;
               try { thrower(); } catch (x) { s = x.stack; }
               [s.split("\n")[0], /^    at /.test(s.split("\n")[1])].join("|")"#
        ),
        "Error: deep|true"
    );
    // Native faults caught as JS errors carry the summary too.
    assert_eq!(
        eval_value(
            r#"var s; try { null.x; } catch (x) { s = x.stack; } s.split("\n")[0].indexOf("TypeError: ")"#
        ),
        "0"
    );
}

/// ES2020 19.5: `name` and `message` live on the error prototypes, and an
/// instance owns only a non-enumerable `message` (when one was passed) and
/// `stack`. Instances used to own enumerable `name`/`message`/`stack`:
/// - `JSON.stringify(err)` printed all three;
/// - `Error.prototype.name` was undefined;
/// - a subclass's `MyErr.prototype.name` was shadowed, so errors printed
///   as `Error`.
/// Expected values are what Node v22.2.0 prints.
#[test]
fn error_name_and_message_are_inherited_and_not_enumerable() {
    assert_eq!(
        eval_value(
            r#"var e = new Error("m"); var keys = []; for (var k in e) keys.push(k);
               [JSON.stringify(e), Object.keys(new TypeError("x")).length, e.hasOwnProperty("name"),
                e.hasOwnProperty("message"), new Error().hasOwnProperty("message"),
                JSON.stringify(new Error(undefined).message), keys.length].join("|")"#
        ),
        r#"{}|0|false|true|false|""|0"#
    );
    assert_eq!(
        eval_value(
            r#"[TypeError.prototype.name, JSON.stringify(Error.prototype.message),
                RangeError.prototype.hasOwnProperty("name"),
                Error.prototype.propertyIsEnumerable("name")].join("|")"#
        ),
        r#"TypeError|""|true|false"#
    );
    assert_eq!(
        eval_value(
            r#"function MyErr(m) { this.message = m; }
               MyErr.prototype = Object.create(Error.prototype); MyErr.prototype.name = "MyErr";
               class E2 extends Error {} E2.prototype.name = "E2";
               var a = new MyErr("x"), b = new E2("y");
               [a.name, String(a), a instanceof Error, b.name, String(b), b.message,
                Object.keys(b).length].join("|")"#
        ),
        "MyErr|MyErr: x|true|E2|E2: y|y|0"
    );
    assert_eq!(
        eval_value(
            r#"var r; try { null.x; } catch (c) {
                 r = [c.name, c instanceof TypeError, Object.keys(c).length,
                      c.hasOwnProperty("name")].join("|"); } r"#
        ),
        "TypeError|true|0|false"
    );
}

/// ES2022 InstallErrorCause: `new Error(message, { cause })` (also the call
/// form, the other error constructors and a subclass's `super(m, options)`)
/// installs an own non-enumerable `cause`, including an inherited one; an
/// options object without `cause` installs none. Expected string is Node
/// v22.2.0's output.
#[test]
fn error_options_cause_is_installed() {
    assert_eq!(
        eval_value(
            r#"const e2 = new Error('a', { cause: 1 });
const inner = new Error('inner'); const e5 = new Error('outer', { cause: inner });
class E extends Error { constructor(m, o) { super(m, o); } }
const e7 = new E('m', { cause: 3 });
const d = Object.getOwnPropertyDescriptor(e2, 'cause');
[e2.cause, d.enumerable, d.writable, d.configurable, e5.cause === inner, e5.cause.message, new TypeError('x', { cause: 'why' }).cause, Error('a', { cause: 2 }).cause, e7.cause, 'cause' in new Error('a', {}), 'cause' in new Error('a', Object.create({ cause: 'inh' })), JSON.stringify(e2), Object.keys(e2).length].join(' ')"#
        ),
        "1 false true true true inner why 2 3 false true {} 0"
    );
}
