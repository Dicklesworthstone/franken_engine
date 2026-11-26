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
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3FunctionDesc, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

fn lower_error_source(source: &str) -> Ir3Module {
    let tree = parse_script(source).expect("error constructor regression parses");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "error-constructor-regression.js"),
        &LoweringContext::new("error-constructor", "cause", "builtin-only"),
    )
    .expect("error constructor regression lowers")
    .ir3
}

fn error_cores() -> impl Iterator<Item = InterpreterCore> {
    [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ]
    .into_iter()
    .map(|mut config| {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "error-constructor-regression")
    })
}

fn assert_native_error_output(source: &str, expected: &[&str]) {
    let module = lower_error_source(source);
    for stress in [None, Some(1)] {
        for mut core in error_cores() {
            core.set_gc_stress_interval(stress);
            let result = core
                .execute(&module)
                .expect("native error regression executes");
            let actual: Vec<&str> = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect();
            assert_eq!(actual, expected, "GC stress: {stress:?}");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "GC stress: {stress:?}"
            );
        }
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
///
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

#[test]
fn error_cause_getters_keep_receiver_order_and_undefined_presence() {
    assert_native_error_output(
        r#"
        const calls = [];
        const inherited = Object.create({
            get cause() { calls.push('cause:' + (this === inherited)); return undefined; }
        });
        const error = new Error({ toString() { calls.push('message'); return 'outer'; } }, inherited);
        const descriptor = Object.getOwnPropertyDescriptor(error, 'cause');
        console.log(calls.join('|'), error.message, error.hasOwnProperty('cause'),
            descriptor.value === undefined, descriptor.writable, descriptor.enumerable,
            descriptor.configurable);
        let reads = 0;
        const options = { get cause() { reads++; return this; } };
        const own = Error('own', options);
        console.log(own.cause === options, reads, new Error('absent', {}).hasOwnProperty('cause'));
        "#,
        &[
            "message|cause:true outer true true true false true",
            "true 1 false",
        ],
    );
}

#[test]
fn error_cause_proxy_has_precedes_get_and_can_change_the_property() {
    assert_native_error_output(
        r#"
        const calls = [];
        const target = { cause: 'before' };
        const options = new Proxy(target, {
            has(t, key) { calls.push('has:' + key); t.cause = 'after'; return true; },
            get(t, key, receiver) {
                calls.push('get:' + key + ':' + (receiver === options));
                return Reflect.get(t, key, receiver);
            }
        });
        console.log(new Error('proxy', options).cause, calls.join('|'));
        const absent = new Proxy({ cause: 1 }, {
            has(t, key) { calls.push('absent:' + key); return false; },
            get() { throw 'Get must not run after false HasProperty'; }
        });
        console.log(new Error('absent', absent).hasOwnProperty('cause'), calls[2]);
        let callable;
        callable = new Proxy(function () {}, {
            has(t, key) { calls.push('function-has:' + key); return true; },
            get(t, key, receiver) {
                calls.push('function-get:' + key + ':' + (receiver === callable));
                return 42;
            }
        });
        console.log(Error('callable', callable).cause, calls.slice(3).join('|'));
        function localSurvivor() {
            const survivor = { value: 17 };
            const trace = [];
            const options = new Proxy({}, {
                has() {
                    trace.push('has');
                    for (let i = 0; i < 32; i++) {
                        const garbage = { value: i };
                        if (garbage.value < 0) throw 'unreachable';
                    }
                    return true;
                },
                get() {
                    trace.push('get');
                    for (let i = 0; i < 32; i++) {
                        const garbage = { value: i };
                        if (garbage.value < 0) throw 'unreachable';
                    }
                    return { value: 23 };
                }
            });
            const error = new Error('outer', options);
            return [survivor.value, error.message, error.cause.value, trace.join('|')].join(' ');
        }
        console.log(localSurvivor());
        "#,
        &[
            "after has:cause|get:cause:true",
            "false absent:cause",
            "42 function-has:cause|function-get:cause:true",
            "17 outer 23 has|get",
        ],
    );
}

#[test]
fn error_cause_accepts_callable_promise_generator_and_iterator_options() {
    assert_native_error_output(
        r#"
        const token = {};
        const options = [function () {}, () => 0, async function () {}, function* () {},
            async function* () {}, Promise.resolve(0), (function* () {})(),
            (async function* () {})(), [1].values()];
        let reads = 0;
        const results = [];
        for (let i = 0; i < options.length; i++) {
            const option = options[i];
            Object.defineProperty(option, 'cause', {
                get() { reads++; if (this !== option) throw 'wrong receiver'; return token; }
            });
            results.push(new Error('carrier', option).cause === token);
        }
        console.log(results.join(','), reads);
        function inherited() {}
        Object.setPrototypeOf(inherited, { get cause() { return this; } });
        console.log(new Error('inherited', inherited).cause === inherited);
        "#,
        &["true,true,true,true,true,true,true,true,true 9", "true"],
    );
}

#[test]
fn all_native_errors_and_subclasses_observe_cause_getters() {
    assert_native_error_output(
        r#"
        const constructors = [Error, TypeError, RangeError, ReferenceError, SyntaxError, EvalError, URIError];
        const token = {};
        let reads = 0;
        const options = { get cause() { reads++; return token; } };
        const results = [];
        for (let i = 0; i < constructors.length; i++) {
            const Constructor = constructors[i];
            results.push(Constructor('call', options).cause === token);
            results.push(new Constructor('new', options).cause === token);
        }
        class Derived extends TypeError { constructor(message, option) { super(message, option); } }
        const derived = new Derived('derived', options);
        console.log(results.join(','), reads, derived.cause === token, derived instanceof Derived);
        const calls = [];
        const errors = { [Symbol.iterator]() {
            calls.push('iterator');
            return { next() { calls.push('next'); return { done: true }; } };
        } };
        const aggregate = new AggregateError(errors,
            { toString() { calls.push('message'); return 'aggregate'; } },
            { get cause() { calls.push('cause'); return token; } });
        class DerivedAggregate extends AggregateError {}
        const derivedAggregate = new DerivedAggregate([], 'derived aggregate', options);
        console.log(calls.join('|'), aggregate.cause === token, aggregate.errors.length,
            derivedAggregate.cause === token, derivedAggregate instanceof DerivedAggregate);
        "#,
        &[
            "true,true,true,true,true,true,true,true,true,true,true,true,true,true 15 true true",
            "message|cause|iterator|next true 0 true true",
        ],
    );
}

#[test]
fn error_cause_preserves_abrupt_completion_and_skips_later_steps() {
    assert_native_error_output(
        r#"
        const token = {};
        const options = [
            { get cause() { throw token; } },
            new Proxy({}, { has() { throw token; }, get() { throw 'unexpected get'; } }),
            new Proxy({}, { has() { return true; }, get() { throw token; } })
        ];
        const caught = [];
        for (let i = 0; i < options.length; i++) {
            try { new Error('failure', options[i]); caught.push(false); }
            catch (error) { caught.push(error === token); }
        }
        console.log(caught.join(','));
        const revoked = Proxy.revocable({}, {});
        revoked.revoke();
        try { new Error('revoked', revoked.proxy); }
        catch (error) { console.log(error instanceof TypeError); }
        const fixed = Object.defineProperty({}, 'cause', { value: 1, configurable: false });
        try { new Error('invariant', new Proxy(fixed, { has() { return false; } })); }
        catch (error) { console.log(error instanceof TypeError); }
        let iterated = false;
        const errors = { [Symbol.iterator]() { iterated = true; throw 'late iterator'; } };
        try { new AggregateError(errors, 'aggregate', options[0]); }
        catch (error) { console.log(error === token, iterated); }
        let causeRead = false;
        try {
            new Error({ toString() { throw token; } }, { get cause() { causeRead = true; } });
        } catch (error) { console.log(error === token, causeRead); }
        console.log(new Error('after', { get cause() { return 42; } }).cause);
        "#,
        &[
            "true,true,true",
            "true",
            "true",
            "true false",
            "true false",
            "42",
        ],
    );
}

#[test]
fn error_cause_ignores_primitive_options_without_boxing() {
    assert_native_error_output(
        r#"
        let reads = 0;
        Object.defineProperty(Object.prototype, 'cause', {
            get() { reads++; throw 'primitive options must not be boxed'; }, configurable: true
        });
        const options = [undefined, null, true, 1, 'text', Symbol('key'), 1n];
        const present = [];
        for (let i = 0; i < options.length; i++) {
            present.push(new Error('primitive', options[i]).hasOwnProperty('cause'));
        }
        console.log(present.join(','), reads);
        "#,
        &["false,false,false,false,false,false,false 0"],
    );
}

#[test]
fn error_cause_preserves_stored_property_labels_through_public_options_aliases() {
    for inherited in [false, true] {
        for mut core in error_cores() {
            let holder = core.alloc_object_with_prototype(None).unwrap();
            let options = if inherited {
                core.alloc_object_with_prototype(Some(holder)).unwrap()
            } else {
                holder
            };
            for (register, value) in [
                (0, Value::str("outer")),
                (1, Value::Object(options)),
                (5, Value::str("cause")),
                (6, Value::Int(42)),
                (7, Value::Object(options)),
                (8, Value::Object(holder)),
            ] {
                core.seed_register(register, value).unwrap();
            }
            core.set_register_label(6, Label::Secret).unwrap();
            let mut module = lower_error_source("0;");
            module.instructions = vec![
                Ir3Instruction::SetProperty {
                    obj: 8,
                    key: 5,
                    val: 6,
                },
                Ir3Instruction::Move { dst: 1, src: 7 },
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:Error".into()),
                    args: RegRange { start: 0, count: 2 },
                    dst: 3,
                },
                Ir3Instruction::GetProperty {
                    obj: 3,
                    key: 5,
                    dst: 4,
                },
                Ir3Instruction::Return { value: 4 },
            ];
            let result = core.execute(&module).expect("labeled error cause executes");
            assert_eq!(result.value, Value::Int(42));
            assert_eq!(result.completion_label, Label::Secret);
            assert_eq!(core.get_register_label(1).unwrap(), &Label::Public);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn error_cause_observes_inherited_callable_and_generator_labels_without_own_storage() {
    for generator in [false, true] {
        for source in ["data", "getter", "absent shape"] {
            for mut core in error_cores() {
                let property = if source == "absent shape" {
                    "unrelated"
                } else {
                    "cause"
                };
                let stored = if source == "getter" {
                    Value::Accessor {
                        get: Some(std::sync::Arc::new(Value::Function(1))),
                        set: None,
                    }
                } else {
                    Value::Int(42)
                };
                for (register, value) in [
                    (0, Value::str("outer")),
                    (1, Value::Function(0)),
                    (5, Value::str(property)),
                    (6, stored),
                    (9, Value::str("cause")),
                ] {
                    core.seed_register(register, value).unwrap();
                }
                core.set_register_label(
                    if source == "absent shape" { 5 } else { 6 },
                    Label::Secret,
                )
                .unwrap();
                let mut module = lower_error_source("0;");
                module.instructions = if generator {
                    vec![
                        Ir3Instruction::CreateGenerator {
                            dst: 10,
                            function_index: 0,
                            capture_count: 0,
                        },
                        Ir3Instruction::Call {
                            callee: 10,
                            args: RegRange {
                                start: 11,
                                count: 0,
                            },
                            dst: 1,
                        },
                    ]
                } else {
                    Vec::new()
                };
                module.instructions.extend([
                    Ir3Instruction::HostCall {
                        capability: CapabilityTag("builtin:ObjectGetPrototypeOf".into()),
                        args: RegRange { start: 1, count: 1 },
                        dst: 8,
                    },
                    Ir3Instruction::Move { dst: 7, src: 1 },
                    Ir3Instruction::SetProperty {
                        obj: 8,
                        key: 5,
                        val: 6,
                    },
                    Ir3Instruction::HostCall {
                        capability: CapabilityTag("builtin:Error".into()),
                        args: RegRange { start: 0, count: 2 },
                        dst: 3,
                    },
                    Ir3Instruction::GetProperty {
                        obj: 3,
                        key: 9,
                        dst: 4,
                    },
                    Ir3Instruction::Return { value: 4 },
                ]);
                let entry = module.instructions.len() as u32;
                module.instructions.extend([
                    Ir3Instruction::LoadUndefined { dst: 0 },
                    Ir3Instruction::Return { value: 0 },
                    Ir3Instruction::LoadInt { dst: 0, value: 42 },
                    Ir3Instruction::Return { value: 0 },
                ]);
                module.function_table = vec![
                    Ir3FunctionDesc {
                        entry,
                        arity: 0,
                        frame_size: 1,
                        name: Some("options".into()),
                        is_generator: generator,
                        rest_param_index: None,
                    },
                    Ir3FunctionDesc {
                        entry: entry + 2,
                        arity: 0,
                        frame_size: 1,
                        name: Some("cause_getter".into()),
                        is_generator: false,
                        rest_param_index: None,
                    },
                ];
                let result = core
                    .execute(&module)
                    .expect("inherited carrier cause executes");
                let expected = if source == "absent shape" {
                    Value::Undefined
                } else {
                    Value::Int(42)
                };
                assert_eq!(
                    result.value, expected,
                    "generator={generator}, source={source}"
                );
                assert_eq!(
                    result.completion_label,
                    Label::Secret,
                    "generator={generator}, source={source}"
                );
                assert_eq!(core.get_register_label(7).unwrap(), &Label::Public);
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes()
                );
            }
        }
    }
}

#[test]
fn error_cause_observes_proxy_prototype_shape_when_has_hides_the_property() {
    for mut core in error_cores() {
        let target = core.alloc_object_with_prototype(None).unwrap();
        let handler = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(handler, "has".into(), Value::Function(1))
            .unwrap();
        for (register, value) in [
            (0, Value::str("outer")),
            (5, Value::str("cause")),
            (6, Value::Int(42)),
            (11, Value::str("prototype")),
            (14, Value::Object(target)),
            (15, Value::Object(handler)),
        ] {
            core.seed_register(register, value).unwrap();
        }
        core.set_register_label(5, Label::Secret).unwrap();
        let mut module = lower_error_source("0;");
        module.instructions = vec![
            Ir3Instruction::CreateGenerator {
                dst: 10,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:Proxy".into()),
                args: RegRange {
                    start: 14,
                    count: 2,
                },
                dst: 16,
            },
            Ir3Instruction::SetProperty {
                obj: 10,
                key: 11,
                val: 16,
            },
            Ir3Instruction::Call {
                callee: 10,
                args: RegRange {
                    start: 17,
                    count: 0,
                },
                dst: 1,
            },
            Ir3Instruction::Move { dst: 7, src: 1 },
            Ir3Instruction::SetProperty {
                obj: 14,
                key: 5,
                val: 6,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:Error".into()),
                args: RegRange { start: 0, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::LoadBool {
                dst: 0,
                value: false,
            },
            Ir3Instruction::Return { value: 0 },
        ];
        module.function_table = vec![
            Ir3FunctionDesc {
                entry: 8,
                arity: 0,
                frame_size: 1,
                name: Some("options".into()),
                is_generator: true,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 10,
                arity: 2,
                frame_size: 2,
                name: Some("hide_cause".into()),
                is_generator: false,
                rest_param_index: None,
            },
        ];
        let result = core
            .execute(&module)
            .expect("Proxy prototype cause executes");
        assert!(matches!(result.value, Value::Object(_)));
        assert_eq!(result.completion_label, Label::Secret);
        assert_eq!(core.get_register_label(7).unwrap(), &Label::Public);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

/// V8's Error.captureStackTrace, which npm error classes call unguarded
/// (`Error.captureStackTrace(this, MyError)`): it was undefined, so those
/// constructors threw "expected function, got undefined". The first stack
/// line is Error.prototype.toString of the target; the property is not
/// enumerable; a non-object target is a TypeError. Node v22.2.0's value.
#[test]
fn error_capture_stack_trace() {
    assert_eq!(
        eval_value(
            r#"class MyError extends Error { constructor(m) { super(m); this.name = 'MyError'; Error.captureStackTrace(this, MyError); } }
const e = new MyError('x');
const o = {}; Error.captureStackTrace(o);
const p = { message: 'hi', name: 'Custom' }; Error.captureStackTrace(p);
function F(msg) { this.message = msg; Error.captureStackTrace(this, F); }
F.prototype = Object.create(Error.prototype); F.prototype.name = 'F'; F.prototype.constructor = F;
const f = new F('m');
let threw; try { Error.captureStackTrace(1); threw = 'no'; } catch (err) { threw = err.constructor.name; }
[e.stack.split('\n')[0], e instanceof MyError, o.stack.split('\n')[0], Object.keys(o).length, p.stack.split('\n')[0], f.stack.split('\n')[0], f instanceof Error, threw, typeof Error.captureStackTrace, Error.captureStackTrace.length, Error.stackTraceLimit].join(' | ')"#
        ),
        "MyError: x | true | Error | 0 | Custom: hi | F: m | true | TypeError | function | 2 | 10"
    );
}

#[test]
fn error_to_string_observes_name_conversion_before_message_for_all_carriers() {
    assert_native_error_output(
        r#"
        const carriers = [
            {},
            function ordinary() {},
            (function bound() {}).bind(null),
            Promise.resolve(0),
            (function* () { yield 1; })(),
            (async function* () { yield 1; })(),
            [1][Symbol.iterator](),
            "x"[Symbol.iterator](),
            new Proxy(function callable() {}, {})
        ];
        for (const receiver of carriers) {
            const trace = [];
            const name = {
                [Symbol.toPrimitive](hint) {
                    trace.push("name:" + (this === name) + ":" + hint);
                    const message = {
                        toString() {
                            trace.push("message:" + (this === message));
                            return "changed";
                        }
                    };
                    Object.defineProperty(receiver, "message", {
                        configurable: true,
                        get() {
                            trace.push("get:message:" + (this === receiver));
                            return message;
                        }
                    });
                    return "Custom";
                }
            };
            Object.defineProperty(receiver, "name", {
                configurable: true,
                get() {
                    trace.push("get:name:" + (this === receiver));
                    return name;
                }
            });
            Object.defineProperty(receiver, "message", {
                configurable: true,
                get() { throw "message read before name conversion"; }
            });
            console.log(Error.prototype.toString.call(receiver) + "|" + trace.join(","));
        }
        "#,
        &["Custom: changed|get:name:true,name:true:string,get:message:true,message:true"; 9],
    );
}

#[test]
fn error_to_string_preserves_abrupt_getters_and_conversions() {
    assert_native_error_output(
        r#"
        function check(stage) {
            const trace = [];
            const token = {};
            const receiver = {
                get name() {
                    trace.push("name");
                    if (stage === "name-getter") throw token;
                    if (stage === "symbol-name") return Symbol("name");
                    return {
                        [Symbol.toPrimitive](hint) {
                            trace.push("name:" + hint);
                            if (stage === "name-conversion") throw token;
                            return "";
                        }
                    };
                },
                get message() {
                    trace.push("message");
                    if (stage === "message-getter") throw token;
                    if (stage === "symbol-message") return Symbol("message");
                    return {
                        [Symbol.toPrimitive](hint) {
                            trace.push("message:" + hint);
                            throw token;
                        }
                    };
                }
            };
            try {
                Error.prototype.toString.call(receiver);
                console.log("did not throw");
            } catch (error) {
                console.log(trace.join(",") + "|" + (error === token ? "token" : error.name));
            }
        }
        for (const stage of [
            "name-getter", "name-conversion", "symbol-name",
            "message-getter", "message-conversion", "symbol-message"
        ]) check(stage);
        "#,
        &[
            "name|token",
            "name,name:string|token",
            "name|TypeError",
            "name,name:string,message|token",
            "name,name:string,message,message:string|token",
            "name,name:string,message|TypeError",
        ],
    );
}

#[test]
fn error_to_string_preserves_exact_utf16_and_default_branches() {
    assert_native_error_output(
        r#"
        const stringify = Error.prototype.toString;
        const high = "\ud800";
        const low = "\udc00";
        const joined = stringify.call({ name: high, message: low });
        console.log(joined.length + "|" + joined.charCodeAt(0) + "|" + joined.charCodeAt(3));
        console.log([
            joined === high + ": " + low,
            stringify.call({ name: "", message: high }) === high,
            stringify.call({ name: low, message: "" }) === low,
            stringify.call({ message: high }) === "Error: " + high,
            stringify.call({ name: high }) === high,
            stringify.call({}) === "Error",
            stringify.call({ name: "", message: "" }) === "",
            stringify.call({ name: null, message: 0 }) === "null: 0",
            stringify.call({
                name: { toString() { return high; } },
                message: { [Symbol.toPrimitive]() { return low; } }
            }) === high + ": " + low
        ].join("|"));
        "#,
        &[
            "4|55296|56320",
            "true|true|true|true|true|true|true|true|true",
        ],
    );
}

#[test]
fn error_to_string_accepts_unmaterialized_objects_but_rejects_primitives() {
    assert_native_error_output(
        r#"
        const stringify = Error.prototype.toString;
        function named() {}
        console.log([
            stringify.call(named),
            stringify.call(Math.max),
            stringify.call(Promise.resolve()),
            stringify.call((function* () {})()),
            stringify.call((async function* () {})()),
            stringify.call([][Symbol.iterator]()),
            stringify.call(Object.create(null)),
            stringify.call(Object(1))
        ].join("|"));
        const errors = [];
        for (const value of [undefined, null, true, 1, NaN, "text", 1n, Symbol("x")]) {
            try {
                stringify.call(value);
                errors.push("accepted");
            } catch (error) {
                errors.push(error.name);
            }
        }
        console.log(errors.join("|"));
        "#,
        &[
            "named|max|Error|Error|Error|Error|Error|Error",
            "TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError",
        ],
    );
}

#[test]
fn error_to_string_retains_property_labels_through_public_receiver_aliases() {
    use frankenengine_engine::baseline_interpreter::{BuiltinFunction, BuiltinFunctionKind};

    for inherited in [false, true] {
        for property in ["name", "message"] {
            for stress in [None, Some(1)] {
                for mut core in error_cores() {
                    core.set_gc_stress_interval(stress);
                    let holder = core.alloc_object_with_prototype(None).unwrap();
                    core.set_object_property(holder, "name".into(), Value::str("Visible"))
                        .unwrap();
                    core.set_object_property(holder, "message".into(), Value::str("text"))
                        .unwrap();
                    let receiver = if inherited {
                        core.alloc_object_with_prototype(Some(holder)).unwrap()
                    } else {
                        holder
                    };
                    let stringify = Value::BuiltinFunction(BuiltinFunction {
                        kind: BuiltinFunctionKind::ErrorPrototypeToString,
                        module_specifier: Default::default(),
                        iterator_handle: None,
                        bound_object: None,
                    });
                    for (register, value) in [
                        (0, Value::Object(receiver)),
                        (1, Value::Object(holder)),
                        (2, Value::str(property)),
                        (3, Value::str("Classified")),
                        (4, Value::Object(receiver)),
                        (5, stringify),
                    ] {
                        core.seed_register(register, value).unwrap();
                    }
                    core.set_register_label(3, Label::Secret).unwrap();
                    let mut module = lower_error_source("0;");
                    module.instructions = vec![
                        Ir3Instruction::SetProperty {
                            obj: 1,
                            key: 2,
                            val: 3,
                        },
                        Ir3Instruction::Move { dst: 0, src: 4 },
                        Ir3Instruction::CallMethod {
                            receiver: 0,
                            callee: 5,
                            args: RegRange { start: 6, count: 0 },
                            dst: 7,
                        },
                        Ir3Instruction::Return { value: 7 },
                    ];
                    let result = core
                        .execute(&module)
                        .expect("labeled error string executes");
                    let expected = if property == "name" {
                        "Classified: text"
                    } else {
                        "Visible: Classified"
                    };
                    assert_eq!(result.value, Value::str(expected));
                    assert_eq!(
                        result.completion_label,
                        Label::Secret,
                        "inherited={inherited}, property={property}, GC stress={stress:?}"
                    );
                    assert_eq!(core.get_register_label(0).unwrap(), &Label::Public);
                    assert_eq!(
                        core.estimated_memory_bytes(),
                        core.recompute_estimated_memory_bytes(),
                        "inherited={inherited}, property={property}, GC stress={stress:?}"
                    );
                }
            }
        }
    }
}
