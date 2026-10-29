//! bd-8enww.3.3 (YTBG-C3): invocation semantics for functions produced by the
//! `Function` constructor.
//!
//! The 3.2 slice parsed and compiled `new Function(args, body)` into a callable
//! artifact but left invocation fail-closed. This slice makes the artifact
//! actually run: the body executes in **global scope** (it cannot capture
//! construction-site or call-site locals — both nonstandard and a containment
//! leak), with positional argument binding, return values, builtin/global calls,
//! and constructor calls with fresh instances, `new.target`, prototype lookup,
//! and the ordinary return-object-or-this rule.
//!
//! Containment note: generated code replaces the caller's capability envelope
//! with the engine-local `VmDispatch`/`HeapAllocate` baseline plus exactly the
//! safe (`Builtin`/`Console`/`Timer`) capabilities validated from its own
//! compiled module and canonical realm builtin references. Bare references to
//! identifiers that are neither a recognized builtin nor present in the live
//! global environment fail closed with a `ReferenceError` rather than silently
//! resolving — the conservative posture for adversary-authored dynamic code.
//!
//! The driving vector is BotGuard's G-2: `var f=new Function("x","return x*2");
//! f(21)` must return `42` through `HybridRouter::eval`.

use frankenengine_engine::{
    HybridRouter, JsEngine, QuickJsInspiredNativeEngine, V8InspiredNativeEngine,
};

/// Evaluate through the direct native engine (isolates engine semantics from
/// HybridRouter routing).
fn eval_value(source: &str) -> String {
    let mut engine = QuickJsInspiredNativeEngine;
    engine
        .eval(source)
        .expect("source should evaluate successfully")
        .value
}

/// Evaluate through the HybridRouter — the path named by the parent-bead AC#1.
fn eval_value_hybrid(source: &str) -> String {
    let mut router = HybridRouter::default();
    router
        .eval(source)
        .expect("source should evaluate successfully")
        .value
}

fn eval_error(source: &str) -> String {
    let mut router = HybridRouter::default();
    router
        .eval(source)
        .expect_err("source should fail deterministically")
        .to_string()
}

/// Constructor semantics must agree in both native lanes and routed execution.
fn assert_constructor_value(source: &str, expected: &str) {
    assert_eq!(eval_value(source), expected, "QuickJS-inspired native lane");
    let mut engine = V8InspiredNativeEngine;
    assert_eq!(
        engine.eval(source).expect("V8-inspired native lane").value,
        expected,
        "V8-inspired native lane"
    );
    assert_eq!(eval_value_hybrid(source), expected, "hybrid router");
}

// --- AC#1: the exact G-2 vector returns 42 -----------------------------------

#[test]
fn exact_g2_vector_returns_42_through_hybrid_router() {
    assert_eq!(
        eval_value_hybrid(r#"var f = new Function("x", "return x * 2;"); f(21);"#),
        "42"
    );
}

#[test]
fn exact_g2_vector_returns_42_through_native_engine() {
    assert_eq!(
        eval_value(r#"var f = new Function("x", "return x * 2;"); f(21);"#),
        "42"
    );
}

// --- AC#3: return values, argument binding, builtin/nested calls, `this` ------

#[test]
fn generated_function_returns_literal_value() {
    assert_eq!(eval_value(r#"new Function("return 7;")();"#), "7");
}

#[test]
fn generated_function_without_return_yields_undefined() {
    assert_eq!(eval_value(r#"new Function("var a = 1;")();"#), "undefined");
}

#[test]
fn generated_function_binds_multiple_arguments_positionally() {
    assert_eq!(
        eval_value(r#"new Function("a", "b", "return a + b;")(2, 3);"#),
        "5"
    );
}

#[test]
fn generated_function_missing_arguments_are_undefined() {
    assert_eq!(
        eval_value(r#"new Function("a", "b", "return typeof b;")(2);"#),
        "undefined"
    );
}

#[test]
fn generated_function_can_call_builtin_globals() {
    // `Math` is a realm builtin reachable from the generated function's
    // global-only scope; the call needs the `Builtin` capability, which the
    // generated module declares and the contained-codegen envelope grants.
    assert_eq!(
        eval_value(r#"new Function("return Math.max(10, 42);")();"#),
        "42"
    );
}

#[test]
fn generated_function_supports_nested_builtin_calls() {
    assert_eq!(
        eval_value(r#"new Function("return Math.max(Math.min(100, 42), 7);")();"#),
        "42"
    );
}

#[test]
fn generated_function_this_obeys_body_strictness_and_contained_realm() {
    // OrdinaryCallBindThis uses the callee's realm for a sloppy null/undefined
    // receiver, and preserves the receiver for a strict body. Generated code
    // has its own sanitized realm; returning its global must not expose the
    // caller's ambient or recursive-codegen bindings.
    for (source, expected) in [
        // Retain the exact formerly failing program. Node and the pre-change
        // engine both return "object"; the old "undefined" assertion was stale.
        (r#"new Function("return typeof this;")();"#, "object"),
        (
            r#"new Function("'use strict'; return typeof this;")();"#,
            "undefined",
        ),
        (
            r#"(function () {'use strict'; return new Function("return typeof this;")();})();"#,
            "object",
        ),
        (
            r#"var F = new Function("return this;");
            [F() === F.call(null), F() === new Function("return this;")(),
             F.call(7).valueOf() === 7, F.call("x").valueOf() === "x"].join(":");"#,
            "true:true:true:true",
        ),
        (
            r#"var F = new Function("'use strict'; return this;");
            [F() === undefined, F.call(null) === null,
             F.call(7) === 7, F.call("x") === "x"].join(":");"#,
            "true:true:true:true",
        ),
        (
            r#"var receiver = {}; var F = new Function("return this;");
            function caller() {return F();}
            [caller.call(receiver) === F(), caller.call(receiver) === receiver,
             F.call(receiver) === receiver].join(":");"#,
            "true:false:true",
        ),
        (
            r#"var realm = new Function("return this;")();
            typeof realm.Function === "undefined" && typeof realm.eval === "undefined" &&
                typeof realm.process === "undefined" && typeof realm.require === "undefined";"#,
            "true",
        ),
        // Planted caller-realm substitution: the same safe-global predicate
        // must reject the caller's real Function binding.
        (
            r#"var realm = globalThis;
            typeof realm.Function === "undefined" && typeof realm.eval === "undefined" &&
                typeof realm.process === "undefined" && typeof realm.require === "undefined";"#,
            "false",
        ),
    ] {
        assert_constructor_value(source, expected);
    }
}

// --- AC#2: global-scope binding (globals visible, locals not) -----------------

#[test]
fn generated_function_cannot_capture_call_site_locals() {
    // The function is invoked deep inside caller() where `callerLocal` is in
    // scope; the global-only collapse means it must still read as undefined.
    // This is the discriminating "cannot capture non-global locals" check:
    // without the global-only scope collapse the call-site `callerLocal` would
    // leak in as "number". (Construction-site locals cannot exist to leak in the
    // first place: `new Function(...)` resolves `Function` only at global scope,
    // so every generated function is necessarily *constructed* in global scope.)
    let src = r#"
        var f = new Function("return typeof callerLocal;");
        function caller() {
            var callerLocal = 5;
            return f();
        }
        caller();
    "#;
    assert_eq!(eval_value(src), "undefined");
}

// --- Containment: bare unbound references fail closed ------------------------

#[test]
fn generated_function_unbound_reference_fails_closed() {
    // A bare reference (not under `typeof`) to an identifier that is neither a
    // recognized builtin nor a live global must not silently resolve; it fails
    // closed rather than reaching into ambient state.
    let _err = eval_error(r#"new Function("return someUndeclaredGlobalXyz + 1;")();"#);
}

// --- Generated-function [[Construct]] ---------------------------------------

#[test]
fn generated_constructor_initializes_fresh_instances_and_new_target() {
    assert_constructor_value(
        r#"
        var F = new Function("x", "this.value = x; this.target = new.target;");
        var first = new F(42);
        var second = new F(7);
        [first.value, second.value, first !== second,
         Object.getPrototypeOf(first) === F.prototype,
         F.prototype.constructor === F, first.target === F,
         first instanceof F].join(":");
    "#,
        "42:7:true:true:true:true:true",
    );
}

#[test]
fn generated_constructor_uses_return_object_or_this_and_retains_returned_closures() {
    assert_constructor_value(
        r#"
        var Primitive = new Function("this.value = 42; return 9;");
        var Empty = new Function("this.value = 7;");
        var ObjectResult = new Function("this.ignored = true; return { value: 19 };");
        var CallableResult = new Function("return function () { return 23; };");
        var explicit = new ObjectResult();
        var callable = new CallableResult();
        [(new Primitive()).value, (new Empty()).value, explicit.value,
         typeof explicit.ignored, callable(),
         explicit instanceof ObjectResult, typeof callable].join(":");
    "#,
        "42:7:19:undefined:23:false:function",
    );
}

#[test]
fn generated_constructor_reflect_construct_preserves_caller_new_target() {
    assert_constructor_value(
        r#"
        function Decoy() {}
        function Custom() {}
        Custom.prototype.marker = 17;
        var F = new Function("x", "this.value = x; this.target = new.target; this.name = new.target.name;");
        var instance = Reflect.construct(F, [42], Custom);
        [instance.value, instance.marker, instance.target === Custom,
         instance.name, Object.getPrototypeOf(instance) === Custom.prototype,
         instance instanceof Custom, instance instanceof F].join(":");
    "#,
        "42:17:true:Custom:true:true:false",
    );
}

#[test]
fn generated_constructor_supports_bound_targets_and_distinct_bound_new_targets() {
    assert_constructor_value(
        r#"
        var F = new Function("a", "b", "this.sum = a + b; this.target = new.target;");
        var ignoredThis = {};
        var Bound = F.bind(ignoredThis, 10);
        var first = new Bound(11);
        function Custom() {}
        var BoundTarget = Custom.bind(null);
        BoundTarget.prototype = { marker: 5 };
        var second = Reflect.construct(Bound, [5], BoundTarget);
        var BareBoundTarget = Custom.bind(null);
        var third = Reflect.construct(F, [2, 3], BareBoundTarget);
        [first.sum, first.target === F, first instanceof F,
         first instanceof Bound, typeof ignoredThis.sum === "undefined",
         second.sum, second.target === BoundTarget,
         Object.getPrototypeOf(second) === BoundTarget.prototype,
         Object.getPrototypeOf(third) === Object.prototype].join(":");
    "#,
        "21:true:true:true:true:15:true:true:true",
    );
}

#[test]
fn generated_constructor_supports_explicit_and_implicit_derived_constructors() {
    assert_constructor_value(
        r#"
        var Parent = new Function("x", "this.value = x; this.target = new.target;");
        class Child extends Parent {
            extra = 2;
            constructor(x) { super(x); this.value += this.extra; }
        }
        class Implicit extends Parent {}
        var child = new Child(40);
        var implicit = new Implicit(9);
        [child.value, child.target === Child, child instanceof Child,
         child instanceof Parent, Object.getPrototypeOf(child) === Child.prototype,
         implicit.value, implicit.target === Implicit].join(":");
    "#,
        "42:true:true:true:true:9:true",
    );
}

#[test]
fn generated_constructor_prototype_descriptors_support_reassignment_and_freeze() {
    assert_constructor_value(
        r#"
        var F = new Function("this.value = 42;");
        var original = F.prototype;
        var descriptor = Object.getOwnPropertyDescriptor(F, "prototype");
        var constructorDescriptor = Object.getOwnPropertyDescriptor(original, "constructor");
        var replacement = { marker: 7 };
        F.prototype = replacement;
        var instance = new F();
        Object.freeze(F);
        F.prototype = { marker: 99 };
        var frozen = Object.getOwnPropertyDescriptor(F, "prototype");
        [descriptor.writable, descriptor.enumerable, descriptor.configurable,
         constructorDescriptor.value === F, constructorDescriptor.writable,
         constructorDescriptor.enumerable, constructorDescriptor.configurable,
         Object.getPrototypeOf(original) === Object.prototype,
         Object.getPrototypeOf(instance) === replacement, instance.marker,
         frozen.writable, F.prototype === replacement,
         F.propertyIsEnumerable("prototype"), delete F.prototype,
         Reflect.defineProperty(F, "prototype", { value: original })].join(":");
    "#,
        "true:false:false:true:true:false:true:true:true:7:false:true:false:false:false",
    );
}

#[test]
fn generated_constructor_prototypes_are_per_artifact_and_instanceof_reads_actual_value() {
    assert_constructor_value(
        r#"
        var F = new Function("");
        var G = new Function("");
        var distinct = F.prototype !== G.prototype;
        F.prototype = 3;
        var instance = new F();
        var error = "";
        try { instance instanceof F; } catch (caught) { error = caught.name; }
        Object.defineProperty(F, Symbol.hasInstance, {
            value: function (candidate) { return candidate.marker === 42; }
        });
        [distinct, Object.getPrototypeOf(instance) === Object.prototype,
         error, { marker: 42 } instanceof F, { marker: 0 } instanceof F].join(":");
    "#,
        "true:true:TypeError:true:false",
    );
}

#[test]
fn generated_constructor_observes_new_target_getter_once_before_running_body() {
    assert_constructor_value(
        r#"
        var log = [];
        var Target = (function Target() {}).bind(null);
        var chosen = {};
        Object.defineProperty(Target, "prototype", {
            get: function () { log.push("prototype"); return chosen; }
        });
        var F = new Function("log", "log.push('body'); this.target = new.target;");
        var instance = Reflect.construct(F, [log], Target);
        var Throwing = (function Throwing() {}).bind(null);
        Object.defineProperty(Throwing, "prototype", {
            get: function () { log.push("throw"); throw "sentinel"; }
        });
        var caught = "";
        try { Reflect.construct(F, [log], Throwing); } catch (error) { caught = error; }
        [log.join(","), caught, Object.getPrototypeOf(instance) === chosen,
         instance.target === Target].join(":");
    "#,
        "prototype,body,throw:sentinel:true:true",
    );
}

#[test]
fn generated_constructor_arguments_callee_keeps_authenticated_artifact_identity() {
    assert_constructor_value(
        r#"
        var F = new Function("n", "this.callee = arguments.callee; this.target = new.target; this.value = n; if (n > 0) this.child = new arguments.callee(n - 1);");
        var first = new F(2);
        var escaped = first.callee;
        var second = new escaped(0);
        [first.callee === F, first.child.callee === F,
         first.child.target === F, first.child.child.value,
         second.callee === F, second instanceof F].join(":");
    "#,
        "true:true:true:0:true:true",
    );
}

#[test]
fn generated_constructor_throw_restores_caller_for_following_construction() {
    assert_constructor_value(
        r#"
        var Throwing = new Function("throw 'ctor-failed';");
        var Following = new Function("this.value = 42;");
        var caught = "";
        try { new Throwing(); } catch (error) { caught = error; }
        caught + ":" + (new Following()).value;
    "#,
        "ctor-failed:42",
    );
}

#[test]
fn generated_constructor_keeps_global_only_scope_and_ambient_authority_restrictions() {
    assert_constructor_value(
        r#"
        var F = new Function("this.observed = typeof callerLocal;");
        function caller() { var callerLocal = 42; return new F(); }
        caller().observed;
        "#,
        "undefined",
    );
    let error = eval_error(r#"var F = new Function("this.leak = process;"); new F();"#);
    assert!(error.contains("ambient authority violation"), "{error}");
}

#[test]
fn generated_constructor_consumes_shared_instruction_budget() {
    let error = HybridRouter::default()
        .eval_with_instruction_budget(
            r#"var F = new Function("while (true) {}"); try { new F(); } catch (_) { 42; }"#,
            2_000,
        )
        .expect_err("constructor loops must exhaust the shared budget")
        .to_string();
    assert!(error.contains("budget exhausted"), "{error}");
}

// --- Determinism: identical source ⇒ identical observable result --------------

#[test]
fn generated_function_invocation_is_deterministic() {
    let src = r#"var f = new Function("x", "return x * 2;"); f(21);"#;
    assert_eq!(eval_value(src), eval_value(src));
}
