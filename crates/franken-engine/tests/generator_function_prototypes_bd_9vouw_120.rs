//! bd-9vouw.120: every generator and async generator function has its own
//! `prototype` object, and its generators inherit from it.
//!
//! All generator functions shared one `prototype`, %GeneratorPrototype%
//! itself (inherited from %GeneratorFunction.prototype%), so a member added
//! to one function's `g.prototype` reached every generator and `g() instanceof
//! h` was true for any two generator functions. Now `g.prototype` is the
//! function's own object (created on first use, inheriting
//! %GeneratorPrototype% / %AsyncGeneratorPrototype%, no `constructor`;
//! ES2020 14.4.11), an assignment replaces it, and a generator records the
//! object its function's `prototype` held at the call (a non-object gives the
//! intrinsic; ES2020 14.4.10 OrdinaryCreateFromConstructor), which
//! Object.getPrototypeOf, [[Get]], `in`, for-in and instanceof read.
//! Expected strings are Node v22.2.0's output for the same programs.
//!
//! No-claim: a generator's own `next`, `return` and `throw` (and @@iterator)
//! are still the built-ins whatever its prototype says, so an override on
//! g.prototype or a prototype without them is not observed by calls;
//! Object.setPrototypeOf on a generator object is not covered.

#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// `source`'s completion value with a collection at every safe point, and
/// the memory-accounting invariant checked after the run.
fn eval_under_gc_stress(source: &str) -> String {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "generator_prototypes.js".into(),
                text: source.into(),
                goal: ParseGoal::Script,
            },
            &ParserOptions::default(),
        )
        .expect("source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "generator_prototypes.js"),
        &LoweringContext::new("gp-trace", "gp-decision", "gp-policy"),
    )
    .expect("source lowers")
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "generator-prototypes");
    core.set_gc_stress_interval(Some(1));
    let result = core.execute(&module).expect("source runs");
    assert!(
        core.gc_stats().collections > 0,
        "the stress interval collects"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    match result.value {
        Value::Str(text) => text.to_string(),
        other => format!("{other:?}"),
    }
}

/// Each generator function has its own `prototype`, inheriting %GeneratorPrototype% with no own properties; its generators inherit from it.
#[test]
fn generator_prototypes_own_prototype_per_function() {
    let source = "function* g() {} function* h() {}\n\
         var GP = Object.getPrototypeOf(function* () {}).prototype;\n\
         [g.prototype === h.prototype, g.prototype === GP, Object.getPrototypeOf(g.prototype) === GP,\n\
          Object.getPrototypeOf(g()) === g.prototype, Reflect.getPrototypeOf(h()) === h.prototype, Object.getOwnPropertyNames(g.prototype).length,\n\
          g.prototype.hasOwnProperty('constructor'), g.prototype === g.prototype, g() instanceof g, g() instanceof h, h() instanceof h].join(' ');";
    assert_eq!(
        eval(source),
        "false false true true true 0 false true true false true"
    );
}

/// Members a program adds to g.prototype reach g's generators only, through [[Get]], `in` and for-in.
#[test]
fn generator_prototypes_inherited_members() {
    let source = "function* g() { yield 1; yield 2; } function* h() {}\n\
         g.prototype.tag = 'g-tag'; g.prototype.sum = function () { var s = 0; for (var v of this) s += v; return s; };\n\
         var it = g(); var keys = []; for (var k in g()) keys.push(k);\n\
         [it.tag, 'tag' in it, h().tag, 'tag' in h(), it.sum(), keys.join('+'), it.hasOwnProperty('tag'), typeof it.next].join(' ');";
    assert_eq!(eval(source), "g-tag true  false 3 tag+sum false function");
}

/// An assigned `prototype` is what later calls inherit from; a non-object value falls back to %GeneratorPrototype%.
#[test]
fn generator_prototypes_assigned_prototype() {
    let source = "function* k() { yield 1; }\n\
         var before = k();\n\
         var P = Object.create(Object.getPrototypeOf(k.prototype)); P.extra = 'x';\n\
         k.prototype = P; var after = k();\n\
         function* n() { yield 2; } n.prototype = 7; var plain = n();\n\
         [Object.getPrototypeOf(after) === P, after.extra, before.extra, after.next().value, [...k()].join(), k.prototype === P,\n\
          Object.getPrototypeOf(plain) === Object.getPrototypeOf(function* () {}).prototype, plain.next().value].join(' ');";
    assert_eq!(eval(source), "true x  1 1 true true 2");
}

/// Async generator functions and generator methods get their own `prototype` objects too.
#[test]
fn generator_prototypes_async_generators_and_methods() {
    let source = "async function* ag() {} var AGP = Object.getPrototypeOf(async function* () {}).prototype;\n\
         var o = { *m() { yield 3; } }; class C { *n() {} static *s() {} }\n\
         [Object.getPrototypeOf(ag()) === ag.prototype, Object.getPrototypeOf(ag.prototype) === AGP, ag.prototype === AGP, ag() instanceof ag,\n\
          Object.getPrototypeOf(o.m()) === o.m.prototype, o.m().next().value, typeof C.prototype.n.prototype,\n\
          Object.getPrototypeOf(C.s()) === C.s.prototype, C.s.prototype === C.prototype.n.prototype].join(' ');";
    assert_eq!(
        eval(source),
        "true true false true true 3 object true false"
    );
}

/// `prototype` is a writable, non-enumerable, non-configurable own data property.
#[test]
fn generator_prototypes_prototype_descriptor() {
    let source = "function* g() {}\n\
         var d = Object.getOwnPropertyDescriptor(g, 'prototype');\n\
         [d.value === g.prototype, d.writable, d.enumerable, d.configurable, Object.getOwnPropertyNames(g).sort().join(),\n\
          (function () { Object.defineProperty(g, 'prototype', { value: { via: 'define' } }); return g().via; })()].join(' ');";
    assert_eq!(
        eval(source),
        "true true false false length,name,prototype define"
    );
}

/// A generator keeps the prototype it was created with alive after its
/// function's `prototype` is replaced (the generator is its only holder):
/// the collector traces it.
#[test]
fn generator_prototypes_survive_collection() {
    let source = "var GP = Object.getPrototypeOf(function* () {}).prototype;\n\
         function* g() { yield 1; }\n\
         g.prototype = Object.create(GP); g.prototype.mark = 'a';\n\
         var it = g();\n\
         g.prototype = Object.create(GP); g.prototype.mark = 'b';\n\
         var junk = []; for (var i = 0; i < 3000; i++) junk.push({ i: i }); junk = null;\n\
         [it.mark, Object.getPrototypeOf(it).mark, g().mark, it.next().value].join(' ');";
    assert_eq!(eval_under_gc_stress(source), "a a b 1");
}
