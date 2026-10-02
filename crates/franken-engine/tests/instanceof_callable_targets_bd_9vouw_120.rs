//! bd-9vouw.120: `instanceof` with a generator function on the right.
//!
//! InstanceofOperator (ES2020 12.10.4) requires a callable target and
//! OrdinaryHasInstance reads its `prototype` through [[Get]]; the engine
//! required a constructor, so `gen() instanceof genFn` threw a TypeError.
//! Expected strings are Node v22.2.0's output for the same programs.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// A generator (or async generator) is an instance of its generator function: instanceof needs a callable target, not a constructor.
#[test]
fn instanceof_generator_functions() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         function* g() {} var it = g(); var ag = async function* () {};\n\
         g.prototype.tag = 1;\n\
         [it instanceof g, g() instanceof g, ({}) instanceof g, Object.create(g.prototype) instanceof g, ag() instanceof ag, it instanceof ag,\n\
          attempt(() => (function* () {})() instanceof Object)].join(' ');";
    assert_eq!(eval(source), "true true false true true false true");
}

/// Arrow functions, async functions and methods have no prototype: an object operand is a TypeError, a primitive is false.
#[test]
fn instanceof_non_constructor_targets() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         var arrow = () => 1; async function af() {} var o = { m() {} };\n\
         [attempt(() => ({}) instanceof arrow), attempt(() => 1 instanceof arrow), attempt(() => ({}) instanceof af), attempt(() => ({}) instanceof o.m),\n\
          attempt(() => ({}) instanceof {}), attempt(() => [] instanceof Array), attempt(() => ({}) instanceof Math.max)].join(' ');";
    assert_eq!(
        eval(source),
        "TypeError false TypeError TypeError TypeError true TypeError"
    );
}
