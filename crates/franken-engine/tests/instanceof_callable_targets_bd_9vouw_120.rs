//! bd-9vouw.120: `instanceof` with a generator function on the right.
//!
//! InstanceofOperator (ES2020 12.10.4) requires a callable target and
//! OrdinaryHasInstance reads its `prototype` through [[Get]]; the engine
//! required a constructor, so `gen() instanceof genFn` threw a TypeError,
//! and its chain walk stopped at a generator or iterator left operand.
//! Expected strings are Node v22.2.0's output for the same programs.
//!
//! No-claim: every generator function here shares one `prototype` object
//! (%GeneratorPrototype%; Node gives each its own), so `g() instanceof h`
//! for two generator functions is true here and false in Node.

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

/// Generator, async generator, iterator and promise values walk their prototype chains to Object.prototype.
#[test]
fn instanceof_exotic_left_operands() {
    let source = "async function* ag() {}\n\
         [(function* () {})() instanceof Object, ag() instanceof Object, [].keys() instanceof Object, new Map().entries() instanceof Object,\n\
          new Set().values() instanceof Object, 'ab'[Symbol.iterator]() instanceof Object, Promise.resolve(1) instanceof Object,\n\
          [].keys() instanceof Function, (function* () {})() instanceof Function].join(' ');";
    assert_eq!(
        eval(source),
        "true true true true true true true false false"
    );
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

/// bd-9vouw.268: %Function.prototype% is a function in the spec (an object
/// here), so OrdinaryHasInstance with it as C reads its `prototype`: a
/// TypeError when that is not an object, false for a primitive candidate.
/// The bd-9vouw.268 path answered false for any non-callable C. Expected
/// lines: Node v22.2.0's output, captured programmatically.
#[test]
fn function_prototype_reads_its_prototype_for_instanceof_bd_9vouw_268() {
    let source = r#"function k(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
console.log(k(function () { return [] instanceof Function.prototype; }), k(function () { return Function.prototype[Symbol.hasInstance].call(Function.prototype, {}); }));
Function.prototype.prototype = '';
console.log(k(function () { return [] instanceof Function.prototype; }), k(function () { return 1 instanceof Function.prototype; }), k(function () { return ({}) instanceof Object; }));
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(lines, ["TypeError TypeError", "TypeError false true",]);
}
