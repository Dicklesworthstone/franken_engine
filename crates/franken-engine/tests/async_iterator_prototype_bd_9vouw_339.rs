//! bd-9vouw.339: %AsyncGeneratorPrototype%'s [[Prototype]] is
//! %AsyncIteratorPrototype% (ES2018 25.1.3, 25.5.1), whose only own member
//! is [Symbol.asyncIterator] returning its receiver, and whose [[Prototype]]
//! is Object.prototype. The engine linked %AsyncGeneratorPrototype% straight
//! to Object.prototype and kept @@asyncIterator on it, so the intrinsic code
//! reaches with `Object.getPrototypeOf(Object.getPrototypeOf(g.prototype))`
//! was Object.prototype. Node v22.2.0 gives this line (Bun 1.4.2 lists a
//! second own symbol, Symbol.asyncDispose, which v22.2.0 does not have).

use frankenengine_engine::HybridRouter;

#[test]
fn async_generators_inherit_async_iterator_prototype() {
    let source = r#"
async function* g() {}
var AGP = Object.getPrototypeOf(g.prototype);
var AIP = Object.getPrototypeOf(AGP);
var method = AIP[Symbol.asyncIterator];
var desc = Object.getOwnPropertyDescriptor(AIP, Symbol.asyncIterator);
var receiver = {};
console.log([
  AIP !== Object.prototype,
  Object.getPrototypeOf(AIP) === Object.prototype,
  typeof method,
  method.name,
  method.length,
  desc.writable, desc.enumerable, desc.configurable,
  method.call(receiver) === receiver,
  Object.prototype.hasOwnProperty.call(AGP, Symbol.asyncIterator),
  Object.getOwnPropertySymbols(AIP).length,
  Object.getOwnPropertyNames(AIP).length,
  g()[Symbol.asyncIterator]() !== undefined,
].join(' '));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        ["true true function [Symbol.asyncIterator] 0 true false true true false 1 0 true"]
    );
}
