//! bd-9vouw.147: Proxy [[GetOwnProperty]] and [[DefineOwnProperty]]
//! (ES2020 9.5.5, 9.5.6).
//!
//! `Object.getOwnPropertyDescriptor(proxy, k)` answered undefined even
//! without a trap, and `Object.defineProperty(proxy, ...)` neither called the
//! `defineProperty` trap nor reached the target. Expected strings are Node
//! v22.2.0's output for the same programs.
//!
//! No-claim: Object.defineProperties, Object.create's second argument and
//! Object.getOwnPropertyDescriptors still read and define without the traps.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// Without traps, getOwnPropertyDescriptor and defineProperty reach the target.
#[test]
fn proxy_descriptor_forwarding() {
    let source = "var t = { a: 1 }; var p = new Proxy(t, {});\n\
         Object.defineProperty(p, 'x', { value: 2, enumerable: true });\n\
         [JSON.stringify(Object.getOwnPropertyDescriptor(p, 'a')), t.x, JSON.stringify(Object.getOwnPropertyDescriptor(t, 'x')), String(Object.getOwnPropertyDescriptor(p, 'zz')), Reflect.defineProperty(p, 'y', { value: 3 }), t.y].join(' ');";
    assert_eq!(
        eval(source),
        "{\"value\":1,\"writable\":true,\"enumerable\":true,\"configurable\":true} 2 {\"value\":2,\"writable\":false,\"enumerable\":true,\"configurable\":false} undefined true 3"
    );
}

/// The traps receive (target, key) and (target, key, descriptor); the trap's descriptor is completed.
#[test]
fn proxy_descriptor_traps() {
    let source = "var log = []; var t = {};\n\
         var p = new Proxy(t, {\n\
           getOwnPropertyDescriptor(target, k) { log.push('gopd:' + String(k) + ':' + (target === t)); return { value: 7, configurable: true }; },\n\
           defineProperty(target, k, d) { log.push('def:' + k + ':' + JSON.stringify(d)); return Reflect.defineProperty(target, k, d); }\n\
         });\n\
         var d = Object.getOwnPropertyDescriptor(p, 'q');\n\
         Object.defineProperty(p, 'w', { value: 3, writable: true });\n\
         [JSON.stringify(d), t.w, log.join('|')].join(' ');";
    assert_eq!(
        eval(source),
        "{\"value\":7,\"writable\":false,\"enumerable\":false,\"configurable\":true} 3 gopd:q:true|def:w:{\"value\":3,\"writable\":true}"
    );
}

/// Invariant violations are TypeErrors (ES2020 9.5.5, 9.5.6); a false defineProperty result throws in Object.defineProperty and is false in Reflect.defineProperty.
#[test]
fn proxy_descriptor_invariants() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         var locked = {}; Object.defineProperty(locked, 'k', { value: 1, configurable: false });\n\
         var hides = new Proxy(locked, { getOwnPropertyDescriptor() { return undefined; } });\n\
         var invents = new Proxy({}, { getOwnPropertyDescriptor() { return { value: 1, configurable: false }; } });\n\
         var refuses = new Proxy({}, { defineProperty() { return false; } });\n\
         var lies = new Proxy({}, { defineProperty() { return true; } });\n\
         [attempt(() => Object.getOwnPropertyDescriptor(hides, 'k')), attempt(() => Object.getOwnPropertyDescriptor(invents, 'k')),\n\
          attempt(() => Object.defineProperty(refuses, 'a', { value: 1 })), attempt(() => Reflect.defineProperty(refuses, 'a', { value: 1 })),\n\
          attempt(() => Object.defineProperty(lies, 'b', { value: 1, configurable: false })), attempt(() => Reflect.defineProperty({}, 'c', { get: 1 }))].join(' ');";
    assert_eq!(
        eval(source),
        "TypeError TypeError TypeError false TypeError TypeError"
    );
}

/// A callable proxy (bd-9vouw.132) takes the same path.
#[test]
fn proxy_descriptor_callable() {
    let source = "function f(a, b) {} var p = new Proxy(f, {});\n\
         Object.defineProperty(p, 'tag', { value: 't', enumerable: true });\n\
         [JSON.stringify(Object.getOwnPropertyDescriptor(p, 'length')), f.tag, JSON.stringify(Object.getOwnPropertyDescriptor(p, 'tag'))].join(' ');";
    assert_eq!(
        eval(source),
        "{\"value\":2,\"writable\":false,\"enumerable\":false,\"configurable\":true} t {\"value\":\"t\",\"writable\":false,\"enumerable\":true,\"configurable\":false}"
    );
}

/// bd-9vouw.236: HasOwnProperty of a Proxy is its [[GetOwnProperty]]: the
/// getOwnPropertyDescriptor trap, else the target's own property (string or
/// symbol key), and a revoked Proxy throws. Every key read false, so mobx's
/// `hasOwnProperty.call(proxy, $mobx)` made a second administration and
/// recursed until the stack overflowed on `observable({ a: 1 })`. Node v22.2.0
/// gives this value; Bun 1.4.2 agrees.
#[test]
fn has_own_property_of_a_proxy_asks_its_target_or_trap() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\nvar sym = Symbol('adm');\nvar target = {};\nObject.defineProperty(target, sym, { value: 1, enumerable: false, writable: true, configurable: true });\ntarget.s = 2;\nvar plain = new Proxy(target, {});\nvar virtual = new Proxy({}, { getOwnPropertyDescriptor(t, k) { return k === 'virt' ? { value: 1, configurable: true } : undefined; } });\nvar revocable = Proxy.revocable({ a: 1 }, {}); revocable.revoke();\nvar hop = Object.prototype.hasOwnProperty;\n[hop.call(plain, sym), hop.call(plain, 's'), hop.call(plain, 'missing'), plain.hasOwnProperty(sym), Object.hasOwn(plain, 's'),\n hop.call(virtual, 'virt'), hop.call(virtual, 'other'), attempt(() => hop.call(revocable.proxy, 'a'))].join(' ');\n";
    assert_eq!(
        eval(source),
        "true true false true true true false TypeError"
    );
}
