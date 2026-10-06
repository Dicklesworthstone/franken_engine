#![forbid(unsafe_code)]

//! bd-9vouw.205: ClassDefinitionEvaluation (ES2020 14.6.13 step 6.g) throws a
//! TypeError for a superclass that is not a constructor (an arrow, a
//! generator, an async function, a plain object) and for one whose
//! `prototype` is neither an object nor null; the class was defined anyway.
//! Not covered: `class extends null {}`, which still throws (the lowering
//! reads `null.prototype`).
//!
//! Expected line is Node v22.2.0's output (Bun 1.4.2 prints the same).

use frankenengine_engine::HybridRouter;

#[test]
fn class_heritage_must_be_a_constructor_with_an_object_prototype() {
    let source = "const out = [];\nconst cases = [['arrow', () => { const f = () => {}; return class extends f {}; }], ['generator', () => { function* g() {} return class extends g {}; }], ['async', () => { async function a() {} return class extends a {}; }], ['object', () => class extends ({}) {}], ['badproto', () => { function F() {} F.prototype = 1; return class extends F {}; }], ['nullproto', () => { function F() {} F.prototype = null; return class extends F {}; }]];\nfor (const [label, make] of cases) {\n  try { make(); out.push(label + ':ok'); } catch (e) { out.push(label + ':' + e.constructor.name); }\n}\nconsole.log(out.join(' '));\n";
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "arrow:TypeError generator:TypeError async:TypeError object:TypeError badproto:TypeError nullproto:ok"
        ]
    );
}

/// bd-9vouw.216: `F.__proto__ = P` on a function runs Object.prototype's
/// `__proto__` setter: P becomes F's [[Prototype]] (F inherits P's statics),
/// a primitive is ignored, a cycle is a TypeError, and no own `__proto__`
/// property appears. It stored an own data property, so
/// `Object.getPrototypeOf(F)` stayed Function.prototype and `F.s` was
/// undefined. Not covered: `Object.setPrototypeOf(f, null)` on a function
/// still reports Function.prototype.
#[test]
fn assigning_proto_on_a_function_sets_its_prototype_bd_9vouw_216() {
    let source = "function P() {} P.s = 1; function C() {} C.__proto__ = P;\nvar r1 = [Object.getPrototypeOf(C) === P, C.s, C.__proto__ === P];\nfunction D() {} D.__proto__ = 5;\nvar r2 = Object.getPrototypeOf(D) === Function.prototype;\nvar cyc; try { P.__proto__ = C; cyc = 'no'; } catch (e) { cyc = e.name; }\nconsole.log(r1.join(), r2, cyc, Object.keys(C).length, Object.prototype.hasOwnProperty.call(C, '__proto__'));\n";
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(lines, ["true,1,true true TypeError 0 false"]);
}

/// bd-9vouw.228: a class element or destructuring key spelled as a numeric
/// literal names ToString of its value, as an object literal key does:
/// binary, octal, hex, exponent, leading-dot and non-canonical decimal
/// accessors, a static accessor, a method, static and instance fields, a
/// BigInt key, the accessor's function name, and `{ 0x10: a }` patterns.
/// The key kept its source text ("0b10"), so `C.prototype['2']` was
/// undefined (31 Test262 tests). Expected lines are Node v22.2.0's output;
/// Bun 1.4.2 agrees.
#[test]
fn numeric_literal_class_and_pattern_keys_are_canonical_bd_9vouw_228() {
    let source = "var log = [];\nclass C { get 0b10() { return 'b'; } set 0b10(v) { log.push(v); } get 1E+9() { return 'e'; } get 0x10() { return 'h'; } get .1() { return 'd'; } get 0.0000001() { return 'n'; } get 0o10() { return 'o'; } static get 0b11() { return 's'; } }\nconsole.log(C.prototype['2'], C.prototype['1000000000'], C.prototype['16'], C.prototype['0.1'], C.prototype['1e-7'], C.prototype['8'], C['3']);\nC.prototype['2'] = 'x';\nconsole.log(log.join(), Object.getOwnPropertyDescriptor(C.prototype, '2').get.name, C.prototype.hasOwnProperty('0b10'));\nclass D { 0x10() { return 'm'; } static 1e3 = 'f'; 0b101 = 'i'; 1n() { return 'big'; } }\nconsole.log(new D()[16](), D[1000], new D()[5], new D()[1](), D.prototype[16].name);\nvar { 0x10: a, 1e1: b, .5: c } = { 16: 'A', 10: 'B', 0.5: 'C' };\nconsole.log(a, b, c);\n";
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        ["b e h d n o s", "x get 2 false", "m f i big 16", "A B C"]
    );
}
