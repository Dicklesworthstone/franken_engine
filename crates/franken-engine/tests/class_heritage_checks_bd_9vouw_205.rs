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
