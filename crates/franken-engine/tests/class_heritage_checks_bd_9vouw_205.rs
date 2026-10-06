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
