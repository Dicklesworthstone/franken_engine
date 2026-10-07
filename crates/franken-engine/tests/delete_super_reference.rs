#![forbid(unsafe_code)]

//! ES2022 13.5.1.2: `delete` of a super reference throws a ReferenceError
//! after the reference is evaluated (`this`, then the key expression; no
//! ToPropertyKey, no super base). It lowered as an ordinary member delete on
//! the super base: a TypeError where the base is null or a primitive, and in
//! a method it removed the parent's method (`typeof X.prototype.method` was
//! undefined afterwards). Test262: language/expressions/delete/super-*.

use frankenengine_engine::HybridRouter;

/// A derived constructor, an instance method (the parent method survives),
/// a static method whose home has a null prototype, and an object-literal
/// method with a computed key (evaluated, never converted). Expected lines
/// are Node v22.2.0's output, captured programmatically. The last line
/// compares the error type only: before super() the spec evaluates `this`
/// first, a ReferenceError whose message V8 does not use.
#[test]
fn delete_of_a_super_reference_throws_a_reference_error() {
    let source = r#"function k(f) { try { f(); return 'no'; } catch (e) { return e.constructor.name + ':' + e.message; } }
class C extends Object { constructor() { super(); delete super.x; } }
class X { method() { return this; } }
class Y extends X { method() { delete super.method; } }
class S { static m() { delete super.x; } }
Object.setPrototypeOf(S, null);
var log = [];
var key = { toString() { log.push('key'); return 'x'; } };
var obj = { x: 1, m() { delete super[(log.push('expr'), key)]; } };
console.log(k(function () { new C(); }), k(function () { new Y().method(); }), k(function () { S.m(); }));
console.log(k(function () { obj.m(); }), log.join(','), typeof X.prototype.method, obj.x);
class D extends Object { constructor() { delete super.x; super(); } }
console.log(k(function () { new D(); }).split(':')[0]);
"#;
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
            "ReferenceError:Unsupported reference to 'super' ReferenceError:Unsupported reference to 'super' ReferenceError:Unsupported reference to 'super'",
            "ReferenceError:Unsupported reference to 'super' expr function 1",
            "ReferenceError",
        ]
    );
}
