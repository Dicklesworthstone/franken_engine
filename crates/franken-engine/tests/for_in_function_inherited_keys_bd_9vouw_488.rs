//! bd-9vouw.488: for-in over a function, a bound function, a class, a
//! generator or an async arrow lists the enumerable properties it inherits
//! from its value-level [[Prototype]] (%Function.prototype%, a parent class),
//! not only its own and Object.prototype's: the walk used to follow the
//! function's backing object's link, which defaults to Object.prototype.
//! Own keys still come first and shadow inherited ones (an own
//! non-enumerable key hides an inherited enumerable one), parent statics
//! follow the class's own, and ordinary objects are unchanged. Node v22.2.0
//! and Bun 1.4.3 print the line; before this change frankenctl printed
//! `own | - | - | - | - | y,x | x | shared | - | a | p | own | y,x`.

use frankenengine_engine::HybridRouter;

#[test]
fn for_in_over_functions_lists_inherited_keys() {
    let source = r#"const out = [];
const keys = (v) => { const ks = []; for (const k in v) ks.push(k); return ks.join(',') || '-'; };
Object.defineProperty(Function.prototype, 'shared', { value: 1, enumerable: true, writable: true, configurable: true });
function foo() {}
foo.own = 1;
out.push(keys(foo), keys(foo.bind({})), keys(class C {}), keys(function* g() {}), keys(async () => {}));
class A { static x = 1; }
class B extends A { static y = 2; }
out.push(keys(B), keys(A));
function shadow() {}
shadow.shared = 'own';
out.push(keys(shadow));
function hidden() {}
Object.defineProperty(hidden, 'shared', { value: 0, enumerable: false });
out.push(keys(hidden));
out.push(keys({ a: 1 }), keys(Object.create({ p: 1 })));
delete Function.prototype.shared;
out.push(keys(foo), keys(B));
console.log(out.join(' | '));
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
        [
            "own,shared | shared | shared | shared | shared | y,x,shared | x,shared | shared | - | a | p | own | y,x"
        ]
    );
}
