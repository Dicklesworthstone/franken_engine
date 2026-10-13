//! bd-9vouw.310: %MapIteratorPrototype%.next, %SetIteratorPrototype%.next
//! and %ArrayIteratorPrototype%.next throw a TypeError when `this` is not
//! an iterator of their kind, including a detached `next()` (no receiver)
//! and `next.call(undefined)`. Both stepped the iterator the method was read
//! from. A receiver of the right kind still advances, and for-of,
//! destructuring and `yield*` over a Map or Set are unaffected. Node v22.2.0
//! gives this value; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn iterator_next_without_an_iterator_receiver_throws() {
    let source = r#"
var out = [];
function attempt(f) { try { return JSON.stringify(f()); } catch (e) { return e.constructor.name; } }
var it = new Map([[1, 2], [3, 4]]).entries();
var n = it.next;
out.push(attempt(function () { return n(); }));
out.push(attempt(function () { return n.call(undefined); }));
var si = new Set([5]).values();
out.push(attempt(function () { return si.next.call(undefined); }));
var ai = [6, 7].values();
out.push(attempt(function () { return ai.next.call(undefined); }));
out.push(attempt(function () { return it.next(); }));
out.push(attempt(function () { return n.call(it); }));
for (const [k] of new Map([[8, 9]])) out.push(k);
var [a, b] = new Set([10, 11]); out.push(a + b);
function* g() { yield* new Set([12]); } out.push([...g()].join());
out.join(' ');
"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        r#"TypeError TypeError TypeError TypeError {"value":[1,2],"done":false} {"value":[3,4],"done":false} 8 21 12"#
    );
}
