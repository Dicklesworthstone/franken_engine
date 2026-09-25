//! bd-9vouw.55: `RegExp.prototype.exec` with `lastIndex`, capture-complete
//! non-global `String.prototype.match`, and `WeakMap.prototype` methods.
//!
//! Before this, `re.exec` was undefined (breaking the standard tokenizer
//! loop), `match` returned only `[0]`, and `wm.set(k, v)` was not callable.
//! Expected strings are what Node v22.2.0 prints for the same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn exec_loop_advances_last_index() {
    check(
        "const re = /(\\w)(\\d)/g; let m, out = []; \
         while ((m = re.exec('a1 b2 c3')) !== null) out.push(m[1] + m[2] + '@' + m.index); \
         out.join(',') + '|' + re.lastIndex;",
        "a1@0,b2@3,c3@6|0",
    );
    check(
        "var re = /a/y; re.lastIndex = 1; (re.exec('ba') !== null) + ':' + re.lastIndex + ':' + \
         (re.exec('ba') === null) + ':' + re.lastIndex;",
        "true:2:true:0",
    );
    check("/x/.exec('abc') === null;", "true");
}

#[test]
fn exec_and_match_return_captures_and_groups() {
    check(
        "var m = /(?<y>\\d{4})-(?<mo>\\d{2})/.exec('on 2020-12'); \
         m.groups.y + ':' + m.groups.mo + ':' + m.index + ':' + m[0];",
        "2020:12:3:2020-12",
    );
    check(
        "var m = '2020-12-31'.match(/(\\d{4})-(\\d{2})/); \
         m[1] + ':' + m[2] + ':' + m.length + ':' + m.index + ':' + (m.groups === undefined);",
        "2020:12:3:0:true",
    );
}

#[test]
fn weakmap_methods() {
    check(
        "var wm = new WeakMap(); var k = {}; var k2 = {}; wm.set(k, 1).set(k2, 2); \
         [wm.get(k), wm.has(k2), wm.delete(k), wm.has(k), wm.get({})].join();",
        "1,true,true,false,",
    );
}

/// `WeakSet.prototype.add/has/delete` over object identity, and `WeakMap` /
/// `WeakSet` as first-class constructors whose instances inherit from their
/// prototypes. Before this, `ws.add` was undefined and `typeof WeakSet`
/// threw a ReferenceError.
#[test]
fn weakset_methods_and_weak_constructor_values() {
    check(
        "var ws = new WeakSet(); var a = {}, b = {}; ws.add(a); \
         [ws.has(a), ws.has(b), ws.delete(a), ws.has(a), ws.delete(a), ws.has(1), \
         ws.add(b) === ws].join()",
        "true,false,true,false,false,false,true",
    );
    check(
        "var r; try { new WeakSet().add(1); r = 'added'; } catch (e) { r = e instanceof TypeError; } \
         var s; try { WeakSet.prototype.has.call({}, {}); s = 'ok'; } \
         catch (e) { s = e instanceof TypeError; } r + ',' + s",
        "true,true",
    );
    check(
        "var k = {}; var ws = new WeakSet([k]); [typeof WeakSet, typeof WeakMap, ws.has(k), \
         ws instanceof WeakSet, new WeakMap() instanceof WeakMap, ws instanceof Object].join()",
        "function,function,true,true,true,true",
    );
}
