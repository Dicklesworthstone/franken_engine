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
    // Functions are objects and valid keys (immer keys a WeakMap by
    // function); `set` threw "expected object WeakMap key, got function".
    check(
        "const wm = new WeakMap(); const f = function () {}; const g = () => 1; class C {} \
         wm.set(f, 'fn').set(g, 'arrow').set(C, 'class').set(Math.max, 'builtin'); \
         const ws = new WeakSet([f]); \
         [wm.get(f), wm.get(g), wm.get(C), wm.get(Math.max), wm.has(function () {}), \
         wm.delete(g), wm.has(g), ws.has(f), wm.get(() => 2)].join();",
        "fn,arrow,class,builtin,false,true,false,true,",
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

/// A replace callback receives the named groups object as its last
/// argument (ES2020 21.2.5.8 step 14.l) when the pattern has named groups,
/// and no extra argument otherwise. It never received it.
#[test]
fn replace_callbacks_receive_named_groups() {
    check(
        "['x-y 2020-01'.replace(/(?<a>x)-(?<b>y)/, (...args) => JSON.stringify(args.at(-1)) + typeof args.at(-1)), \
         '2020-01'.replace(/(?<y>\\d+)-(?<m>\\d+)/, (m, y, mo, off, str, g) => g.m + '/' + g.y), \
         'ab'.replace(/(?<x>a)|(?<z>q)/, (...args) => JSON.stringify(args.at(-1)) + ('z' in args.at(-1))), \
         'ab'.replace(/(a)/, (...args) => args.length)].join(' ');",
        r#"{"a":"x","b":"y"}object 2020-01 01/2020 {"x":"a"}trueb 4b"#,
    );
}
