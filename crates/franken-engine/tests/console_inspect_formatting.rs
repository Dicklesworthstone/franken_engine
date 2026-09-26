//! `console.log` renders its arguments the way Node does (`util.format` with
//! `util.inspect` at its defaults: depth 2, breakLength 80, compact 3).
//!
//! Arguments used to go through ToString, so `console.log({ a: 1 })` printed
//! `[object Object]`, `console.log([1, [2]])` printed `1,2`, `-0` printed `0`
//! and `%s`/`%d` directives were printed literally. Program output that logs
//! any structured value differed from Node.
//!
//! Expected output is what Node v22.2.0 prints for the same program (console
//! lines joined with `\n`). Not covered here, and still different from Node:
//! class constructors print as `[Function: A]` rather than `[class A]`, and
//! error stacks carry the engine's own frames and messages.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn console_of(source: &str) -> String {
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for {source:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn check(source: &str, node: &str) {
    assert_eq!(
        console_of(source),
        node,
        "`{source}` must print what Node v22.2.0 prints"
    );
}

#[test]
fn primitives_and_strings() {
    check(
        r#"console.log(1, -0, 1.5, NaN, Infinity, -Infinity, 10n, true, null, undefined, "s", Symbol("x"), Symbol())"#,
        r#"1 -0 1.5 NaN Infinity -Infinity 10n true null undefined s Symbol(x) Symbol()"#,
    );
    check(
        r#"console.log("a b", "it's"); console.log(""); console.log()"#,
        r#"a b it's

"#,
    );
    check(
        r#"console.log({ s: "line1\nline2", t: "tab\there", q: "it's", e: "" })"#,
        r#"{ s: 'line1\nline2', t: 'tab\there', q: "it's", e: '' }"#,
    );
    check(
        r#"console.log({ s: "line1\nline2 and more text here to exceed width abcdefghijklmnopqrstuvwxyz0123456789" })"#,
        r#"{
  s: 'line1\n' +
    'line2 and more text here to exceed width abcdefghijklmnopqrstuvwxyz0123456789'
}"#,
    );
    check(
        r#"console.log({ a: -0, b: 1e21, c: 1e-7, d: 0.1 + 0.2, e: 2n ** 64n })"#,
        r#"{
  a: -0,
  b: 1e+21,
  c: 1e-7,
  d: 0.30000000000000004,
  e: 18446744073709551616n
}"#,
    );
    check(
        r#"console.log([true, false, null, undefined, 0, "", NaN])"#,
        r#"[ true, false, null, undefined, 0, '', NaN ]"#,
    );
}

#[test]
fn arrays() {
    check(
        r#"console.log([]); console.log([1, 2, 3]); console.log([1, [2, [3, [4, [5]]]]]); console.log(["a", "it's", 'say "x"'])"#,
        r#"[]
[ 1, 2, 3 ]
[ 1, [ 2, [ 3, [Array] ] ] ]
[ 'a', "it's", 'say "x"' ]"#,
    );
    check(
        r#"console.log([1, 2, 3, 4, 5, 6, 7]); console.log(Array.from({ length: 30 }, (_, i) => i * 37))"#,
        r#"[
  1, 2, 3, 4,
  5, 6, 7
]
[
    0,  37,  74, 111,  148,  185,
  222, 259, 296, 333,  370,  407,
  444, 481, 518, 555,  592,  629,
  666, 703, 740, 777,  814,  851,
  888, 925, 962, 999, 1036, 1073
]"#,
    );
    check(
        r#"console.log("abcdefghijklmnopqrstuvwxyz".split(""))"#,
        r#"[
  'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l',
  'm', 'n', 'o', 'p', 'q', 'r',
  's', 't', 'u', 'v', 'w', 'x',
  'y', 'z'
]"#,
    );
    check(
        r#"console.log([1, "two", { three: 3 }, [4], null, undefined, true, 8.5, "nine", 10])"#,
        r#"[
  1,            'two',
  { three: 3 }, [ 4 ],
  null,         undefined,
  true,         8.5,
  'nine',       10
]"#,
    );
    check(
        r#"console.log([, 1, , , 2, ,]); var a = [1, 2]; a[10] = 3; console.log(a); console.log(new Array(5))"#,
        r#"[ <1 empty item>, 1, <2 empty items>, 2, <1 empty item> ]
[ 1, 2, <8 empty items>, 3 ]
[ <5 empty items> ]"#,
    );
    check(
        r#"console.log(Array.from({ length: 120 }, (_, i) => i))"#,
        r#"[
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11,
  12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
  24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
  36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
  48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
  60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
  72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83,
  84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
  96, 97, 98, 99,
  ... 20 more items
]"#,
    );
    check(
        r#"var a = [1, 2]; a.x = "y"; console.log(a)"#,
        r#"[ 1, 2, x: 'y' ]"#,
    );
    check(
        r#"console.log({ matrix: [[1, 2, 3], [4, 5, 6], [7, 8, 9]], labels: ["x", "y", "z"] })"#,
        r#"{
  matrix: [ [ 1, 2, 3 ], [ 4, 5, 6 ], [ 7, 8, 9 ] ],
  labels: [ 'x', 'y', 'z' ]
}"#,
    );
    check(
        r#"console.log([{ id: 1, name: "alpha", tags: ["a", "b"] }, { id: 2, name: "beta", tags: [] }, { id: 3, name: "gamma", tags: ["c"] }])"#,
        r#"[
  { id: 1, name: 'alpha', tags: [ 'a', 'b' ] },
  { id: 2, name: 'beta', tags: [] },
  { id: 3, name: 'gamma', tags: [ 'c' ] }
]"#,
    );
}

#[test]
fn objects() {
    check(
        r#"console.log({}); console.log({ a: 1 }); console.log({ a: 1, b: "two", c: [3], d: { e: null } })"#,
        r#"{}
{ a: 1 }
{ a: 1, b: 'two', c: [ 3 ], d: { e: null } }"#,
    );
    check(
        r#"console.log({ a: { b: { c: { d: { e: 1 } } } } }); console.log([[[[[1]]]]])"#,
        r#"{ a: { b: { c: [Object] } } }
[ [ [ [Array] ] ] ]"#,
    );
    check(
        r#"console.log({ "a-b": 1, _x: 2, $y: 3, 2: 4, "it's": 5, "": 6, [Symbol("s")]: 7 })"#,
        r#"{ '2': 4, 'a-b': 1, _x: 2, '$y': 3, "it's": 5, '': 6, [Symbol(s)]: 7 }"#,
    );
    check(
        r#"console.log({ name: "franken", version: "0.2.0", description: "a runtime", keywords: ["js", "engine", "rust"], license: "MIT" })"#,
        r#"{
  name: 'franken',
  version: '0.2.0',
  description: 'a runtime',
  keywords: [ 'js', 'engine', 'rust' ],
  license: 'MIT'
}"#,
    );
    check(
        r#"console.log({ status: 200, data: { users: [{ id: 1, name: "Ann", roles: ["admin"] }, { id: 2, name: "Bob", roles: [] }], total: 2 }, ok: true })"#,
        r#"{
  status: 200,
  data: { users: [ [Object], [Object] ], total: 2 },
  ok: true
}"#,
    );
    check(
        r#"var o = { get a() { return 1; }, set b(v) {}, get c() { return 1; }, set c(v) {} }; console.log(o)"#,
        r#"{ a: [Getter], b: [Setter], c: [Getter/Setter] }"#,
    );
    check(
        r#"class Point { constructor(x, y) { this.x = x; this.y = y; } } console.log(new Point(1, 2)); class Empty {} console.log(new Empty()); function Legacy() { this.v = 1; } console.log(new Legacy())"#,
        r#"Point { x: 1, y: 2 }
Empty {}
Legacy { v: 1 }"#,
    );
    check(
        r#"var o = Object.create(null); console.log(o); o.a = 1; console.log(o); console.log(Object.create({ inherited: 1 }))"#,
        r#"[Object: null prototype] {}
[Object: null prototype] { a: 1 }
{}"#,
    );
    check(
        r#"var o = { name: "o" }; o.self = o; console.log(o); var a = [1]; a.push(a); console.log(a); var p = { q: {} }; p.q.p = p; console.log(p)"#,
        r#"<ref *1> { name: 'o', self: [Circular *1] }
<ref *1> [ 1, [Circular *1] ]
<ref *1> { q: { p: [Circular *1] } }"#,
    );
    check(
        r#"console.log(JSON.parse('{"a":[1,2,{"b":null}],"c":"d","e":{"f":{"g":{"h":1}}}}'))"#,
        r#"{ a: [ 1, 2, { b: null } ], c: 'd', e: { f: { g: [Object] } } }"#,
    );
}

/// Guest data may carry a `__type` field (a common JSON discriminator); it is
/// printed like any other key, not mistaken for an engine-internal slot.
#[test]
fn guest_type_fields_are_ordinary_keys() {
    check(
        r#"console.log({ __type: "Map", name: "x", __id: 5 }, { __type: "Order", __v: 1 })"#,
        r#"{ __type: 'Map', name: 'x', __id: 5 } { __type: 'Order', __v: 1 }"#,
    );
}

#[test]
fn functions() {
    check(
        r#"function named() {} console.log(named); console.log(function () {}); console.log(() => 1); var f = () => 2; console.log(f); console.log(async function af() {}, function* g() {}, async function* ag() {})"#,
        r#"[Function: named]
[Function (anonymous)]
[Function (anonymous)]
[Function: f]
[AsyncFunction: af] [GeneratorFunction: g] [AsyncGeneratorFunction: ag]"#,
    );
    check(
        r#"function withProps() {} withProps.a = 1; withProps.b = "x"; console.log(withProps); console.log({ f: withProps })"#,
        r#"[Function: withProps] { a: 1, b: 'x' }
{ f: [Function: withProps] { a: 1, b: 'x' } }"#,
    );
    check(
        r#"function t() {} console.log(t.bind(null), Math.max, [].push, parseInt)"#,
        r#"[Function: bound t] [Function: max] [Function: push] [Function: parseInt]"#,
    );
}

#[test]
fn builtin_objects() {
    check(
        r#"console.log(new Map([[1, "a"], ["b", { c: 2 }]])); console.log(new Set([1, "two", [3]])); console.log(new Map(), new Set()); console.log({ m: new Map([[1, 2]]) })"#,
        r#"Map(2) { 1 => 'a', 'b' => { c: 2 } }
Set(3) { 1, 'two', [ 3 ] }
Map(0) {} Set(0) {}
{ m: Map(1) { 1 => 2 } }"#,
    );
    check(
        r#"console.log(new WeakMap(), new WeakSet())"#,
        r#"WeakMap { <items unknown> } WeakSet { <items unknown> }"#,
    );
    check(
        r#"console.log(new Date(0)); console.log([new Date(86400000)]); console.log(new Date(NaN)); console.log(/ab+c/gi, [/x/])"#,
        r#"1970-01-01T00:00:00.000Z
[ 1970-01-02T00:00:00.000Z ]
Invalid Date
/ab+c/gi [ /x/ ]"#,
    );
    check(
        r#"console.log(Promise.resolve(42)); console.log(new Promise(() => {})); var r = Promise.reject(new Error("no")); r.catch(() => {}); console.log(Promise.resolve({ a: 1 }))"#,
        r#"Promise { 42 }
Promise { <pending> }
Promise { { a: 1 } }"#,
    );
    check(
        r#"console.log(new Uint8Array([1, 2, 3])); console.log(new Float64Array(2)); console.log(new Int16Array([70000, -1]))"#,
        r#"Uint8Array(3) [ 1, 2, 3 ]
Float64Array(2) [ 0, 0 ]
Int16Array(2) [ 4464, -1 ]"#,
    );
    check(
        r#"console.log(new ArrayBuffer(4))"#,
        r#"ArrayBuffer { [Uint8Contents]: <00 00 00 00>, byteLength: 4 }"#,
    );
}

#[test]
fn format_directives() {
    check(
        r#"console.log("%s is %d years", "Ann", 42); console.log("%i %f", 42.9, "3.5x"); console.log("%j", { a: [1, "b"] }); console.log("100%% %s", "done"); console.log("%c styled", "color: red"); console.log("%s", { a: 1 }, "extra", 5)"#,
        r#"Ann is 42 years
42 3.5
{"a":[1,"b"]}
100% done
 styled
{ a: 1 } extra 5"#,
    );
    check(
        r#"console.log("%O", { a: { b: { c: { d: 1 } } } }); console.log("%s %s", "only one"); console.log("%x %s", "y"); console.log("a", "%s", "b")"#,
        r#"{ a: { b: { c: [Object] } } }
only one %s
%x y
a %s b"#,
    );
    check(
        r#"console.error({ level: "error" }); console.warn([1, 2]); console.info("info", { x: 1 })"#,
        r#"{ level: 'error' }
[ 1, 2 ]
info { x: 1 }"#,
    );
}
