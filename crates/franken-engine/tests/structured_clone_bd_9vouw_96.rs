//! bd-9vouw.96: `structuredClone` (HTML structured clone).
//!
//! `typeof structuredClone` was "undefined" (Node: "function"). PROGRAM runs
//! the cases below; NODE_OUTPUT is Node v22.2.0's output for it, line by line:
//! - shared references and cycles;
//! - Map (object keys), Set, Date (valid and invalid), RegExp (lastIndex resets);
//! - errors: the constructor from `name`, subclasses to Error, extra props dropped;
//! - arrays with holes and extra keys; class instances to plain objects;
//!   getters read; non-enumerable and Symbol keys dropped;
//! - typed arrays, ArrayBuffer and DataView over a cloned buffer, a view's
//!   buffer shared with a sibling clone; wrappers, -0 and NaN, BigInt;
//! - the function as a value, DataCloneError (code 25) for functions,
//!   symbols, methods, WeakMap/WeakSet, promises and proxies; the missing
//!   argument error;
//! - 999 levels of nesting.
//!
//! No-claim: the `transfer` option. There is no fixed nesting limit (Node's
//! depends on its native stack, about 1,600 nested objects); the walk is
//! bounded by the instruction and memory budgets. Two engine-wide gaps the
//! program steps around: `instanceof DataView` is false for every DataView
//! (the brand is checked through Object.prototype.toString), and
//! Function.prototype.toString gives the native-code form, so a
//! DataCloneError for a function quotes that form, not the source.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"const o = { a: 1, b: 'x', c: [1, 2, { d: true }], n: null, u: undefined };
const c = structuredClone(o);
console.log(JSON.stringify(c), c !== o, c.c !== o.c, c.c[2] !== o.c[2], 'u' in c);
const cyc = { name: 'root' }; cyc.self = cyc; cyc.list = [cyc];
const cc = structuredClone(cyc);
console.log(cc.self === cc, cc.list[0] === cc, cc !== cyc, cc.name);
const shared = { s: 1 }; const two = structuredClone({ x: shared, y: shared });
console.log(two.x === two.y, two.x !== shared);
const m = new Map([[1, 'a'], ['k', { v: 2 }]]); const mk = { key: true }; m.set(mk, mk);
const mc = structuredClone(m);
console.log(mc instanceof Map, mc.size, mc.get(1), mc.get('k').v, mc.get('k') !== m.get('k'));
const ents = [...mc.entries()]; console.log(ents[2][0] === ents[2][1], ents[2][0] !== mk, ents[2][0].key);
const s = new Set([1, 'two', { three: 3 }]); const sc = structuredClone(s);
console.log(sc instanceof Set, sc.size, [...sc][2].three);
const d = new Date(1700000000000); const dc = structuredClone(d);
console.log(dc instanceof Date, dc.getTime(), dc !== d, Number.isNaN(structuredClone(new Date(NaN)).getTime()));
const r = /ab+c/gi; r.lastIndex = 3; const rc = structuredClone(r);
console.log(rc instanceof RegExp, rc.source, rc.flags, rc.lastIndex, rc !== r, rc.test('xABBC'));
const e = new TypeError('bad'); e.extra = 1; const ec = structuredClone(e);
console.log(ec instanceof TypeError, ec.name, ec.message, ec !== e, ec.extra, ec.stack === e.stack);
class MyErr extends Error { constructor(msg) { super(msg); this.name = 'MyErr'; } }
const me = structuredClone(new MyErr('m')); console.log(me.name, me.message, me instanceof MyErr, me instanceof Error);
const arr = [1, , 3]; arr.extra = 'x'; const ac = structuredClone(arr);
console.log(Array.isArray(ac), ac.length, 1 in ac, ac.extra, ac[2]);
const sparse = []; sparse[5] = 'x'; const sp = structuredClone(sparse); console.log(sp.length, Object.keys(sp).join());
class P { constructor() { this.v = 1; } get g() { return 2; } }
const pc = structuredClone(new P());
console.log(pc instanceof P, Object.getPrototypeOf(pc) === Object.prototype, JSON.stringify(pc));
const acc = { get x() { return 'got'; } }; console.log(JSON.stringify(structuredClone(acc)));
const hidden = Object.defineProperty({ vis: 1 }, 'hid', { value: 2, enumerable: false });
console.log(JSON.stringify(Object.getOwnPropertyNames(structuredClone(hidden))));
const sym = Symbol('s'); const withSym = { [sym]: 1, k: 2 }; const ws = structuredClone(withSym); console.log(ws[sym], ws.k);
const u8 = new Uint8Array([1, 2, 3]); const u8c = structuredClone(u8);
console.log(u8c instanceof Uint8Array, u8c.length, u8c[2], u8c.buffer !== u8.buffer);
u8c[0] = 9; console.log(u8[0]);
const ab = new ArrayBuffer(4); new Uint8Array(ab)[0] = 9; const abc = structuredClone(ab);
console.log(abc instanceof ArrayBuffer, abc.byteLength, new Uint8Array(abc)[0]);
const view = new Uint8Array(ab, 1, 2); const pair = structuredClone({ ab, view });
console.log(pair.view.buffer === pair.ab, pair.view.byteOffset, pair.view.length);
const dv = new DataView(new ArrayBuffer(8), 2, 4); const dvc = structuredClone(dv); console.log(Object.prototype.toString.call(dvc), dvc.byteOffset, dvc.byteLength, dvc.buffer.byteLength);
const f32 = structuredClone(new Float64Array([1.5, -2])); console.log(f32[0], f32[1], f32.length);
console.log(structuredClone(5), structuredClone('s'), structuredClone(null), structuredClone(undefined), structuredClone(10n), structuredClone(true));
console.log(Object.is(structuredClone(-0), -0), Number.isNaN(structuredClone(NaN)));
console.log(typeof structuredClone, structuredClone.length, structuredClone.name);
const box = structuredClone(new Number(3)); console.log(typeof box, box instanceof Number, box.valueOf());
const sbox = structuredClone(new String('ab')); console.log(typeof sbox, sbox.valueOf(), sbox.length);
const clone = structuredClone; console.log(clone([1, [2]])[1][0]);
const nested = structuredClone({ inner: [new Map([[{ a: 1 }, new Set([new Date(0)])]])] });
const [k, v] = [...nested.inner[0]][0]; console.log(k.a, v.size, [...v][0].getTime());
for (const bad of [() => 1, Symbol('q'), { f() {} }, new WeakMap(), new WeakSet(), Promise.resolve(1), new Proxy({}, {})]) {
  try { structuredClone(bad); console.log('cloned'); } catch (err) { console.log(err.name, typeof bad === 'function' || typeof bad.f === 'function' ? '(function source)' : err.message, err.code, err instanceof Error); }
}
try { structuredClone(); } catch (err) { console.log(err.name, err.code, err.message); }
let deep = []; let cur = deep; for (let i = 0; i < 999; i++) { const next = []; cur.push(next); cur = next; }
let dc2 = structuredClone(deep); let depth = 0; while (dc2.length) { dc2 = dc2[0]; depth++; } console.log(depth);"#;

/// Node v22.2.0's output for `PROGRAM`.
const NODE_OUTPUT: &str = r#"{"a":1,"b":"x","c":[1,2,{"d":true}],"n":null} true true true true
true true true root
true true
true 3 a 2 true
true true true
true 3 3
true 1700000000000 true true
true ab+c gi 0 true true
true TypeError bad true undefined true
Error m false true
true 3 false x 3
6 5
false true {"v":1}
{"x":"got"}
["vis"]
undefined 2
true 3 3 true
1
true 4 9
true 1 2
[object DataView] 2 4 8
1.5 -2 2
5 s null undefined 10n true
true true
function 0 structuredClone
object true 3
object ab 2
2
1 1 0
DataCloneError (function source) 25 true
DataCloneError Symbol(q) could not be cloned. 25 true
DataCloneError (function source) 25 true
DataCloneError #<WeakMap> could not be cloned. 25 true
DataCloneError #<WeakSet> could not be cloned. 25 true
DataCloneError #<Promise> could not be cloned. 25 true
DataCloneError #<Object> could not be cloned. 25 true
TypeError ERR_MISSING_ARGS The value argument must be specified
999"#;

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "structured-clone.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "structured-clone.js"),
        &LoweringContext::new("clone-trace", "clone-decision", "clone-policy"),
    )
    .map_err(|error| format!("lower: {error:?}"))?
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "structured-clone");
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift"
    );
    let result = result.map_err(|error| format!("execute: {error:?}"))?;
    Ok(result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n"))
}

#[test]
fn structured_clone_matches_node() {
    let output = console_output(PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}
