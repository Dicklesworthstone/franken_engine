//! Async and callable semantics on the shipped `frankenctl run` path, compared
//! with Node v22.2.0's console output for each program.
//!
//! - bd-9vouw.26: an async function ran inline on its caller's stack, so a
//!   settled `await` continued synchronously (`a,b,c` instead of `a,c,b`) and a
//!   pending `await` froze every caller frame until the Promise settled.
//! - bd-9vouw.30: timers silently dropped builtin, async and generator
//!   callbacks, so `await new Promise(r => setTimeout(r, ms))` never resolved.
//! - bd-6vl81: object-literal and class `async`/generator methods were rejected
//!   by the parser or installed under a key like `"async m"`.
//! - bd-9vouw.35: computed class member keys (`[k](){}`) were installed under a
//!   static fallback key instead of the evaluated property key.
//! - bd-9vouw.33: Map/Set `keys`/`values`/`entries`/`forEach` were missing.
//! - bd-9vouw.38: an Error thrown in a Promise handler reached the next
//!   handler as its stringified message.
//! - bd-9vouw.40: `String.prototype.split` ignored its limit.
//! - bd-9vouw.39: `Promise.prototype.finally` was `then(cb, cb)`, which
//!   swallowed rejections and replaced the settled value.
//! - bd-9vouw.37 (partial): `+` and template substitutions now run a guest
//!   `toString` / `valueOf` / `@@toPrimitive`; arithmetic, relational
//!   operators and `Array.prototype.join` still do not.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type Case = (&'static str, &'static str, &'static [&'static str]);

const AWAIT_CASES: &[Case] = &[
    (
        "settled_await_defers",
        "(async()=>{ console.log('a'); await null; console.log('b') })(); console.log('c');",
        &["a", "c", "b"],
    ),
    (
        "await_resolved_promise_defers",
        "(async()=>{ console.log('a'); await Promise.resolve(1); console.log('b') })(); console.log('c');",
        &["a", "c", "b"],
    ),
    (
        "declared_async_await_value",
        "async function f(){ console.log('a'); const v = await 1; console.log('b', v) } f(); console.log('c');",
        &["a", "c", "b 1"],
    ),
    (
        "pending_await_returns_to_caller",
        "(async()=>{ console.log('a'); const v = await new Promise(r=>setTimeout(()=>r(7),0)); console.log('b', v) })(); console.log('c');",
        &["a", "c", "b 7"],
    ),
    (
        "nested_async_calls",
        "async function f(){ await new Promise(r=>setTimeout(()=>r(),0)); return 5 } (async()=>{ const v = await f(); console.log('v', v) })(); console.log('s');",
        &["s", "v 5"],
    ),
    (
        "await_in_loop",
        "(async()=>{ for (let i=0;i<3;i++){ await new Promise(r=>setTimeout(()=>r(),0)); console.log('i', i) } console.log('done') })(); console.log('sync');",
        &["sync", "i 0", "i 1", "i 2", "done"],
    ),
    (
        "interleaved_microtasks",
        "const log=[]; setTimeout(()=>{log.push('timeout'); console.log(log.join(','))},0); Promise.resolve().then(()=>log.push('p1')).then(()=>log.push('p2')); (async()=>{log.push('a0'); await null; log.push('a1');})(); log.push('sync');",
        &["a0,sync,p1,a1,p2,timeout"],
    ),
    (
        "two_async_interleave",
        "async function t(n){ console.log(n, 1); await null; console.log(n, 2); await null; console.log(n, 3) } t('x'); t('y'); console.log('main');",
        &["x 1", "y 1", "main", "x 2", "y 2", "x 3", "y 3"],
    ),
    (
        "await_rejection_catchable",
        "(async()=>{ try { await Promise.reject(new Error('no')) } catch(e) { console.log('c', e.message) } console.log('end') })(); console.log('s');",
        &["s", "c no", "end"],
    ),
    // Already correct before the fix; guards for the rerouted call paths.
    (
        "sync_throw_rejects_promise",
        "async function f(){ throw new Error('early') } f().catch(e=>console.log('caught', e.message)); console.log('after');",
        &["after", "caught early"],
    ),
    (
        "return_value_resolves",
        "async function f(){ await null; return 42 } f().then(v=>console.log('v', v)); console.log('s');",
        &["s", "v 42"],
    ),
    (
        "async_arrow_lexical_this",
        "function C(){ this.k = 9; const f = async()=>{ await null; return this.k }; f().then(v=>console.log('k', v)) } new C(); console.log('s');",
        &["s", "k 9"],
    ),
    (
        "async_callback_from_then",
        "Promise.resolve(1).then(async v=>{ await null; console.log('cb', v) }); console.log('s');",
        &["s", "cb 1"],
    ),
];

const TIMER_CASES: &[Case] = &[
    (
        "resolve_function_as_timer_callback",
        "new Promise(r=>setTimeout(r,0)).then(()=>console.log('done'));",
        &["done"],
    ),
    (
        "sleep_idiom",
        "(async()=>{ const sleep = ms => new Promise(r => setTimeout(r, ms)); console.log('a'); await sleep(5); console.log('b') })();",
        &["a", "b"],
    ),
    (
        "builtin_callback_with_arguments",
        "setTimeout(console.log, 0, 'direct');",
        &["direct"],
    ),
    (
        "async_timer_callback",
        "setTimeout(async()=>{ console.log('t1'); await null; console.log('t2') },0); console.log('s');",
        &["s", "t1", "t2"],
    ),
    (
        "builtin_immediate_callback",
        "setImmediate(console.log, 'imm'); console.log('s');",
        &["s", "imm"],
    ),
    (
        "builtin_interval_reschedules_and_clears",
        "const id = setInterval(console.log, 10, 'tick'); setTimeout(()=>clearInterval(id), 25);",
        &["tick", "tick"],
    ),
];

const METHOD_FORM_CASES: &[Case] = &[
    (
        "object_async_and_generator_methods",
        "const o={ async m(){ await null; return 1 }, *g(){ yield 2; yield 3 }, async *h(){ yield 4 } }; o.m().then(v=>console.log('m', v)); console.log([...o.g()].join()); o.h().next().then(r=>console.log('h', r.value));",
        &["2,3", "m 1", "h 4"],
    ),
    (
        "class_async_and_generator_methods",
        "class A { constructor(){ this.n = 5 } async m(){ await null; return this.n } *g(){ yield this.n } static async s(){ return 'S' } async(){ return 'named' } } const a = new A(); a.m().then(v=>console.log('m', v)); console.log([...a.g()].join(), a.async()); A.s().then(v=>console.log('s', v));",
        &["5 named", "s S", "m 5"],
    ),
];

const COMPUTED_CLASS_KEY_CASES: &[Case] = &[(
    "computed_class_member_keys",
    "const log=[]; const k=Symbol('k'); const key=(s)=>{ log.push(s); return s }; class C { [k](){ return 'sym' } [key('m'+1)](){ return 'computed' } static [key('s')](){ return 'static' } get [key('g')](){ return 'getter' } } const c=new C(); console.log(c[k](), c.m1(), C.s(), c.g, log.join());",
    &["sym computed static getter m1,s,g"],
)];

const COLLECTION_METHOD_CASES: &[Case] = &[
    (
        "map_and_set_iterators",
        "const m=new Map([['b',1],['a',2]]); console.log([...m.keys()].join(), [...m.values()].join(), [...m.entries()].map(e=>e.join(':')).join(), Array.from(m.values()).join()); const s=new Set(['x','y']); console.log([...s.values()].join(), [...s.keys()].join(), [...s.entries()].map(e=>e.join(':')).join());",
        &["b,a 1,2 b:1,a:2 1,2", "x,y x,y x:x,y:y"],
    ),
    (
        "map_and_set_for_each",
        "const m=new Map([['b',1],['a',2]]); const s=new Set(['x','y']); const log=[]; m.forEach(function(v,k,c){ log.push(k+'='+v+(c===m)+this.t) }, {t:'!'}); s.forEach((v,k)=>log.push(v+k)); console.log(log.join()); const d=new Map([[1,1],[2,2],[3,3]]); const seen=[]; d.forEach((v,k)=>{ seen.push(k); if (k===1) d.delete(2) }); console.log(seen.join());",
        &["b=1true!,a=2true!,xx,yy", "1,3"],
    ),
];

const PROMISE_HANDLER_THROW_CASES: &[Case] = &[(
    "handler_throws_keep_the_thrown_object",
    "const err=new Error('x'); Promise.resolve().then(()=>{ throw err }).catch(e=>console.log('caught', e.message, typeof e, e===err, e instanceof Error)); Promise.reject(new TypeError('t')).catch(e=>{ throw e }).catch(e=>console.log('rethrown', e.name, e.message));",
    &["caught x object true true", "rethrown TypeError t"],
)];

const STRING_SPLIT_LIMIT_CASES: &[Case] = &[(
    "split_limit",
    "console.log(JSON.stringify(['a,b,c'.split(',', 2), 'a,b'.split(',', 0), 'a,b'.split(',', NaN), 'a,b'.split(',', -1), 'abc'.split('', 2), 'a,b'.split(undefined, 0), 'a,b,c'.split(',', '2')]))",
    &[r#"[["a","b"],[],[],["a","b"],["a","b"],[],["a","b"]]"#],
)];

const PROMISE_FINALLY_CASES: &[Case] = &[
    (
        "finally_keeps_rejection",
        "Promise.reject(new Error('e')).finally(()=>console.log('cleanup')).catch(e=>console.log('caught', e.message)).then(()=>console.log('end'));",
        &["cleanup", "caught e", "end"],
    ),
    (
        "finally_keeps_value",
        "Promise.resolve(1).finally(()=>console.log('fin')).then(v=>console.log('v', v));",
        &["fin", "v 1"],
    ),
    (
        "finally_throw_rejects",
        "Promise.resolve(1).finally(()=>{ throw new Error('f') }).catch(e=>console.log('caught', e.message));",
        &["caught f"],
    ),
    (
        "finally_waits_for_returned_promise",
        "Promise.resolve(2).finally(()=>new Promise(r=>setTimeout(r,5))).then(v=>console.log('after delay', v));",
        &["after delay 2"],
    ),
    (
        "finally_returned_rejection_wins",
        "Promise.resolve(3).finally(()=>Promise.reject(new Error('rf'))).catch(e=>console.log('rejected by finally', e.message));",
        &["rejected by finally rf"],
    ),
    (
        "finally_non_callable_passes_through",
        "Promise.resolve(4).finally(5).then(v=>console.log('passthrough', v)); Promise.reject(new Error('r4')).finally().catch(e=>console.log('passthrough reject', e.message));",
        &["passthrough 4", "passthrough reject r4"],
    ),
];

const TO_PRIMITIVE_CASES: &[Case] = &[
    (
        "class_to_string_in_concat_and_template",
        "class P { constructor(n){ this.n=n } toString(){ return 'P(' + this.n + ')' } } const p=new P(1); console.log('x' + p, `${p}`, String(p));",
        &["xP(1) P(1) P(1)"],
    ),
    (
        "value_of_versus_to_string_hints",
        "const o={valueOf(){return 5}, toString(){return 'S'}}; console.log(o+1, `${o}`, ''+o);",
        &["6 S 5"],
    ),
    (
        "symbol_to_primitive_hints",
        "const t={[Symbol.toPrimitive](h){ return h==='number'? 42 : h }}; console.log(`${t}`, t+'');",
        &["string default"],
    ),
    (
        "engine_objects_keep_default_conversion",
        "console.log('x'+{}, [1,2]+'', {}+1, [1]+1);",
        &["x[object Object] 1,2 [object Object]1 11"],
    ),
    (
        "conversion_throw_is_catchable",
        "const b={toString(){ throw new Error('no') }}; try { ''+b } catch(e) { console.log('caught', e.message) } try { `${b}` } catch(e) { console.log('caught tpl', e.message) }",
        &["caught no", "caught tpl no"],
    ),
    (
        "class_value_of_addition",
        "class M{constructor(v){this.v=v} valueOf(){return this.v}} console.log(new M(3)+new M(4), new M(2)+'!');",
        &["7 2!"],
    ),
];

fn run(dir: &PathBuf, id: &str, source: &str) -> Result<Vec<String>, String> {
    let input = dir.join(format!("{id}.js"));
    let report = dir.join(format!("{id}.run.json"));
    fs::write(&input, source).expect("write case");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8"),
            "--extension-id",
            "async-callable-semantics",
            "--instruction-budget",
            "10000000",
            "--out",
            report.to_str().expect("utf8"),
        ])
        .output()
        .expect("frankenctl should execute");
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
    Ok(report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .map(|entry| entry["message"].as_str().unwrap_or_default().to_string())
        .collect())
}

fn assert_matches_node(group: &str, cases: &[Case]) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_{group}_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("temp dir");

    let mut problems = Vec::new();
    for (id, source, node) in cases {
        match run(&dir, id, source) {
            Ok(lines) if lines == *node => {}
            Ok(lines) => problems.push(format!("{id}: got {lines:?}, Node prints {node:?}")),
            Err(stderr) => problems.push(format!(
                "{id}: frankenctl failed: {}",
                stderr
                    .lines()
                    .find(|line| line.contains("failed for"))
                    .or_else(|| stderr.lines().last())
                    .unwrap_or_default()
            )),
        }
    }
    assert!(
        problems.is_empty(),
        "{group}: programs diverge from Node:\n{}",
        problems.join("\n")
    );
}

#[test]
fn await_parks_only_its_own_activation_bd_9vouw_26() {
    assert_matches_node("await", AWAIT_CASES);
}

#[test]
fn timers_run_every_callable_callback_bd_9vouw_30() {
    assert_matches_node("timers", TIMER_CASES);
}

#[test]
fn async_and_generator_method_forms_run_bd_6vl81() {
    assert_matches_node("method_forms", METHOD_FORM_CASES);
}

#[test]
fn computed_class_member_keys_are_evaluated_bd_9vouw_35() {
    assert_matches_node("computed_class_keys", COMPUTED_CLASS_KEY_CASES);
}

#[test]
fn map_and_set_iteration_methods_bd_9vouw_33() {
    assert_matches_node("collection_methods", COLLECTION_METHOD_CASES);
}

#[test]
fn promise_handler_throws_keep_the_thrown_value_bd_9vouw_38() {
    assert_matches_node("promise_handler_throws", PROMISE_HANDLER_THROW_CASES);
}

#[test]
fn string_split_honors_limit_bd_9vouw_40() {
    assert_matches_node("string_split_limit", STRING_SPLIT_LIMIT_CASES);
}

#[test]
fn promise_finally_passes_settlement_through_bd_9vouw_39() {
    assert_matches_node("promise_finally", PROMISE_FINALLY_CASES);
}

#[test]
fn addition_and_templates_run_guest_conversions_bd_9vouw_37() {
    assert_matches_node("to_primitive", TO_PRIMITIVE_CASES);
}
