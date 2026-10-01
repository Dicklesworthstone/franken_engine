//! `Proxy` is a first-class constructor value.
//!
//! `new Proxy(t, h)` worked (intercepted at lowering), but a bare `Proxy`
//! had no binding: `typeof Proxy` was "undefined", so libraries that feature
//! detect it (immer, Vue, MobX) took their no-Proxy paths, and the
//! constructor could not be stored or passed. Expected lines are Node
//! v22.2.0's for the same programs (`node -e`).

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

/// (name, program, Node v22.2.0 output)
const CASES: &[(&str, &str, &str)] = &[
    (
        "typeof_and_alias",
        r#"const P = Proxy; const p = new P({}, { get: (t, k) => k + '!' }); console.log(typeof Proxy, p.hello, typeof P);"#,
        "function hello! function",
    ),
    (
        "name_length_prototype",
        r#"console.log(Proxy.name, Proxy.length, Proxy.prototype);"#,
        "Proxy 2 undefined",
    ),
    (
        "revocable_through_alias",
        r#"const P = Proxy; const r = P.revocable({ a: 1 }, {}); console.log(r.proxy.a); r.revoke(); let threw = false; try { r.proxy.a; } catch (e) { threw = e instanceof TypeError; } console.log(threw);"#,
        "1\ntrue",
    ),
    (
        "feature_detection",
        r#"const hasProxy = typeof Proxy !== 'undefined' && typeof Proxy === 'function'; console.log(hasProxy ? 'proxy' : 'fallback');"#,
        "proxy",
    ),
    (
        "called_without_new_throws",
        r#"try { Proxy({}, {}); console.log('no throw'); } catch (e) { console.log(e instanceof TypeError); }"#,
        "true",
    ),
];
fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "proxy.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "proxy.js"),
        &LoweringContext::new("proxy-trace", "proxy-decision", "proxy-policy"),
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
    let mut core = InterpreterCore::new(config, "proxy");
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift: {source}"
    );
    let result = result.map_err(|error| format!("{error:?}"))?;
    Ok(result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n"))
}

#[test]
fn proxy_constructor_value_matches_node() {
    let mut mismatches = Vec::new();
    for (name, source, node) in CASES {
        match console_output(source) {
            Ok(output) if output == *node => {}
            other => mismatches.push(format!("{name}: node {node:?}, got {other:?}")),
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} programs differ from Node:\n{}",
        mismatches.len(),
        CASES.len(),
        mismatches.join("\n")
    );
}

/// Array.prototype methods on a Proxy of an array run over its traps
/// (ES2020 23.1.3): they read and write the target through [[Get]]/[[Set]]/
/// [[HasProperty]]/[[Delete]]. They used the receiver's own element storage,
/// which a proxy lacks: `push` changed nothing, `map` gave [], `indexOf` -1
/// and `Array.isArray(proxy)` false (immer drafts, reactive arrays).
/// (name, program, Node v22.2.0 output)
const ARRAY_CASES: &[(&str, &str, &str)] = &[
    (
        "push_through_traps",
        r#"const target = [1, 2]; const log = []; const p = new Proxy(target, { get(t, k, r) { log.push('get:' + String(k)); return Reflect.get(t, k, r); }, set(t, k, v, r) { log.push('set:' + String(k)); return Reflect.set(t, k, v, r); } }); p.push(3); console.log(target.join() + ' ' + log.join());"#,
        "1,2,3 get:push,get:length,set:2,set:length",
    ),
    (
        "reading_methods",
        r#"const q = new Proxy([3, 1, 2], {}); console.log([q.map((x) => x * 2).join(), q.indexOf(1), Array.isArray(q), q.slice(1).join(), q.includes(2), q.join('-'), q.filter((x) => x > 1).join(), q.reduce((a, b) => a + b, 0), q.find((x) => x < 3), q.findIndex((x) => x === 2), q.some((x) => x > 2), q.every((x) => x > 0), String(q), q.at(-1)].join('|'));"#,
        "6,2,4|1|true|1,2|true|3-1-2|3,2|6|1|2|true|true|3,1,2|2",
    ),
    (
        "sort_and_reverse_in_place",
        r#"const r = new Proxy([5, 3, 4, 1], {}); r.sort(); r.reverse(); console.log(r.join() + ' ' + r.length);"#,
        "5,4,3,1 4",
    ),
    (
        "splice",
        r#"const s = new Proxy([1, 2, 3, 4, 5], {}); const removed = s.splice(1, 2, 'a', 'b', 'c'); console.log(removed.join() + ' ' + s.join() + ' ' + s.length);"#,
        "2,3 1,a,b,c,4,5 6",
    ),
    (
        "unshift_pop_shift",
        r#"const u = new Proxy([2], {}); u.unshift(0, 1); console.log(u.pop() + ' ' + u.shift() + ' ' + u.join() + ' ' + u.length);"#,
        "2 0 1 1",
    ),
    (
        "iteration_and_concat",
        r#"console.log([...new Proxy(['x', 'y'], {})].join() + ' ' + Array.from(new Proxy([7, 8], {}).entries()).join(';') + ' ' + [].concat(new Proxy([1, 2], {}), 3).join());"#,
        "x,y 0,7;1,8 1,2,3",
    ),
    (
        "is_array_and_copying_methods",
        r#"console.log(Array.isArray(Array.prototype) + ' ' + Array.isArray(new Proxy({}, {})) + ' ' + new Proxy([1, 2, 3], {}).toSorted((a, b) => b - a).join() + ' ' + new Proxy([1, 2], {}).with(0, 9).join() + ' ' + new Proxy([1, 2], {}).fill(0).join());"#,
        "true false 3,2,1 9,2 0,0",
    ),
];

#[test]
fn array_methods_run_through_proxy_traps() {
    let mut mismatches = Vec::new();
    for (name, source, node) in ARRAY_CASES {
        match console_output(source) {
            Ok(output) if output == *node => {}
            other => mismatches.push(format!("{name}: node {node:?}, got {other:?}")),
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} programs differ from Node:\n{}",
        mismatches.len(),
        ARRAY_CASES.len(),
        mismatches.join("\n")
    );
}
