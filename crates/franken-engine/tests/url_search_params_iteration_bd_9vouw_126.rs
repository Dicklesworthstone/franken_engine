//! bd-9vouw.126: URLSearchParams iterates.
//!
//! `[...new URLSearchParams('a=1&b=2')]`, `sp.keys()` and
//! `for (const [k, v] of sp)` threw: `typeof sp.keys` was "undefined".
//! keys, values, entries, forEach and @@iterator (entries) now exist.
//! PROGRAM covers spread, the three iterators, for-of with destructuring,
//! forEach with thisArg and the params argument, a pair appended during
//! forEach (visited, as Node reads the list live), the wrong-receiver and
//! non-callable TypeErrors (with `typeof` of the method on the same line, so
//! a missing method cannot pass as the expected TypeError), and Array.from /
//! new Map / Object.fromEntries over params. NODE_OUTPUT is Node v22.2.0's
//! output.
//!
//! No-claim: keys/values/entries iterate the pairs present when they were
//! called. Node's iterators are live, so a pair appended after creating an
//! iterator is visited in Node and not here. `URLSearchParams` is still not
//! a global value (only `new URLSearchParams(...)` lowers), so
//! URLSearchParams.prototype is not reachable to read methods from.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"const sp = new URLSearchParams('a=1&b=2&a=3');
console.log([...sp].map(function (pair) { return pair.join('='); }).join('&'), [...sp.keys()].join(), [...sp.values()].join(), JSON.stringify([...sp.entries()]));
const seen = []; for (const [k, v] of sp) { seen.push(k + v); } console.log(seen.join(' '));
const out = []; sp.forEach(function (value, name, params) { out.push(name + ':' + value + ':' + (params === sp) + ':' + this.tag); }, { tag: 't' }); console.log(out.join(' '));
console.log(typeof sp[Symbol.iterator], typeof sp.keys().next, JSON.stringify(sp.keys().next()), JSON.stringify(new URLSearchParams('').keys().next()));
const live = new URLSearchParams('x=1'); const visited = []; live.forEach(function (v, k) { visited.push(k); if (visited.length === 1) { live.append('y', '2'); } }); console.log(visited.join());
const keys = sp.keys; try { keys.call({}); } catch (e) { console.log('keys on a plain object', typeof keys, e instanceof TypeError); }
try { sp.forEach(5); } catch (e) { console.log('non-callable', typeof sp.forEach, e instanceof TypeError); }
console.log(Array.from(new URLSearchParams('p=q&r=s')).join('|'), new Map(new URLSearchParams('m=1&n=2')).get('n'), Object.fromEntries(new URLSearchParams('k=v&k2=v2')).k2);"#;

const NODE_OUTPUT: &str = r#"a=1&b=2&a=3 a,b,a 1,2,3 [["a","1"],["b","2"],["a","3"]]
a1 b2 a3
a:1:true:t b:2:true:t a:3:true:t
function function {"value":"a","done":false} {"done":true}
x,y
keys on a plain object function true
non-callable function true
p,q|r,s 2 v2"#;

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "url-search-params-iteration.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "url-search-params-iteration.js"),
        &LoweringContext::new("usp-trace", "usp-decision", "usp-policy"),
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
    let mut core = InterpreterCore::new(config, "url-search-params-iteration");
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
fn url_search_params_iteration_matches_node() {
    let output = console_output(PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}
