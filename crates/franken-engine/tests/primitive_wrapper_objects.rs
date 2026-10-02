//! Primitive wrapper objects (bd-9vouw.73, bd-9vouw.48).
//!
//! `Object(primitive)` failed ("boxing primitives through Object() is not
//! supported yet") and `new Number(x)` / `new String(x)` / `new Boolean(x)`
//! returned primitives (typeof "number"). A wrapper is now an object whose
//! prototype is its type's and whose engine-private slot holds the
//! primitive: the prototype methods unwrap it (thisNumberValue and
//! friends), conversions and JSON see the primitive, a String wrapper has
//! its indices and length as own properties, Object.prototype.toString
//! reports its tag, and console.log prints it like Node (`[Number: 3]`).
//! lodash's baseGetTag (`symToStringTag in Object(value)`) and the common
//! `var O = Object(this)` polyfill shape need it.
//!
//! Each program runs through the parser, the lowering and the interpreter;
//! the expected line is what Node v22.2.0 prints for the same program
//! (`node -e`). Every run also checks the memory-accounting invariant.

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
        "object_number",
        r#"const o = Object(1); console.log(typeof o, o instanceof Number, o + 1, o * 2, o == 1, o === 1, String(o), `${o}`);"#,
        "object true 2 2 true false 1 1",
    ),
    (
        "object_string",
        r#"const o = Object('ab'); console.log(typeof o, o.length, o[1], o[2], o + 'c', o.toUpperCase(), o == 'ab', o instanceof String);"#,
        "object 2 b undefined abc AB true true",
    ),
    (
        "object_boolean",
        r#"const o = Object(false); console.log(typeof o, o ? 'truthy' : 'falsy', o.valueOf(), String(o), o instanceof Boolean);"#,
        "object truthy false false true",
    ),
    (
        "new_number",
        r#"const n = new Number(3); console.log(typeof n, n.valueOf(), +n, n + 1, n.toFixed(2), n.toString(2), JSON.stringify(n), JSON.stringify({ n }));"#,
        r#"object 3 3 4 3.00 11 3 {"n":3}"#,
    ),
    (
        "new_string",
        r#"const s = new String('hi'); console.log(typeof s, s.length, s[0], s + '!', s.charAt(1), s.slice(0, 1), JSON.stringify([s]), s.valueOf() === 'hi');"#,
        r#"object 2 h hi! i h ["hi"] true"#,
    ),
    (
        "new_boolean",
        r#"const b = new Boolean(false); console.log(typeof b, b ? 'truthy' : 'falsy', b.valueOf(), b.toString(), JSON.stringify({ b }), !b);"#,
        r#"object truthy false false {"b":false} false"#,
    ),
    (
        "called_constructors_stay_primitive",
        r#"console.log(typeof Number('4'), typeof String(5), typeof Boolean(0), Number('4') + 1);"#,
        "number string boolean 5",
    ),
    (
        "wrapper_identity",
        r#"const a = new Number(1), b = new Number(1); console.log(a == b, a === a, a == 1, new String('x') == 'x', Object(a) === a);"#,
        "false true true true true",
    ),
    (
        "to_string_tags",
        r#"const t = x => Object.prototype.toString.call(x); console.log(t(Object(1)), t(new Boolean(true)), t(Object('')), t(Object(1n)), t(new String('q')));"#,
        "[object Number] [object Boolean] [object String] [object BigInt] [object String]",
    ),
    (
        "in_and_own",
        r#"const s = new String('ab'); console.log('length' in s, 0 in s, 2 in s, 'x' in Object(1), 'toFixed' in Object(1), s.hasOwnProperty('0'), s.hasOwnProperty('length'), s.hasOwnProperty('charAt'));"#,
        "true true false false true true true false",
    ),
    (
        "bigint_and_symbol_wrappers",
        r#"const b = Object(5n); const y = Object(Symbol('q')); console.log(typeof b, b + 1n, b.toString(), typeof y, y.toString());"#,
        "object 6n 5 object Symbol(q)",
    ),
    (
        "console_format",
        r#"const n = new Number(5); n.extra = 1; console.log(new Number(3), new String('ab'), [Object(true)], n);"#,
        "[Number: 3] [String: 'ab'] [ [Boolean: true] ] [Number: 5] { extra: 1 }",
    ),
    (
        "lodash_base_get_tag",
        r#"const symToStringTag = Symbol.toStringTag; const toStr = Object.prototype.toString; function baseGetTag(value) { if (value == null) { return value === undefined ? '[object Undefined]' : '[object Null]'; } return (symToStringTag && symToStringTag in Object(value)) ? 'raw' : toStr.call(value); } console.log(baseGetTag(1), baseGetTag('s'), baseGetTag(true), baseGetTag({}), baseGetTag(null));"#,
        "[object Number] [object String] [object Boolean] [object Object] [object Null]",
    ),
    (
        "polyfill_object_this",
        r#"function find(pred) { var O = Object(this); var len = O.length >>> 0; for (var i = 0; i < len; i++) { if (pred(O[i])) return O[i]; } } console.log(find.call('abc', c => c > 'a'), find.call([1, 5, 9], x => x > 3));"#,
        "b 5",
    ),
    (
        "new_object_primitive",
        r#"const o = new Object('z'); console.log(typeof o, o.length, String(o));"#,
        "object 1 z",
    ),
    (
        "wrapper_properties",
        r#"const n = new Number(7); n.label = 'seven'; console.log(n.label, Object.keys(n).join(), n + 0);"#,
        "seven label 7",
    ),
    (
        "string_keys_values_entries",
        r#"console.log(JSON.stringify(Object.keys('ab')), JSON.stringify(Object.values('ab')), JSON.stringify(Object.entries('ab')));"#,
        r#"["0","1"] ["a","b"] [["0","a"],["1","b"]]"#,
    ),
    (
        "string_wrapper_enumeration",
        r#"const s = new String('xy'); s.extra = 1; console.log(Object.keys(s).join(), Object.values(s).join(), JSON.stringify(Object.entries(s)));"#,
        r#"0,1,extra x,y,1 [["0","x"],["1","y"],["extra",1]]"#,
    ),
    (
        "for_in_primitives",
        r#"const a = []; for (const k in 'abc') a.push(k); const b = []; for (const k in 7) b.push(k); const c = []; for (const k in new String('q')) c.push(k); console.log(a.join(), b.length, c.join());"#,
        "0,1,2 0 0",
    ),
    (
        "number_methods_reject_other_receivers",
        r#"const r = []; const b = new Boolean(); b.v = Number.prototype.valueOf; for (const f of [() => b.v(), () => Number.prototype.valueOf.call({}), () => Number.prototype.toString.call('x'), () => Number.prototype.valueOf.call(new Number(5)), () => Number.prototype.toString.call(new Number(255), 16)]) { try { r.push(String(f())); } catch (e) { r.push(e.constructor.name); } } console.log(r.join());"#,
        "TypeError,TypeError,TypeError,5,ff",
    ),
    // A computed member key that is an object goes through ToPropertyKey
    // (its toString runs, preferred over valueOf); `o[k]` read the key
    // "[object#13]", the object's heap id, for get, set, `in` and delete.
    (
        "object_property_keys",
        r#"var k = { toString() { return 'key'; } }; var o = {}; o[k] = 1; var a = {}; a[{}] = 2; var d = new Date(0); var c = {}; c[d] = 'd'; var both = { toString() { return 'ts'; }, valueOf() { return 'vo'; } }; c[both] = 3; var has = k in o; delete o[k]; console.log(Object.keys(a).join(), has, 'key' in o, Object.keys(c).length, c[d], c.ts, c[both]);"#,
        "[object Object] true false 2 d 3 3",
    ),
    // A null or undefined base throws before an object key's toString runs
    // (EvaluatePropertyAccessWithExpressionKey: RequireObjectCoercible, then
    // ToPropertyKey), and so does a non-object `in` operand (Test262
    // compound-assignment S11.13.2_A7.*).
    (
        "member_base_checked_before_key",
        r#"const log = []; const key = { toString() { log.push('key'); return 'k'; } }; const r = []; try { null[key]; } catch (e) { r.push(e.constructor.name); } try { undefined[key] = 1; } catch (e) { r.push(e.constructor.name); } try { key in 5; } catch (e) { r.push(e.constructor.name); } try { delete null[key]; } catch (e) { r.push(e.constructor.name); } let base = null; try { base[key] &= 1; } catch (e) { r.push(e.constructor.name); } r.push(log.length, ({ k: 1 })[key], key in { k: 1 }); console.log(r.join(' '));"#,
        "TypeError TypeError TypeError TypeError TypeError 0 1 true",
    ),
    // A String.prototype method ToStrings an object `this` (its toString,
    // else valueOf, runs) and concat ToStrings object arguments; both read
    // "[object Object]".
    (
        "string_methods_on_object_this",
        r#"var o = { toString() { return 'Ab-c'; } }; var S = String.prototype; console.log(S.toUpperCase.call(o), S.split.call(o, '-').join('|'), S.slice.call(o, 1), S.indexOf.call(o, 'c'), S.trim.call(o), S.padStart.call(o, 6, '*'), S.includes.call(o, 'b'), S.charAt.call(o, 0), S.at.call(o, -1));"#,
        "AB-C Ab|c b-c 3 Ab-c **Ab-c true A c",
    ),
    (
        "string_method_this_value_of",
        r#"var o = { toString: undefined, valueOf() { return 'vv'; } }; console.log(String.prototype.toUpperCase.call(o), String(o), o + '');"#,
        "VV vv vv",
    ),
    (
        "string_concat_object_arguments",
        r#"var n = 0; var o2 = { toString() { n++; return 'x'; } }; String.prototype.concat.call(o2, o2); console.log(n, 'a'.concat(o2, 1));"#,
        "2 ax1",
    ),
    // Number.prototype, String.prototype and Boolean.prototype are wrapper
    // objects of +0, "" and false: `Number.prototype.toString(10)` was
    // "expected Number receiver, got object" (Test262 Number/prototype/
    // toString/S15.7.4.2_A1_T02 and relatives).
    (
        "builtin_prototypes_are_wrappers",
        r#"console.log(Number.prototype.toString(10), Number.prototype.toString(36), Number.prototype.valueOf(), String.prototype.valueOf() === '', String.prototype.length, Boolean.prototype.valueOf(), Object.prototype.toString.call(Number.prototype), Object.prototype.toString.call(String.prototype), Object.prototype.toString.call(Boolean.prototype), Number.prototype + 1, JSON.stringify([Number.prototype, String.prototype, Boolean.prototype]), Number.prototype.toFixed(2), JSON.stringify(String.prototype.toUpperCase()));"#,
        r#"0 0 0 true 0 false [object Number] [object String] [object Boolean] 1 [0,"",false] 0.00 """#,
    ),
];
fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "wrapper.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "wrapper.js"),
        &LoweringContext::new("wrapper-trace", "wrapper-decision", "wrapper-policy"),
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
    let mut core = InterpreterCore::new(config, "wrapper");
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
fn primitive_wrapper_objects_match_node() {
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
