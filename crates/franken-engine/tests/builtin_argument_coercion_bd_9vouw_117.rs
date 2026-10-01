//! bd-9vouw.117: builtins convert object arguments through ToPrimitive.
//!
//! String, Array, Number and BigInt builtins converted a numeric or string
//! argument without calling the object's valueOf/toString:
//! `'abc'.indexOf({ toString() { return 'b' } })` was -1 (Node 1),
//! `'ab'.repeat({ valueOf() { return 2 } })` was '', and
//! `[1, 2, 3].slice({ valueOf() { return 1 } })` returned the whole array.
//! PROGRAM covers the String search and position arguments, padStart's
//! fill, the Array index arguments, Number digits and radix, BigInt radix,
//! argument conversion order, Symbol and BigInt arguments (TypeError), and a
//! throwing valueOf/toString propagating. It also covers lastIndexOf with a
//! NaN position, which searches from the end. NODE_OUTPUT is Node v22.2.0's
//! output.
//!
//! No-claim: TypedArray and DataView index arguments still convert without
//! calling valueOf, and the Function constructor's arguments are another
//! path.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"const two = { valueOf() { return 2; } };
const one = { valueOf() { return 1; } };
const b = { toString() { return 'b'; } };
const log = [];
const tracked = function (name, value) { return { valueOf() { log.push(name); return value; } }; };
console.log('abc'.indexOf(b), 'abcb'.lastIndexOf(b), 'abc'.includes(b), 'abc'.startsWith({ toString() { return 'ab'; } }), 'abc'.endsWith({ toString() { return 'bc'; } }));
console.log('ab'.repeat(two), 'abcdef'.slice(one, { valueOf() { return 3; } }), 'abcdef'.substring(two), 'abcdef'.substr(one, two), 'abc'.codePointAt(one), 'abc'.indexOf('c', one));
console.log('5'.padStart(two, { toString() { return '0'; } }), 'x'.padEnd({ valueOf() { return 3; } }, '-'), 'aXbX'.lastIndexOf('X', NaN), 'aXbX'.lastIndexOf('X', 'nope'), 'aXbX'.lastIndexOf('X', one));
console.log([1, 2, 3].slice(one).join(), [1, 2, 3, 2].indexOf(2, two), [1, 2, 3, 2].lastIndexOf(2, one), [1, 2, 3].includes(1, one), [1, 2, 3].at(two), [0, 0, 0].fill(9, one, two).join());
console.log([1, 2, 3, 4].copyWithin(0, two).join(), [1, 2, 3].splice(one, one).join(), [[1, [2]]].flat(two).join(), [1, 2, 3].with(one, 'x').join(), [1, 2, 3].toSpliced(one, one).join());
console.log((12.345).toFixed(two), (255).toString({ valueOf() { return 16; } }), (1234.5).toPrecision(two), (1234.5).toExponential(one), (255n).toString({ valueOf() { return 16; } }));
'abcdef'.slice(tracked('start', 1), tracked('end', 3)); [1, 2, 3].slice(tracked('slice-start', 0), tracked('slice-end', 1));
console.log(log.join());
for (const [label, run] of [
  ['indexOf symbol', function () { return 'abc'.indexOf(Symbol('s')); }],
  ['slice symbol', function () { return 'abc'.slice(Symbol('s')); }],
  ['repeat symbol', function () { return 'a'.repeat(Symbol('s')); }],
  ['array slice symbol', function () { return [1].slice(Symbol('s')); }],
  ['at bigint', function () { return [1].at(1n); }],
  ['toFixed symbol', function () { return (1).toFixed(Symbol('s')); }],
  ['padStart symbol fill', function () { return 'a'.padStart(3, Symbol('s')); }],
]) {
  try { run(); console.log(label, 'no throw'); } catch (e) { console.log(label, e instanceof TypeError); }
}
try { (1).toFixed({ valueOf() { throw new RangeError('from valueOf'); } }); } catch (e) { console.log('abrupt valueOf', e instanceof RangeError, e.message); }
try { 'abc'.indexOf({ toString() { throw new SyntaxError('from toString'); } }); } catch (e) { console.log('abrupt toString', e instanceof SyntaxError, e.message); }"#;

const NODE_OUTPUT: &str = r#"1 3 true true true
abab bc cdef bc 98 2
05 x-- 3 3 1
2,3 3 1 false 3 0,9,0
3,4,3,4 2 1,2 1,x,3 1,3
12.35 ff 1.2e+3 1.2e+3 ff
start,end,slice-start,slice-end
indexOf symbol true
slice symbol true
repeat symbol true
array slice symbol true
at bigint true
toFixed symbol true
padStart symbol fill true
abrupt valueOf true from valueOf
abrupt toString true from toString"#;

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "builtin-argument-coercion.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "builtin-argument-coercion.js"),
        &LoweringContext::new("coerce-trace", "coerce-decision", "coerce-policy"),
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
    let mut core = InterpreterCore::new(config, "builtin-argument-coercion");
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
fn builtin_arguments_convert_like_node() {
    let output = console_output(PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}
