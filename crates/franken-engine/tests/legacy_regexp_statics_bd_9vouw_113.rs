//! bd-9vouw.113: legacy RegExp statics (`RegExp.$1`-`$9`, `input`,
//! `lastMatch`, `lastParen`, `leftContext`, `rightContext` and their `$`
//! aliases).
//!
//! They read undefined, so showdown's paragraph pass (`/¨(K|G)(\d+)\1/.test(s)`
//! then `RegExp.$1`) threw on every header. PROGRAM records a match with
//! test, a failed test (values kept), a global replace, match, split with a
//! capture, exec with an unmatched group, search, matchAll, a read through a
//! subclass, and showdown's destructuring read (`var { $1: d } = RegExp`).
//! NODE_OUTPUT is Node v22.2.0's output, line by line.
//!
//! No-claim: the statics are served as reads of the RegExp constructor, not
//! as accessor properties (Object.getOwnPropertyDescriptor shows no getter).
//!
//! bd-9vouw.241: Annex B `RegExp.prototype.compile` was missing.
//! COMPILE_PROGRAM recompiles a RegExp from strings, from another RegExp
//! (whose lastIndex stays), with no arguments, with patterns and flags that
//! do not parse (the receiver keeps its old source), with throwing and
//! Symbol arguments, on non-RegExp receivers, on a RegExp whose lastIndex is
//! read-only (the source changes, then the TypeError), on a subclass
//! instance (accepted, as in Node), and with the `u` flag.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"const show = () => [RegExp.$1, RegExp.$2, RegExp.$3, RegExp.$9, RegExp.lastMatch, RegExp['$&'], RegExp.lastParen, RegExp['$+'], RegExp.leftContext, RegExp['$`'], RegExp.rightContext, RegExp["$'"], RegExp.input, RegExp.$_].map(v => JSON.stringify(v)).join(' ');
console.log(show());
/(\d+)-(\d+)/.test('ab 12-34 cd');
console.log(show());
/(x)/.test('none');
console.log(show());
'k=v; a=b'.replace(/(\w)=(\w)/g, '$2=$1');
console.log(show());
'p1q22'.match(/q(\d+)/);
console.log(show());
'a,b;c'.split(/([,;])/);
console.log(show());
/(a)|(b)/.exec('b');
console.log(show());
'xyz'.search(/y/);
console.log(show());
[...'m1n2'.matchAll(/\d/g)];
console.log(show());
console.log(Object.keys(RegExp).length, '$1' in RegExp);
class R extends RegExp {}
new R('(z)').exec('z');
try { console.log(R.$1); } catch (e) { console.log(e.name); }
console.log(JSON.stringify(RegExp.$1));
/(\d)(\w)/.test('x7y'); var { $1: delim, $2: num, lastMatch: lm } = RegExp; console.log(delim, num, lm);"#;

/// Node v22.2.0's output for `PROGRAM`.
const NODE_OUTPUT: &str = r#""" "" "" "" "" "" "" "" "" "" "" "" "" ""
"12" "34" "" "" "12-34" "12-34" "34" "34" "ab " "ab " " cd" " cd" "ab 12-34 cd" "ab 12-34 cd"
"12" "34" "" "" "12-34" "12-34" "34" "34" "ab " "ab " " cd" " cd" "ab 12-34 cd" "ab 12-34 cd"
"a" "b" "" "" "a=b" "a=b" "b" "b" "k=v; " "k=v; " "" "" "k=v; a=b" "k=v; a=b"
"22" "" "" "" "q22" "q22" "22" "22" "p1" "p1" "" "" "p1q22" "p1q22"
";" "" "" "" ";" ";" ";" ";" "a,b" "a,b" "c" "c" "a,b;c" "a,b;c"
"" "b" "" "" "b" "b" "b" "b" "" "" "" "" "b" "b"
"" "" "" "" "y" "y" "" "" "x" "x" "z" "z" "xyz" "xyz"
"" "" "" "" "2" "2" "" "" "m1n" "m1n" "" "" "m1n2" "m1n2"
0 true
z
"z"
7 y 7y"#;

/// bd-9vouw.241: RegExp.prototype.compile.
const COMPILE_PROGRAM: &str = r#"function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var re = /abc/gi;
re.lastIndex = 3;
var same = re.compile('d(e)f', 'm') === re;
console.log(same, String(re), re.flags, re.lastIndex, re.test('xDEF'), re.test('def'), re.exec('ddef')[1]);
var donor = /q+/y;
donor.lastIndex = 9;
re.compile(donor);
console.log(String(re), re.sticky, donor.lastIndex, re.test('qq'), attempt(() => re.compile(donor, 'g')), String(re));
console.log(String(re.compile()), re.test(''), String(re.compile(undefined, undefined)), String(re.compile(null, 1 === 1 ? 'g' : '')));
console.log(attempt(() => re.compile('?')), attempt(() => re.compile('a', 'gg')), attempt(() => re.compile('a', 'z')), String(re));
console.log(attempt(() => re.compile({ toString() { throw new RangeError('p'); } })), attempt(() => re.compile('a', Symbol('f'))), String(re));
console.log(String(re.compile({ toString() { return 'x|y'; } }, { toString() { return 'i'; } })), re.test('Y'));
console.log(attempt(() => RegExp.prototype.compile.call({})), attempt(() => RegExp.prototype.compile.call('/a/')), attempt(() => RegExp.prototype.compile.call(undefined)));
var frozen = /old/;
Object.defineProperty(frozen, 'lastIndex', { value: 7, writable: false });
console.log(attempt(() => frozen.compile('new', 'g')), String(frozen), frozen.lastIndex);
var d = Object.getOwnPropertyDescriptor(RegExp.prototype, 'compile');
console.log(typeof d.value, d.writable, d.enumerable, d.configurable, RegExp.prototype.compile.length, RegExp.prototype.compile.name);
class Sub extends RegExp {}
var sub = new Sub('a');
console.log(attempt(() => String(sub.compile('b', 'g'))), sub instanceof Sub);
var u = /x/;
u.compile('[𝌆]', 'u');
console.log(u.test('\ud834'), u.test('𝌆'), u.unicode);"#;

/// Node v22.2.0's output for `COMPILE_PROGRAM`.
const COMPILE_NODE_OUTPUT: &str = r#"true /d(e)f/m m 0 false true e
/q+/y true 9 true TypeError /q+/y
/(?:)/ true /(?:)/ /null/g
SyntaxError SyntaxError SyntaxError /null/g
RangeError TypeError /null/g
/x|y/i true
TypeError TypeError TypeError
TypeError /new/g 7
function true false true 2 compile
/b/g true
false true true"#;

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "legacy-regexp.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "legacy-regexp.js"),
        &LoweringContext::new("legacy-trace", "legacy-decision", "legacy-policy"),
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
    let mut core = InterpreterCore::new(config, "legacy-regexp");
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
fn legacy_regexp_statics_match_node() {
    let output = console_output(PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}

#[test]
fn regexp_prototype_compile_matches_node_bd_9vouw_241() {
    let output = console_output(COMPILE_PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(COMPILE_NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), COMPILE_NODE_OUTPUT.lines().count());
}
