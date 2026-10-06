//! First-class assert exports through the native parse/lower/execute path.
//! No filesystem/module-loader authority is granted by this test harness.
//! Human-facing Node diff/stack rendering and the newer Assert class are not
//! claimed here. Exact-prototype comparison retains the util contract.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn assert_output(source: &str, expected: &str) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "assert-module.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("assertion fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "assert-module.js"),
        &LoweringContext::new("assert-trace", "assert-decision", "assert-policy"),
    )
    .expect("assertion module lowers without filesystem authority")
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
    let mut core = InterpreterCore::new(config, "assert-module");
    let result = core.execute(&module).expect("assertion program executes");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "assertion failures must preserve exact heap accounting"
    );
    let output = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(output, expected);
}

const SCALARS: &str = r#"
const assert = require('assert');
assert(1);
assert.equal(1, '1');
assert.equal(NaN, NaN);
assert.strictEqual(NaN, NaN);
assert.notStrictEqual(0, -0);
function report(fn) {
  try { fn(); console.log('ok'); }
  catch (e) { console.log(e.name, e.code, e.operator); }
}
report(() => assert.strictEqual(1, '1'));
report(() => assert.notEqual(1, '1'));
report(() => assert.strictEqual(0, -0));
report(() => assert.equal());
report(() => assert.strictEqual(1));
console.log(assert === assert.ok, assert.strict.equal === assert.strictEqual);
"#;

#[test]
fn scalar_comparisons_and_missing_arguments() {
    assert_output(
        SCALARS,
        "AssertionError ERR_ASSERTION strictEqual\nAssertionError ERR_ASSERTION !=\n\
         AssertionError ERR_ASSERTION strictEqual\nTypeError ERR_MISSING_ARGS undefined\n\
         TypeError ERR_MISSING_ARGS undefined\ntrue true",
    );
}

const FIRST_CLASS: &str = r#"
const assert = require('node:assert');
const strict = require('assert/strict');
const { strictEqual: compare } = require('assert');
function keep(value) { return value; }
keep(assert)(true);
let local = require('assert'); local = keep(local);
local['strictEqual'](3, 3);
function nested() { return require('node:assert/strict'); }
console.log(assert === require('assert'), strict === assert.strict, nested() === strict);
console.log(compare === assert.strictEqual, strict.strict === strict, strict.ok === assert.ok);
try { strict.equal(1, '1'); } catch (e) { console.log(e.operator); }
"#;

#[test]
fn callable_exports_aliases_and_strict_submodule() {
    assert_output(FIRST_CLASS, "true true true\ntrue true true\nstrictEqual");
}

const STRUCTURAL: &str = r#"
const assert = require('assert');
assert.deepEqual({v: [1]}, {v: ['1']});
assert.deepEqual(new Set([{v: 1}]), new Set([{v: '1'}]));
assert.deepEqual(new Map([[{id: 1}, {v: 2}]]), new Map([[{id: '1'}, {v: '2'}]]));
const a = {v: 1}; a.self = a; const b = {v: '1'}; b.self = b;
assert.deepEqual(a, b);
assert.notDeepStrictEqual(a, b);
assert.strict.deepEqual(new Map([[{id: 1}, {v: 2}]]), new Map([[{id: 1}, {v: 2}]]));
assert.notDeepEqual(new Uint8Array([1, 2]).buffer, new Uint8Array([1, 3]).buffer);
const left = new Uint8Array([9, 1, 2, 9]);
const right = new Uint8Array([1, 2]);
assert.deepStrictEqual(new DataView(left.buffer, 1, 2), new DataView(right.buffer));
console.log('structural');
"#;

#[test]
fn nested_collections_cycles_and_binary_values() {
    assert_output(STRUCTURAL, "structural");
}

const FAILURES: &str = r#"
const assert = require('assert');
const original = new Error('same object');
try { assert(false, original); } catch (e) { console.log(e === original); }
try { assert.fail('reason'); } catch (e) {
  console.log(e instanceof assert.AssertionError, e instanceof Error, e.code, e.message);
}
try { assert.ifError(false); } catch (e) {
  console.log(e.actual === false, e.expected === null, e.operator);
}
const a = {n: 1}; const b = {n: 2};
try { assert.deepStrictEqual(a, b, 'explanation'); } catch (e) {
  console.log(e.actual === a, e.expected === b, e.generatedMessage, e.message.startsWith('explanation'));
}
const error = new assert.AssertionError({actual: 1, expected: 2, operator: '==', message: 'custom'});
console.log(error.name, error.code, error.toString(), Object.keys(error).sort().join(','));
"#;

#[test]
fn assertion_error_fields_and_custom_error_identity() {
    assert_output(
        FAILURES,
        "true\ntrue true ERR_ASSERTION reason\ntrue true ifError\ntrue true false true\n\
         AssertionError ERR_ASSERTION AssertionError [ERR_ASSERTION]: custom actual,code,expected,generatedMessage,operator",
    );
}

const REGEX_CHECKS: &str = r#"
const assert = require('assert/strict');
const pattern = /a/g;
pattern.test = () => { throw new Error('overridden test must not run'); };
assert.match('a', pattern);
console.log(pattern.lastIndex);
assert.doesNotMatch('a', pattern);
console.log(pattern.lastIndex);
try { assert.match('a', {}); } catch (e) { console.log(e.code); }
try { assert.doesNotMatch(1, /x/); } catch (e) { console.log(e.operator, e.actual); }
"#;

#[test]
fn regex_uses_native_receiver_and_validates_arguments() {
    assert_output(REGEX_CHECKS, "1\n0\nERR_INVALID_ARG_TYPE\ndoesNotMatch 1");
}

const SHADOWING: &str = r#"
const assert = require('assert');
function use(require) { return require('assert'); }
console.log(use(name => 'local:' + name));
for (const require of [name => 'loop:' + name]) console.log(require('assert/strict'));
const Map = 'guest-map';
const Object = 'guest-object';
const Promise = 'guest-promise';
assert.deepEqual({x: 1}, {x: '1'});
assert(true);
console.log(Map, Object, Promise);
"#;

#[test]
fn guest_require_and_global_bindings_are_not_captured() {
    assert_output(SHADOWING, "local:assert\nloop:assert/strict\nguest-map guest-object guest-promise");
}

const PRIVATE_COMPARISON: &str = r#"
const assert = require('assert');
const util = require('util');
util.isDeepStrictEqual = () => true;
try { assert.deepStrictEqual({x: 1}, {x: 2}); }
catch (e) { console.log(e.code, e.operator); }
"#;

#[test]
fn public_util_mutation_cannot_replace_the_assertion_comparator() {
    assert_output(PRIVATE_COMPARISON, "ERR_ASSERTION deepStrictEqual");
}
