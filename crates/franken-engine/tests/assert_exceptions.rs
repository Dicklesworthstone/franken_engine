//! Exception and rejection assertions through the native parser and runtime.
//! Host adapters run these same programs separately; they do not certify this path.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn assert_output(source: &str, expected: &str) {
    assert_goal_output(source, expected, ParseGoal::Script);
}

fn assert_goal_output(source: &str, expected: &str, goal: ParseGoal) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "assert-exceptions.js".into(),
                text: source.into(),
            },
            goal,
            &ParserOptions::default(),
        )
        .expect("exception assertion fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "assert-exceptions.js"),
        &LoweringContext::new("assert-exceptions", "assert-decision", "assert-policy"),
    )
    .expect("exception assertion module lowers")
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
    let mut core = InterpreterCore::new(config, "assert-exceptions");
    let result = core.execute(&module).expect("exception assertions execute");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "exception assertions must not lose heap accounting"
    );
    let output = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(output, expected);
}

const SYNC_PATTERNS: &str = r#"
const assert = require('assert');
const original = new TypeError('bad value');
original.code = 'E_BAD';
original.detail = {count: 3};
let calls = 0;
const result = assert.throws(() => { calls++; throw original; },
  {name: 'TypeError', message: /bad/, code: 'E_BAD', detail: {count: 3}});
assert.throws(() => { throw original; }, TypeError);
assert.throws(() => { throw original; }, /bad value/);
let validators = 0;
assert.throws(() => { throw original; }, function (error) {
  validators++;
  return error === original && typeof this === 'object' && Object.keys(this).length === 0;
});
for (const value of [undefined, null, false, 0, '']) {
  assert.throws(() => { throw value; });
}
console.log(calls, validators, result === undefined);
"#;

#[test]
fn constructors_regex_object_matchers_and_falsy_thrown_values() {
    assert_output(SYNC_PATTERNS, "1 1 true");
}

const WRONG_ERRORS: &str = r#"
const assert = require('assert/strict');
const original = new RangeError('original');
let caught = 0;
try { assert.doesNotThrow(() => { throw original; }, TypeError); }
catch (error) { console.log(error === original); }
for (const value of [undefined, null, false, 0, 'wrong']) {
  try { assert.doesNotThrow(() => { throw value; }, () => false); }
  catch (error) { if (error === value) caught++; }
}
const validatorError = new Error('validator');
try { assert.throws(() => { throw original; }, () => { throw validatorError; }); }
catch (error) { console.log(error === validatorError); }
const getterError = new Error('getter');
try {
  assert.throws(() => { throw original; }, {get message() { throw getterError; }});
} catch (error) { console.log(error === getterError); }
console.log(caught);
"#;

#[test]
fn unmatched_negative_assertions_and_matcher_exceptions_preserve_identity() {
    assert_output(WRONG_ERRORS, "true\ntrue\ntrue\n5");
}

const FAILURE_SHAPES: &str = r#"
const assert = require('assert');
try { assert.throws(() => {}, TypeError); }
catch (error) {
  console.log(error.code, error.operator, error.actual === undefined,
    error.expected === TypeError, error.generatedMessage);
}
try { assert.throws(() => { throw undefined; }, {}); }
catch (error) { console.log(error.name, error.code, error.operator); }
try { assert.throws(() => { throw new Error('x'); }, {}); }
catch (error) { console.log(error.name, error.code); }
try { assert.throws(() => { throw 'same'; }, 'same'); }
catch (error) { console.log(error.code); }
try { assert.throws(() => { throw new Error('x'); }, () => 1); }
catch (error) { console.log(error.code, error.operator); }
try { assert.doesNotThrow(() => { throw 0; }, false); }
catch (error) { console.log(error.code, error.operator, error.actual === 0); }
assert.doesNotThrow(() => {}, {});
console.log('done');
"#;

#[test]
fn failure_fields_matcher_validation_and_ambiguous_messages() {
    assert_output(
        FAILURE_SHAPES,
        "ERR_ASSERTION throws true true false\nAssertionError ERR_ASSERTION throws\n\
         TypeError ERR_INVALID_ARG_VALUE\nERR_AMBIGUOUS_ARGUMENT\nERR_ASSERTION throws\n\
         ERR_ASSERTION doesNotThrow true\ndone",
    );
}

const ASYNC_PATTERNS: &str = r#"
const assert = require('assert/strict');
const completion = (async function () {
  const original = new TypeError('rejected');
  original.code = 'E_BAD';
  let calls = 0;
  await assert.rejects(async () => { calls++; throw original; },
    {name: 'TypeError', message: /reject/, code: 'E_BAD'});
  await assert.rejects(Promise.reject(undefined));
  await assert.rejects(() => ({
    then(resolve, reject) { reject(original); }, catch() {}
  }), TypeError);
  await assert.doesNotReject(async () => 42);
  await assert.doesNotReject(Promise.resolve(false));
  try { await assert.doesNotReject(Promise.reject(original), RangeError); }
  catch (error) { console.log(error === original); }
  console.log(calls, 'async');
})();
"#;

#[test]
fn promise_inputs_thenables_and_rejection_matchers() {
    assert_output(ASYNC_PATTERNS, "true\n1 async");
}

const ASYNC_INPUTS: &str = r#"
const assert = require('assert');
const completion = (async function () {
  const sentinel = new Error('sync throw');
  let invoked = 0;
  let matched = 0;
  try {
    await assert.rejects(() => { invoked++; throw sentinel; }, () => { matched++; return true; });
  } catch (error) { console.log(error === sentinel, invoked, matched); }
  for (const input of [7, () => 7, {then() {}}, () => ({then() {}})]) {
    try { await assert.rejects(input); }
    catch (error) { console.log(error.code); }
  }
  const getterError = new Error('then getter');
  try { await assert.rejects({get then() { throw getterError; }, catch() {}}); }
  catch (error) { console.log(error === getterError); }
  let synchronous = true;
  const invalid = assert.rejects(7).catch(error => console.log(!synchronous, error.code));
  synchronous = false;
  await invalid;
})();
"#;

#[test]
fn invalid_promise_inputs_and_synchronous_throws_are_not_matching_rejections() {
    assert_output(
        ASYNC_INPUTS,
        "true 1 0\nERR_INVALID_ARG_TYPE\nERR_INVALID_RETURN_VALUE\nERR_INVALID_ARG_TYPE\n\
         ERR_INVALID_RETURN_VALUE\ntrue\ntrue ERR_INVALID_ARG_TYPE",
    );
}

const ASYNC_FAILURES: &str = r#"
const assert = require('assert');
const completion = (async function () {
  try { await assert.rejects(Promise.resolve('value'), Error); }
  catch (error) { console.log(error.code, error.operator, error.generatedMessage); }
  try { await assert.rejects(Promise.reject(new Error('bad')), {message: 'other'}); }
  catch (error) { console.log(error.code, error.operator, error.generatedMessage); }
  const original = new Error('wrong kind');
  try { await assert.doesNotReject(Promise.reject(original), /match only/); }
  catch (error) { console.log(error === original); }
  try { await assert.doesNotReject(Promise.reject(undefined)); }
  catch (error) { console.log(error.code, error.operator, error.actual === undefined); }
  let callbacks = 0;
  await assert.rejects(async () => { throw original; }, value => {
    callbacks++;
    return value === original;
  });
  console.log(callbacks);
})();
"#;

#[test]
fn asynchronous_failure_metadata_and_unmatched_original_values() {
    assert_output(
        ASYNC_FAILURES,
        "ERR_ASSERTION rejects false\nERR_ASSERTION rejects true\ntrue\n\
         ERR_ASSERTION doesNotReject true\n1",
    );
}

const PUBLIC_MUTATION: &str = r#"
const assert = require('assert');
const util = require('util');
const completion = (async function () {
  util.types.isPromise = () => true;
  util.types.isNativeError = () => true;
  util.isDeepStrictEqual = () => true;
  try { await assert.rejects(7); }
  catch (error) { console.log(error.code); }
  try { assert.throws(() => { throw {detail: {n: 1}}; }, {detail: {n: 2}}); }
  catch (error) { console.log(error.code, error.operator); }
})();
"#;

#[test]
fn public_utility_mutation_cannot_replace_private_assertion_dependencies() {
    assert_output(
        PUBLIC_MUTATION,
        "ERR_INVALID_ARG_TYPE\nERR_ASSERTION throws",
    );
}

const ASYNC_ORDER: &str = r#"
const assert = require('assert');
const order = [];
const completion = (async function () {
  const first = assert.rejects(Promise.reject(new Error('x')), error => {
    order.push('predicate');
    return true;
  }).then(() => order.push('assertion'));
  Promise.resolve().then(() => order.push('peer'));
  order.push('sync');
  await first;
  console.log(order.join(','));
})();
"#;

#[test]
fn rejection_assertions_preserve_promise_reaction_order() {
    assert_output(ASYNC_ORDER, "sync,peer,predicate,assertion");
}

const ESM_IMPORTS: &str = r#"
import assert, {strictEqual, throws} from 'node:assert';
import strict, {rejects} from 'assert/strict';
function keep(value) { return value; }
keep(assert)(true);
strictEqual(strict, assert.strict);
throws(() => { throw new TypeError('x'); }, TypeError);
await rejects(Promise.reject(new Error('x')), /x/);
console.log(strict.equal === strictEqual, strict.strict === strict, 'esm');
"#;

#[test]
fn esm_default_named_and_strict_imports_use_the_same_first_class_values() {
    assert_goal_output(ESM_IMPORTS, "true true esm", ParseGoal::Module);
}
