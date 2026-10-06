'use strict';
// Host differential validation of the exact engine-owned JavaScript.
// This does NOT execute the Rust parser, lowering, interpreter, IFC or heap.
const fs = require('node:fs');
const path = require('node:path');
const oracle = require('node:assert');
const check = require('node:assert/strict');
const util = require('node:util');
const root = path.resolve(__dirname, '..');
const directory = path.join(root, 'crates/franken-engine/src/lowering_pipeline');
function typeTag(value) {
  const tags = [
    ['isProxy', 'Proxy'], ['isDate', 'Date'], ['isRegExp', 'RegExp'],
    ['isMap', 'Map'], ['isSet', 'Set'], ['isWeakMap', 'WeakMap'], ['isWeakSet', 'WeakSet'],
    ['isPromise', 'Promise'], ['isArrayBuffer', 'ArrayBuffer'],
    ['isSharedArrayBuffer', 'SharedArrayBuffer'], ['isDataView', 'DataView'],
    ['isNativeError', 'Error'], ['isNumberObject', 'BoxedNumber'],
    ['isStringObject', 'BoxedString'], ['isBooleanObject', 'BoxedBoolean'],
    ['isBigIntObject', 'BoxedBigInt'], ['isSymbolObject', 'BoxedSymbol'],
  ];
  for (const [test, tag] of tags) if (util.types[test](value)) return tag;
  for (const tag of ['Int8Array','Uint8Array','Uint8ClampedArray','Int16Array','Uint16Array',
      'Int32Array','Uint32Array','Float32Array','Float64Array','BigInt64Array','BigUint64Array']) {
    if (util.types['is' + tag](value)) return tag;
  }
  return Array.isArray(value) ? 'Array' : typeof value === 'object' ? 'Object' : typeof value;
}

const candidateUtil = new Function('__franken_util_inspect', '__franken_util_format',
  '__franken_util_type_tag', 'return ' + fs.readFileSync(path.join(directory, 'util_module.js'), 'utf8'))(
    util.inspect, args => util.format(...args), typeTag);
function loadCandidate() {
  return new Function('__franken_assert_util', '__franken_util_type_tag',
    'return ' + fs.readFileSync(path.join(directory, 'assert_module.js'), 'utf8'))(candidateUtil, typeTag);
}
const candidate = loadCandidate();

let checks = 0;
let failures = 0;
function compare(label, actual, expected) {
  checks++;
  try { check.deepStrictEqual(actual, expected); }
  catch (error) {
    failures++;
    if (failures <= 20) {
      console.error('FAIL', label, util.inspect({actual, expected}, {depth: 5, colors: false}));
    }
  }
}
async function exceptionOutcome(module, method, expected, thrown, value) {
  let called = 0;
  const body = () => { called++; if (thrown) throw value; };
  const block = method === 'rejects' || method === 'doesNotReject' ? async () => body() : body;
  try {
    const result = await module[method](block, expected);
    return {returned: true, called, undefined: result === undefined};
  } catch (error) {
    return {
      returned: false, called, name: error?.name, code: error?.code,
      operator: error?.operator, generatedMessage: error?.generatedMessage,
      original: error === value, actual: error?.actual === value,
      expected: error?.expected === expected
    };
  }
}

async function run() {
  const matchers = [
    undefined, null, false, 0, 1, NaN, 'hint', '', {}, [],
    TypeError, Error, /yes/, /no/, () => true, () => 1,
    {message: 'no'}, new Error('no'), {message: /no/},
    {name: 'TypeError'}, {missing: undefined}
  ];
  const values = [undefined, null, false, 0, 'no', new Error('no'), new TypeError('no'), {message: 'no'}];
  for (const method of ['throws', 'doesNotThrow', 'rejects', 'doesNotReject']) {
    for (const expected of matchers) {
      for (const thrown of [false, true]) {
        for (const value of values) {
          compare(method + ' matcher/value matrix',
            await exceptionOutcome(candidate, method, expected, thrown, value),
            await exceptionOutcome(oracle, method, expected, thrown, value));
        }
      }
    }
  }

  // Fresh inputs for each side: thenable/getter invocation can have effects.
  const promiseCases = [
    () => undefined,
    () => null,
    () => 7,
    () => ({}),
    () => ({then() {}}),
    () => (() => undefined),
    () => (() => ({then() {}})),
    () => (() => ({then: 1, catch() {}})),
    () => (Promise.resolve(7)),
    () => (Promise.reject('rejection')),
    () => (() => Promise.reject('rejection')),
    () => ({then(resolve) { resolve('value'); }, catch() {}}),
    () => ({then(resolve, reject) { reject('rejection'); }, catch() {}}),
    () => (() => ({then(resolve, reject) { reject('rejection'); }, catch() {}})),
  ];
  for (const method of ['rejects', 'doesNotReject']) {
    for (const input of promiseCases) {
      async function observed(module) {
        let synchronous = true;
        try {
          const promise = module[method](input());
          const genuinePromise = util.types.isPromise(promise);
          synchronous = false;
          const value = await promise;
          return {returned: true, undefined: value === undefined, genuinePromise};
        } catch (error) {
          return {
            synchronous, original: error === 'rejection',
            name: error?.name, code: error?.code, operator: error?.operator
          };
        }
      }
      compare(method + ' Promise input validation', await observed(candidate), await observed(oracle));
    }
  }

  for (const method of ['throws', 'doesNotThrow', 'rejects', 'doesNotReject']) {
    for (const expected of ['same', 'hint', '', null, 0, TypeError, /same/]) {
      async function observed(module) {
        const actual = new TypeError('same');
        const block = method === 'rejects' || method === 'doesNotReject'
          ? async () => { throw actual; } : () => { throw actual; };
        try { await module[method](block, expected, 'explicit'); return 'returned'; }
        catch (error) {
          return {name: error?.name, code: error?.code, operator: error?.operator,
            original: error === actual, message: error?.code === 'ERR_ASSERTION'
              ? error.message.includes('explicit') : undefined};
        }
      }
      compare(method + ' third-argument overload', await observed(candidate), await observed(oracle));
    }
  }

  const rustPath = path.join(root, 'crates/franken-engine/tests/assert_exceptions.rs');
  const rust = fs.readFileSync(rustPath, 'utf8');
  const programs = [...rust.matchAll(/const ([A-Z_]+): &str = r#"([\s\S]*?)"#;/g)];
  const expectations = new Map(
    [...rust.matchAll(/assert_output\(\s*([A-Z_]+)\s*,\s*"((?:[^"\\]|\\[\s\S])*)"\s*,?\s*\)/g)]
      .map(([,name,value]) => [name, JSON.parse('"' + value.replace(/\\\r?\n\s*/g, '') + '"')])
  );
  async function runProgram(source, module, utilModule) {
    const output = [];
    const result = new Function('require', 'console', source +
      '\nreturn typeof completion === "undefined" ? undefined : completion;')(
        specifier => {
          if (specifier === 'assert' || specifier === 'node:assert') return module;
          if (specifier === 'assert/strict' || specifier === 'node:assert/strict') return module.strict;
          if (specifier === 'util' || specifier === 'node:util') return utilModule;
          throw new Error('unexpected test require: ' + specifier);
        },
        {log: (...args) => output.push(util.format(...args))}
      );
    await result;
    return output.join('\n');
  }
  let sharedPrograms = 0;
  let esmReferenceOnly = 0;
  for (const [,name,source] of programs) {
    if (name === 'ESM_IMPORTS') {
      const expectedMatch = rust.match(/assert_goal_output\(ESM_IMPORTS,\s*"([^"]*)",/);
      check.ok(expectedMatch, 'predeclared ESM output');
      const result = require('node:child_process').spawnSync(process.execPath,
        ['--input-type=module', '-e', source], {encoding: 'utf8', timeout: 10000, env: {...process.env, FORCE_COLOR: '0', NODE_DISABLE_COLORS: '1'}});
      if (result.error) throw result.error;
      check.equal(result.status, 0, result.stderr);
      check.equal(result.stdout.trimEnd(), expectedMatch[1]);
      esmReferenceOnly++;
      continue;
    }
    const functions = ['isPromise', 'isNativeError'];
    const original = functions.map(key => util.types[key]);
    const originalCandidate = functions.map(key => candidateUtil.types[key]);
    const equality = util.isDeepStrictEqual;
    const candidateEquality = candidateUtil.isDeepStrictEqual;
    try {
      check.ok(expectations.has(name), 'predeclared native expectation: ' + name);
      const actual = await runProgram(source, loadCandidate(), candidateUtil);
      const expected = await runProgram(source, oracle, util);
      compare('predeclared native fixture ' + name, expected, expectations.get(name));
      compare('shared native fixture ' + name, actual, expected);
      sharedPrograms++;
    } finally {
      functions.forEach((key, i) => {
        util.types[key] = original[i];
        candidateUtil.types[key] = originalCandidate[i];
      });
      util.isDeepStrictEqual = equality;
      candidateUtil.isDeepStrictEqual = candidateEquality;
    }
  }

  console.log(JSON.stringify({
    host: process.version, scope: 'host adapters, not native Rust execution',
    checks, failures, sharedPrograms, esmReferenceOnly
  }));
  process.exitCode = failures ? 1 : 0;
}
run().catch(error => { console.error(error); process.exitCode = 1; });
