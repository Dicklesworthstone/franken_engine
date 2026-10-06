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
function outcome(module, name, args) {
  try {
    const result = module[name](...args);
    return {kind: 'returned', undefined: result === undefined};
  } catch (error) {
    return {
      kind: 'thrown', name: error.name, code: error.code, operator: error.operator,
      generatedMessage: error.generatedMessage,
      assertion: error instanceof module.AssertionError,
      originalMessage: error === args[2],
      actualIdentity: error.actual === args[0], expectedIdentity: error.expected === args[1]
    };
  }
}
function compare(label, actual, expected) {
  checks++;
  try { check.deepStrictEqual(actual, expected); }
  catch (error) {
    failures++;
    if (failures <= 20) console.error('FAIL', label, util.inspect({actual, expected}, {depth: 5}));
  }
}
const scalars = [undefined, null, false, true, 0, -0, NaN, Infinity, -Infinity,
  1, 2, '', '0', '1', '2', 'x', 0n, 1n, Symbol.for('assert-case')];
for (const method of ['equal', 'notEqual', 'strictEqual', 'notStrictEqual']) {
  for (const a of scalars) for (const b of scalars) {
    compare(method + ':' + String(a) + ':' + String(b),
      outcome(candidate, method, [a,b]), outcome(oracle, method, [a,b]));
  }
  for (const args of [[], [1], [1, 2, 'message'], [1, 2, new Error('original')]]) {
    compare(method + ' arguments', outcome(candidate, method, args), outcome(oracle, method, args));
  }
}
const pairs = [
  [{n:1},{n:'1'}], [[1,2],['1',2]], [new Set([{n:1}, {n:2}]),new Set([{n:'2'}, {n:'1'}])],
  [new Map([[{id:1}, {n:2}]]),new Map([[{id:'1'}, {n:'2'}]])],
  [new Set([null]),new Set([undefined])],
  [new Set([1,'1']),new Set([1,true])],
  [new Set([{n:1},{n:1}]),new Set([{n:1},{n:2}])],
  [Object.create({x:1}),{}], [new (class A {constructor(){this.n=1;}})(),{n:1}],
  [[,],[undefined]], [[],new Array(3)],
  [new Date(1),new Date(1)], [new Date(NaN),new Date(NaN)],
  [/a/g,/a/g], [/a/g,/a/i], [Object(1),Object(1)], [Object(1),1],
  [new Uint8Array([1,2]),new Uint8Array([1,3])],
  [new Float64Array([NaN]),new Float64Array([NaN])],
  [new Float64Array([-0]),new Float64Array([0])],
  [new Uint8Array([1,2]).buffer,new Uint8Array([1,3]).buffer],
  [new DataView(new Uint8Array([9,1,2,9]).buffer,1,2),new DataView(new Uint8Array([1,2]).buffer)],
  [new WeakMap(),new WeakMap()], [new WeakSet(),new WeakSet()],
  [new TypeError('x'),new TypeError('x')], [new TypeError('x'),new Error('x')],
];
const sym = Symbol('extra');
pairs.push([{[sym]:1},{[sym]:2}]);
const cycleA={n:1}, cycleB={n:'1'}, cycleC={n:2};
cycleA.self=cycleA; cycleB.self=cycleB; cycleC.self=cycleC;
pairs.push([cycleA,cycleB], [cycleA,cycleC]);
const causeA=new Error('same', {cause:{n:1}}), causeB=new Error('same', {cause:{n:'1'}});
pairs.push([causeA,causeB]);
for (const method of ['deepEqual','notDeepEqual','deepStrictEqual','notDeepStrictEqual']) {
  pairs.forEach(([a,b],i) => {
    const actual = outcome(candidate,method,[a,b]);
    const expected = outcome(oracle,method,[a,b]);
    if (i === 7 && (method === 'deepStrictEqual' || method === 'notDeepStrictEqual')) {
      // Node 22.16 ignores this changed prototype when both objects inherit
      // Object as constructor. Retain the existing engine's exact-prototype
      // contract, and report this as divergence, never as a differential pass.
      check.equal(actual.kind, method === 'deepStrictEqual' ? 'thrown' : 'returned');
      check.equal(expected.kind, method === 'deepStrictEqual' ? 'returned' : 'thrown');
      console.log('KNOWN_REFERENCE_DIVERGENCE', method, 'distinct plain-object prototypes');
      return;
    }
    compare(method + ' case ' + i,actual,expected);
  });
}
for (const method of ['match','doesNotMatch']) {
  for (const value of ['alpha','beta',null,7]) {
    for (const pattern of [/a/,/z/,{},undefined]) {
      compare(method + ' argument types', outcome(candidate,method,[value,pattern]),
        outcome(oracle,method,[value,pattern]));
    }
  }
}
for (const module of [candidate, oracle]) {
  const regex = /a/g;
  module.match('a',regex);
  check.equal(regex.lastIndex,1);
  module.doesNotMatch('a',regex);
  check.equal(regex.lastIndex,0);
}
for (const args of [[],[undefined],[null],['reason'],[new Error('explicit')],[1,2,'legacy']]) {
  compare('fail arguments', outcome(candidate,'fail',args),outcome(oracle,'fail',args));
}
for (const value of scalars) {
  compare('ifError',outcome(candidate,'ifError',[value]),outcome(oracle,'ifError',[value]));
}
for (const module of [candidate,oracle]) {
  check.equal(module,module.ok);
  check.equal(module.strict.strict,module.strict);
  check.equal(module.strict.ok,module.ok);
  check.equal(module.strict.equal,module.strictEqual);
  check.equal(module.strict.deepEqual,module.deepStrictEqual);
  const a={x:1},b={x:2};
  try { module.deepStrictEqual(a,b,'custom explanation'); check.fail('must throw'); }
  catch(error) {
    // Node appends a presentation diff to custom deep-equality messages.
    // The engine retains the supplied explanation without claiming identical
    // color, source-expression extraction or stack/diff presentation.
    check.equal(error.message.startsWith('custom explanation'),true);
    check.equal(error.actual,a);
    check.equal(error.expected,b);
    check.equal(error.generatedMessage,false);
    check.equal(error.code,'ERR_ASSERTION');
    check.equal(error instanceof module.AssertionError,true);
  }
}

const rust = fs.readFileSync(path.join(root, 'crates/franken-engine/tests/assert_module.rs'), 'utf8');
const programs = [...rust.matchAll(/const ([A-Z_]+): &str = r#"([\s\S]*?)"#;/g)];
const expectedByName = new Map(
  [...rust.matchAll(/assert_output\(\s*([A-Z_]+)\s*,\s*"((?:[^"\\]|\\[\s\S])*)"\s*,?\s*\)/g)]
    .map(([,name,value]) => [name, JSON.parse('"' + value.replace(/\\\r?\n\s*/g, '') + '"')])
);
function runProgram(source, module, utilModule) {
  const output = [];
  new Function('require','console',source)(specifier => {
    if (specifier === 'assert' || specifier === 'node:assert') return module;
    if (specifier === 'assert/strict' || specifier === 'node:assert/strict') return module.strict;
    if (specifier === 'util' || specifier === 'node:util') return utilModule;
    throw new Error('unexpected test require: ' + specifier);
  }, {log: (...args) => output.push(util.format(...args))});
  return output.join('\n');
}
for (const [,name,source] of programs) {
  const saved = util.isDeepStrictEqual;
  const savedCandidate = candidateUtil.isDeepStrictEqual;
  try {
    check.equal(expectedByName.has(name),true,'predeclared native expectation: ' + name);
    const actual = runProgram(source,loadCandidate(),candidateUtil);
    const expected = runProgram(source,oracle,util);
    compare('native fixture expectation ' + name,expected,expectedByName.get(name));
    compare('shared Rust fixture ' + name,actual,expected);
  } finally {
    util.isDeepStrictEqual = saved;
    candidateUtil.isDeepStrictEqual = savedCandidate;
  }
}

console.log(JSON.stringify({host:process.version, scope:'host adapters, not native Rust execution', checks, failures}));
process.exitCode = failures ? 1 : 0;
