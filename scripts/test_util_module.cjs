'use strict';
// Execute the exact engine-owned factory, not a reimplementation of it.
// This is a Node-host differential suite, NOT native Rust execution evidence.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const util = require('node:util');
const vm = require('node:vm');

const filename = process.env.FRANKEN_UTIL_SOURCE || path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/util_module.js');
const source = fs.readFileSync(filename, 'utf8');
function typeTag(value) {
  for (const [test, tag] of [
    ['isProxy', 'Proxy'], ['isMap', 'Map'], ['isSet', 'Set'],
    ['isWeakMap', 'WeakMap'], ['isWeakSet', 'WeakSet'],
    ['isDate', 'Date'], ['isRegExp', 'RegExp'], ['isNativeError', 'Error'],
    ['isArrayBuffer', 'ArrayBuffer'], ['isDataView', 'DataView'],
    ['isNumberObject', 'BoxedNumber'], ['isStringObject', 'BoxedString'],
    ['isBooleanObject', 'BoxedBoolean'], ['isBigIntObject', 'BoxedBigInt'],
    ['isSymbolObject', 'BoxedSymbol'], ['isPromise', 'Promise'],
  ]) {
    if (util.types[test](value)) return tag;
  }
  return Object.prototype.toString.call(value).slice(8, -1);
}
const candidate = new Function('__franken_util_inspect', '__franken_util_format',
  '__franken_util_type_tag', 'return ' + source)(
  util.inspect, args => util.format(...args), typeTag);
let passed = 0;
function test(name, body) {
  body();
  console.log(`ok ${++passed} - ${name}`);
}
function outcome(parse, config) {
  try { return { result: parse(config) }; }
  catch (error) { return { error: { name: error.name, code: error.code, message: error.message } }; }
}
let comparisons = 0;
function compare(config) {
  assert.deepStrictEqual(outcome(candidate.parseArgs, config), outcome(util.parseArgs, config),
    util.inspect(config, { depth: 6 }));
  comparisons++;
}
const options = {
  color: { type: 'boolean', short: 'c', multiple: true, default: [true] },
  output: { type: 'string', short: 'o', multiple: true },
  verbose: { type: 'boolean', short: 'v' },
};

test('boolean negation, repetition and normalized token names match Node', () => {
  for (const args of [[], ['--no-color'], ['--color', '--no-color', '-c'],
    ['--no-color=true'], ['--no-output'], ['--no-no-color'],
    ['--no-color', '--', '--color'], ['--no-color', 'file'],
    ['--no-__proto__'], ['--no-constructor'], ['--no-toString']]) {
    for (const allowNegative of [false, true]) {
      for (const strict of [false, true]) {
        compare({ args, options, allowNegative, strict, tokens: true });
      }
    }
  }
});
test('explicit no-* options and short aliases preserve Node precedence', () => {
  for (const type of ['string', 'boolean']) {
    for (const positiveType of ['string', 'boolean']) {
      const opts = { color: { type: positiveType, multiple: true },
        'no-color': { type, short: 'n', default: type === 'string' ? 'auto' : true } };
      for (const args of [['--no-color'], ['--no-color=x'], ['-n'], ['-nx'],
        ['--no-no-color'], ['--no-color', '--color'], ['--color=x', '-n']]) {
        for (const strict of [false, true]) {
          compare({ args, options: opts, allowNegative: true, tokens: true, strict });
        }
      }
    }
  }
});
test('allowNegative validation and defaults match Node', () => {
  for (const allowNegative of [undefined, null, true, false, 0, 1, '', 'true', [], {}]) {
    compare({ args: [], allowNegative });
  }
  compare({ args: ['--no-'], allowNegative: true, options: { '': { type: 'boolean' } }, tokens: true });
  compare({ args: ['--no-__proto__'], strict: false, allowNegative: true, tokens: true });
});
test('grouped options retain original argv indices, inline values and terminators', () => {
  for (const args of [
    ['-vc', '--output=one', '-ovalue', '--no-color'],
    ['-vco', 'two', '--', '-v'], ['-v--c', 'tail'], ['-v-c', '--output', 'x'],
    ['--=x', '--x=', '-'], ['-vo--', '--color'], ['-vo', '-c'],
    ['-v', '-v', '-v'], ['-vc', '-vc', '-vc'],
  ]) {
    for (const strict of [false, true]) {
      compare({ args, options, strict, allowNegative: true, tokens: true, allowPositionals: true });
    }
  }
  const unusual = { a: { type: 'boolean', short: 'a' }, dash: { type: 'string', short: '-' },
    equals: { type: 'boolean', short: '=' }, empty: { type: 'boolean', short: ' ' } };
  for (const args of [['-a-x', 'tail'], ['-=a'], ['- a'], ['-a--a'], ['-a-']]) {
    compare({ args, options: unusual, strict: false, tokens: true });
  }
});
test('deterministic generated argument combinations match the live incumbent', () => {
  const atoms = ['-v', '-vc', '-vo', '--color', '--no-color', '--output=x', '-ox',
    '--output', '', 'file', '--', '--no-output', '--no-color=x', '-v-c'];
  for (let i = 0; i < atoms.length; i++) {
    for (let j = 0; j < atoms.length; j++) {
      for (let k = 0; k < atoms.length; k++) {
        compare({ args: [atoms[i], atoms[j], atoms[k]], options, tokens: true,
          allowNegative: (i + j) % 2 === 0, strict: k % 2 === 0, allowPositionals: true });
      }
    }
  }
});
test('duplicate short names, own-only settings and dynamic getters remain observable', () => {
  compare({ args: ['-x', 'value'], tokens: true, allowPositionals: true,
    options: { first: { type: 'boolean', short: 'x' }, second: { type: 'string', short: 'x' } } });
  compare({ args: ['--no-color'], strict: false, allowNegative: true,
    options: Object.create({ color: { type: 'boolean' } }) });
  function run(parse) {
    const reads = [];
    let aliases = 0;
    const config = { args: ['-vo', 'file', '--no-color'], allowNegative: true, tokens: true,
      options: { color: { type: 'boolean' }, verbose: { type: 'boolean',
        get short() { reads.push('short:' + (++aliases)); return 'v'; } },
      output: { type: 'string', short: 'o' } } };
    return { outcome: outcome(parse, config), reads };
  }
  assert.deepStrictEqual(run(candidate.parseArgs), run(util.parseArgs));
});
test('argv is snapshotted without consulting an own slice method', () => {
  const args = ['-vc', '-o', 'file', '--', '--no-color'];
  args.slice = () => { throw new Error('guest slice must not be called'); };
  Object.freeze(args);
  compare({ args, options, allowNegative: true, tokens: true, allowPositionals: true });
  assert.deepEqual(Array.from(args), ['-vc', '-o', 'file', '--', '--no-color']);
});
test('large argument tails and short groups match Node without queue reindexing', () => {
  compare({ args: Array.from({ length: 16000 }, (_, i) => 'file-' + i), allowPositionals: true });
  compare({ args: ['-' + 'v'.repeat(8192), '--output', 'file'], options, tokens: true });
  const realm = vm.createContext({ TextEncoder, TextDecoder });
  vm.runInContext('var util = ' + source + ';', realm);
  vm.runInContext(`
    Array.prototype.shift = Array.prototype.unshift = function () { throw new Error('quadratic queue'); };
    var result = util.parseArgs({ args: ['-vvv', '--', 'file'], tokens: true,
      allowPositionals: true, options: { verbose: { type: 'boolean', short: 'v' } } });
    if (result.tokens.length !== 5 || result.positionals[0] !== 'file') throw new Error('wrong result');
  `, realm);
});
let collectionComparisons = 0;
function compareCollection(a, b) {
  function result(compare) {
    try { return { equal: compare(a, b) }; }
    catch (error) { return { error: { name: error.name, code: error.code, message: error.message } }; }
  }
  assert.deepEqual(result(candidate.isDeepStrictEqual), result(util.isDeepStrictEqual),
    'collection comparison ' + collectionComparisons);
  collectionComparisons++;
}
test('unordered primitive collections retain SameValueZero keys and strict values', () => {
  const symbol = Symbol('shared');
  const fn = function shared() {};
  const keys = [null, undefined, false, true, 0, -0, NaN, Infinity, -Infinity,
    1, 1n, '1', '', '__proto__', 'constructor', symbol, fn];
  for (let size = 0; size <= keys.length; size++) {
    const left = keys.slice(0, size);
    const right = left.slice().reverse();
    compareCollection(new Set(left), new Set(right));
    compareCollection(new Map(left.map(key => [key, { value: String(key) }])),
      new Map(right.map(key => [key, { value: String(key) }])));
    compareCollection(new Set(left), new Set(right.concat(Symbol('different'))));
  }
  compareCollection(new Map([[NaN, -0]]), new Map([[NaN, 0]]));
  compareCollection(new Map([[1, undefined]]), new Map([['1', undefined]]));
  compareCollection(new Set([Symbol('same')]), new Set([Symbol('same')]));
  compareCollection(new Set([function x() {}]), new Set([function x() {}]));
});
test('mixed object/primitive keys still use one-to-one structural matching', () => {
  const object = { x: 1 };
  const pairs = [
    [new Set([1, { x: 1 }, { x: 1 }]), new Set([{ x: 1 }, 1, { x: 2 }])],
    [new Set([1, { x: 1 }, { x: 1 }]), new Set([{ x: 1 }, { x: 1 }, 1])],
    [new Map([[object, 'a'], [{ x: 1 }, 'b'], ['p', 7]]),
      new Map([[object, 'b'], [{ x: 1 }, 'a'], ['p', 7]])],
    [new Map([[{ x: 1 }, 'a'], [{ x: 1 }, 'b'], ['p', 7]]),
      new Map([[{ x: 1 }, 'a'], [{ x: 1 }, 'a'], ['p', 7]])],
    [new Map([[{}, 1], ['x', undefined]]), new Map([['x', undefined], [{}, 1]])],
  ];
  for (const [a, b] of pairs) { compareCollection(a, b); compareCollection(b, a); }
  for (let size = 0; size < 100; size++) {
    const pairs = Array.from({ length: size }, (_, i) =>
      [i % 7 === 0 ? { key: i % 3 } : 'key-' + i, { value: i }]);
    const reversed = pairs.map(([key, value]) =>
      [typeof key === 'object' ? { ...key } : key, { ...value }]).reverse();
    compareCollection(new Map(pairs), new Map(reversed));
    if (size) reversed[0][1].value = -1;
    compareCollection(new Map(pairs), new Map(reversed));
  }
});
test('cycles, recursive collections and failed candidate state remain correct', () => {
  const a = new Map(); const b = new Map();
  a.set('self', a); b.set('self', b);
  a.set({ owner: a }, new Set([a, 1])); b.set({ owner: b }, new Set([1, b]));
  compareCollection(a, b);
  const c = new Set(); const d = new Set();
  c.add(c); c.add({ owner: c }); d.add({ owner: d }); d.add(d);
  compareCollection(c, d);
  const x = {}; x.self = x;
  const y = {}; y.self = y;
  const z = {}; z.self = z;
  compareCollection(new Map([[x, 1], [y, 2]]), new Map([[y, 2], [z, 1]]));
  compareCollection(new Map([[x, 1], [y, 2]]), new Map([[y, 1], [z, 1]]));
});
test('reentrant primitive reinsertion cannot reuse a right-hand match', () => {
  const a = new Map(); const b = new Map();
  let reinsert = true;
  const first = { get value() {
    if (reinsert) { reinsert = false; a.delete('first'); a.set('first', first); }
    return 1;
  } };
  a.set('first', first); a.set('second', 2);
  b.set('first', { value: 1 }); b.set('second', 2);
  assert.equal(candidate.isDeepStrictEqual(a, b), false);
  // The next independent comparison has fresh match/cycle state.
  assert.equal(candidate.isDeepStrictEqual(a, b), true);
  const failure = new Error('getter identity');
  const bad = new Map([['x', { get value() { throw failure; } }]]);
  assert.throws(() => candidate.isDeepStrictEqual(bad, new Map([['x', { value: 1 }]])),
    error => error === failure);
  compareCollection(new Map([['x', { value: 1 }]]), new Map([['x', { value: 1 }]]));
});
test('own iterator isolation is retained; ordinary size getters still follow Node', () => {
  for (const make of [() => new Map([['a', 1]]), () => new Set(['a'])]) {
    const a = make(); const b = make();
    for (const key of ['has', 'get', 'set', 'delete', 'entries', 'values', Symbol.iterator]) {
      Object.defineProperty(a, key, { value() { throw new Error('guest method'); } });
    }
    // Intentional pre-existing engine behavior: collection contents use
    // captured iterators. Node 22 consults these guest methods instead.
    // Keep both assertions; do not count this isolation test as parity.
    assert.equal(candidate.isDeepStrictEqual(a, b), true);
    assert.throws(() => util.isDeepStrictEqual(a, b), /guest method/);
    Object.defineProperty(a, 'size', { get() { throw new Error('guest size'); } });
    compareCollection(a, b);
  }
  const a = new Map([['a', 1]]); const b = new Map([['a', 1]]);
  a.extra = 1; b.extra = 2;
  compareCollection(a, b);
  a.extra = b.extra;
  a[Symbol.for('extra')] = 1;
  compareCollection(a, b);
});
test('primitive lookup work is linear on the shipped code, not a model', () => {
  const counts = { has: 0, get: 0, set: 0, delete: 0 };
  const realm = vm.createContext({ TextEncoder, TextDecoder,
    __franken_util_type_tag: typeTag, counts });
  vm.runInContext(`
    var originalMethods = {};
    for (const name of ['has', 'get', 'set', 'delete']) {
      const original = Map.prototype[name];
      originalMethods[name] = original;
      Map.prototype[name] = function (...args) {
        counts[name]++;
        return Reflect.apply(original, this, args);
      };
    }
    var util = ${source};
    for (const name of ['has', 'get', 'set', 'delete']) Map.prototype[name] = originalMethods[name];
  `, realm);
  for (const n of [64, 1024, 4096]) {
    const keys = Array.from({ length: n }, (_, i) => 'package-' + i);
    for (const map of [false, true]) {
      for (const name of Object.keys(counts)) counts[name] = 0;
      realm.a = map ? new Map(keys.map(key => [key, key])) : new Set(keys);
      realm.b = map ? new Map(keys.slice().reverse().map(key => [key, key])) : new Set(keys.slice().reverse());
      assert.equal(vm.runInContext('util.isDeepStrictEqual(a, b)', realm), true);
      assert.deepEqual(counts, { has: n, get: map ? n : 0, set: n, delete: n });
      compareCollection(realm.a, realm.b);
    }
  }
});
console.log(`# ${passed} groups; ${comparisons} live Node parseArgs comparisons; ` +
  `${collectionComparisons} live Node collection comparisons; source=${filename}`);
