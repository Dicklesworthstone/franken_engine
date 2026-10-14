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
console.log(`# ${passed} groups; ${comparisons} live Node parseArgs comparisons; source=${filename}`);
