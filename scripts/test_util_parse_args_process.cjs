#!/usr/bin/env node
'use strict';

// Execute the checked-in JS factory and Node's actual util.parseArgs in the
// same invocation. This is a host-JS conformance check, NOT proof that the
// Rust lowerer/interpreter or franken-node CLI executes the factory correctly.
// Run from the engine repository root. An optional source path permits a
// baseline-versus-candidate experiment without changing the test expectations.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const vm = require('node:vm');
const util = require('node:util');

const sourcePath = process.argv[2] ||
  'crates/franken-engine/src/lowering_pipeline/util_module.js';
const source = fs.readFileSync(sourcePath, 'utf8');
const results = [];

function test(name, body) {
  try {
    body();
    results.push({ name, passed: true });
  } catch (error) {
    results.push({ name, passed: false, error: String(error.stack || error) });
  }
}

function load(processDescriptor) {
  const sandbox = {
    TextEncoder,
    TextDecoder,
    __franken_util_inspect: (value, depth) => util.inspect(value, { depth }),
    __franken_util_format: (args) => util.format(...args),
    __franken_util_type_tag: (value) => Object.prototype.toString.call(value).slice(8, -1),
  };
  if (processDescriptor) {
    Object.defineProperty(sandbox, 'process', processDescriptor);
  }
  const context = vm.createContext(sandbox);
  return { context, candidate: vm.runInContext(source, context, { filename: sourcePath }) };
}

function outcome(parse, config) {
  try {
    const result = parse(config);
    // Preserve undefined token fields and property names, while removing
    // cross-realm prototypes from the comparison.
    return {
      ok: true,
      nullPrototype: Object.getPrototypeOf(result.values) === null,
      values: Object.fromEntries(Object.entries(result.values).map(([key, value]) =>
        [key, Array.isArray(value) ? Array.from(value) : value])),
      positionals: Array.from(result.positionals),
      ...(result.tokens ? {
        tokens: Array.from(result.tokens, (token) => Object.fromEntries(Object.entries(token))),
      } : {}),
    };
  } catch (error) {
    return { ok: false, name: error.name, code: error.code, message: error.message };
  }
}

function oracle(argv, execArgv, config) {
  const originalArgv = process.argv;
  const originalExecArgv = process.execArgv;
  try {
    process.argv = argv;
    process.execArgv = execArgv;
    return outcome(util.parseArgs, config);
  } finally {
    process.argv = originalArgv;
    process.execArgv = originalExecArgv;
  }
}

const options = {
  verbose: { type: 'boolean', short: 'v' },
  quiet: { type: 'boolean', short: 'q', default: true },
  color: { type: 'boolean', default: true },
  output: { type: 'string', short: 'o' },
  include: { type: 'string', short: 'I', multiple: true },
};
const config = { options, allowPositionals: true, allowNegative: true, tokens: true };
const cases = [
  ['no options', []],
  ['long boolean', ['--verbose']],
  ['long inline string', ['--output=two words']],
  ['long separate string', ['--output', 'two words']],
  ['short inline string', ['-oresult.json']],
  ['short separate string', ['-o', 'result.json']],
  ['short group', ['-vq']],
  ['short group followed by value', ['-vo', 'result.json']],
  ['short group with inline value', ['-voresult.json']],
  ['repeatable short values', ['-Ione', '-I', 'two']],
  ['repeatable mixed values', ['--include=one', '-Itwo', '--include', 'three']],
  ['negative boolean', ['--no-color']],
  ['last boolean wins', ['--no-color', '--color']],
  ['last string wins', ['-oone', '--output=two']],
  ['terminator preserves dashes', ['--', '--verbose', '-x', 'two words']],
  ['empty string positional', ['']],
  ['unicode positional', ['snowman-☃', 'é', '文件']],
  ['long inline empty value', ['--output=']],
  ['equals inside value', ['--output=a=b=c']],
  ['unknown option error', ['--unknown']],
  ['missing value error', ['--output']],
  ['ambiguous value error', ['--output', '--verbose']],
  ['boolean value error', ['--verbose=true']],
  ['single dash positional', ['-']],
];

for (const [name, args] of cases) {
  for (const [layout, execArgv, prefix] of [
    ['file', [], ['franken-node', '/project/app.js']],
    ['eval', ['--eval', 'ignored'], ['franken-node']],
  ]) {
    test(`${layout}: ${name}`, () => {
      const argv = Object.freeze([...prefix, ...args]);
      const flags = Object.freeze([...execArgv]);
      const { candidate } = load({ value: { argv, execArgv: flags } });
      assert.deepStrictEqual(outcome(candidate.parseArgs, config), oracle(argv, flags, config));
    });
  }
}

for (const flag of ['-e', '--eval', '-p', '--print']) {
  test(`Node layout switch ${flag}`, () => {
    const argv = ['franken-node', '--verbose', '-o', 'out'];
    const flags = ['--trace-warnings', flag, 'ignored'];
    const { candidate } = load({ value: { argv, execArgv: flags } });
    assert.deepStrictEqual(outcome(candidate.parseArgs, config), oracle(argv, flags, config));
  });
}

test('absent execArgv uses embedded file-entry layout', () => {
  const argv = ['franken-node', '/app.js', '--verbose', '--output=embedded'];
  const { candidate } = load({ value: { argv } });
  assert.deepStrictEqual(outcome(candidate.parseArgs, config), oracle(argv, [], config));
});

for (const [name, makeConfig] of [
  ['undefined config', () => undefined],
  ['empty config', () => ({})],
  ['args undefined', () => ({ ...config, args: undefined })],
  ['args null', () => ({ ...config, args: null })],
  ['inherited args ignored', () => Object.assign(Object.create({ args: ['--unknown'] }), config)],
]) {
  test(name, () => {
    const argv = ['franken-node', '/app.js', '--verbose'];
    const { candidate } = load({ value: { argv } });
    assert.deepStrictEqual(outcome(candidate.parseArgs, makeConfig()), oracle(argv, [], makeConfig()));
  });
}

test('explicit args override real argv', () => {
  const argv = ['franken-node', '/app.js', '--unknown'];
  const { candidate } = load({ value: { argv } });
  const explicit = { ...config, args: ['--output=explicit'] };
  assert.deepStrictEqual(outcome(candidate.parseArgs, explicit), oracle(argv, [], explicit));
});

test('import and explicit args never access process', () => {
  let reads = 0;
  const { candidate } = load({
    get() { reads += 1; throw new Error('process denied'); },
  });
  assert.equal(reads, 0);
  for (const args of [[], ['--verbose'], ['--output=x']]) {
    const explicit = { ...config, args };
    assert.deepStrictEqual(outcome(candidate.parseArgs, explicit), outcome(util.parseArgs, explicit));
  }
  assert.equal(reads, 0);
});

test('explicit args work without a process global', () => {
  const { candidate } = load();
  const explicit = { ...config, args: ['--verbose'] };
  assert.deepStrictEqual(outcome(candidate.parseArgs, explicit), outcome(util.parseArgs, explicit));
});

test('default args propagate denied process access', () => {
  const denied = new Error('process denied');
  const { candidate } = load({ value: { get argv() { throw denied; } } });
  assert.throws(() => candidate.parseArgs(config), (error) => error === denied);
});

test('default args do not silently use an empty list without process', () => {
  const { candidate } = load();
  assert.equal(outcome(candidate.parseArgs, config).name, 'ReferenceError');
});

test('each call reads current argv instead of a module initialization snapshot', () => {
  const realmProcess = { argv: ['franken-node', '/app.js', '--output=one'] };
  const { candidate } = load({ value: realmProcess });
  assert.equal(candidate.parseArgs(config).values.output, 'one');
  realmProcess.argv = ['franken-node', '/app.js', '--output=two'];
  assert.equal(candidate.parseArgs(config).values.output, 'two');
});

test('realm arguments cannot leak the embedding host command line', () => {
  const argv = ['franken-node', '/sandbox.js', '--output=realm'];
  const saved = process.argv;
  try {
    process.argv = ['node', '/host.js', '--output=HOST_SECRET'];
    const { candidate } = load({ value: { argv } });
    assert.equal(candidate.parseArgs(config).values.output, 'realm');
  } finally {
    process.argv = saved;
  }
});

test('default argv is copied before option configuration getters run', () => {
  function run(parse, argv) {
    return outcome(parse, {
      get options() {
        argv.splice(2, argv.length, '--output=mutated');
        return options;
      },
    });
  }
  const argv = ['franken-node', '/app.js', '--output=original'];
  const { candidate } = load({ value: { argv } });
  const actual = run(candidate.parseArgs, argv);
  const originalArgv = process.argv;
  const originalExecArgv = process.execArgv;
  try {
    process.argv = ['franken-node', '/app.js', '--output=original'];
    process.execArgv = [];
    assert.deepStrictEqual(actual, run(util.parseArgs, process.argv));
    assert.equal(actual.values.output, 'original');
  } finally {
    process.argv = originalArgv;
    process.execArgv = originalExecArgv;
  }
});

test('array instance slice/includes overrides are not called', () => {
  const argv = ['franken-node', '--verbose'];
  const execArgv = ['--eval'];
  Object.defineProperty(argv, 'slice', { value() { throw new Error('user slice'); } });
  Object.defineProperty(execArgv, 'includes', { value() { throw new Error('user includes'); } });
  const { candidate } = load({ value: { argv, execArgv } });
  assert.deepStrictEqual(outcome(candidate.parseArgs, config), oracle(argv, execArgv, config));
});

test('intrinsics remain captured after module initialization', () => {
  const argv = ['franken-node', '--verbose'];
  const execArgv = ['--eval'];
  const { context, candidate } = load({ value: { argv, execArgv } });
  vm.runInContext(`
    Array.prototype.slice = function () { throw new Error('modified slice'); };
    Array.prototype.includes = function () { throw new Error('modified includes'); };
    Reflect.apply = function () { throw new Error('modified apply'); };
  `, context);
  assert.deepStrictEqual(outcome(candidate.parseArgs, config), oracle(argv, execArgv, config));
});

const passed = results.filter((result) => result.passed).length;
console.log(JSON.stringify({
  proofClass: 'host-js-reference-only',
  nodeVersion: process.version,
  sourcePath,
  sourceSha256: crypto.createHash('sha256').update(source).digest('hex'),
  passed,
  failed: results.length - passed,
  results,
}, null, 2));
if (passed !== results.length) process.exitCode = 1;
