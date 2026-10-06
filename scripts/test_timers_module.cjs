#!/usr/bin/env node
'use strict';
// Exact-source bridge tests only. Node supplies timer intrinsics. This does not
// execute the Rust parser, lowering, interpreter, IFC, or capability gates.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');
const timers = require('node:timers');
const promises = require('node:timers/promises');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root,
  'crates/franken-engine/src/lowering_pipeline/timers_module.js'), 'utf8');
const rust = fs.readFileSync(path.join(root,
  'crates/franken-engine/tests/timers_module_objects.rs'), 'utf8');
const fixtures = new Map([...rust.matchAll(/const ([A-Z_]+): &str = r#"([\s\S]*?)"#;/g)]
  .map(match => [match[1], match[2]]));

function candidate(context, overrides = {}) {
  Object.assign(context, {
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
    setImmediate: timers.setImmediate,
    clearImmediate: timers.clearImmediate,
    setInterval: timers.setInterval,
    clearInterval: timers.clearInterval,
    queueMicrotask,
    __franken_timers_timeout: promises.setTimeout,
    __franken_timers_immediate: promises.setImmediate,
    __franken_timers_interval: promises.setInterval,
  }, overrides);
  return vm.runInContext(source, context, { filename: 'timers_module.js', timeout: 1000 });
}

async function runFixture(program, reference) {
  const lines = [];
  const context = vm.createContext({
    console: { log: (...args) => lines.push(args.map(String).join(' ')) },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
    setInterval: timers.setInterval,
    clearInterval: timers.clearInterval,
    setImmediate: timers.setImmediate,
    clearImmediate: timers.clearImmediate,
    queueMicrotask,
  });
  const module = reference ? timers : candidate(context);
  context.require = name => {
    if (name === 'timers' || name === 'node:timers') return module;
    if (name === 'timers/promises' || name === 'node:timers/promises') return module.promises;
    throw new Error(`Unexpected fixture dependency: ${name}`);
  };
  const result = vm.runInContext(program, context, { timeout: 1000 });
  let watchdog;
  try {
    await Promise.race([
      result,
      new Promise((_, reject) => {
        watchdog = timers.setTimeout(() => reject(new Error('fixture timed out')), 3000);
      }),
    ]);
  } finally {
    timers.clearTimeout(watchdog);
  }
  return lines.join('\n');
}

async function main() {
  let differential = 0;
  for (const [name, program] of fixtures) {
    if (name === 'ESM') continue;
    const expected = await runFixture(program, true);
    const actual = await runFixture(program, false);
    assert.equal(actual, expected, name);
    console.log(`PASS shared fixture ${name}`);
    differential++;
  }
  assert.equal(differential, 7, 'fixture discovery must remain exact');

  // Verify forwarding itself, independently of the Node reference scheduler:
  // exact argument identities, original Promise/iterator identity, and throws.
  let bridge = 0;
  const context = vm.createContext({});
  const calls = [];
  const sentinels = [Promise.resolve(42), Promise.resolve(43), { next() {} }];
  const module = candidate(context, {
    __franken_timers_timeout: (...args) => { calls.push(args); return sentinels[0]; },
    __franken_timers_immediate: (...args) => { calls.push(args); return sentinels[1]; },
    __franken_timers_interval: (...args) => { calls.push(args); return sentinels[2]; },
  });
  assert.equal(calls.length, 0, 'loading must not schedule a timer');
  const value = { secret: 42 }, options = { ref: false };
  assert.equal(module.promises.setTimeout(7, value, options), sentinels[0]);
  assert.equal(module.promises.setImmediate(value, options), sentinels[1]);
  assert.equal(module.promises.setInterval(9, value, options), sentinels[2]);
  assert.deepEqual(calls, [[7, value, options], [value, options], [9, value, options]]);
  bridge += 3;
  const denial = new Error('Timer capability denied');
  const refused = candidate(vm.createContext({}), {
    __franken_timers_timeout: () => { throw denial; },
  });
  assert.throws(() => refused.promises.setTimeout(1), error => error === denial);
  bridge++;

  // This is reference-only: no ESM rewriting is simulated here.
  const esm = fixtures.get('ESM');
  assert.equal(typeof esm, 'string');
  const result = spawnSync(process.execPath, ['--input-type=module', '-'], {
    input: esm, encoding: 'utf8', timeout: 3000,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), 'true true\nesm\ntick');
  console.log('PASS ESM fixture (Node reference only)');
  console.log(JSON.stringify({ node: process.version, differentialFixtures: differential,
    bridgeContracts: bridge, esmReferenceOnly: 1, nativeRustExecuted: false }));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
