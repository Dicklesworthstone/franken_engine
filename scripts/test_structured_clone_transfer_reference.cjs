'use strict';
// Verifies expectations embedded in the native tests against live Node/V8.
// This does NOT run FrankenEngine or substitute for its Rust integration tests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const source = fs.readFileSync(path.join(__dirname,
  '../crates/franken-engine/tests/structured_clone_transfer.rs'), 'utf8');
const programs = new Map([...source.matchAll(/const ([A-Z_]+): &str = r#"([\s\S]*?)"#;/g)]
  .map(match => [match[1], match[2]]));
const checks = [...source.matchAll(/check\(([A-Z_]+), &(\[[^\n]+\])\);/g)];
assert.equal(checks.length, programs.size, 'each program must have an expectation');
assert(checks.length > 0, 'no native reference cases discovered');
// Web IDL sequence conversion uses GetIteratorFromMethod / IteratorStepValue:
// https://webidl.spec.whatwg.org/#create-sequence-from-iterable
// Node 22.16 re-reads `next` here, whereas the standard caches it once. Keep
// the native normative assertion; report, rather than conceal, that difference.
const knownNodeObservations = {
  ITERATOR: ['transfer,receiver,next0,next1,next2,graph 1 3 0 0 2', 'true 0'],
};
let matches = 0;
let differences = 0;
for (const [, name, expected] of checks) {
  const result = spawnSync(process.execPath, ['-e', programs.get(name)], {
    encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${name}: ${result.stderr}`);
  assert.equal(result.stderr, '', `${name}: unexpected diagnostics`);
  const actual = result.stdout.trimEnd().split('\n');
  const normative = JSON.parse(expected);
  if (JSON.stringify(actual) === JSON.stringify(normative)) {
    matches++;
    console.log(`${name}: matches live Node ${process.version}`);
  } else {
    assert.deepEqual(actual, knownNodeObservations[name], `${name}: unexplained difference`);
    differences++;
    console.log(`${name}: documented Node/standard difference`);
    console.log(JSON.stringify({ normative, node: actual }));
  }
}
console.log(`${matches} matching reference programs; ${differences} documented differences. Native Rust tests are a separate gate.`);
