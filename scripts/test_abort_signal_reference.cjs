#!/usr/bin/env node
'use strict';
// Runs only the reference side of the shared native Rust fixtures. This is
// deliberately NOT a Rust test runner or an adapter pretending to be the engine.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = fs.readFileSync(path.join(__dirname, '..', 'crates/franken-engine/tests/abort_signal_composition.rs'), 'utf8');
const programs = new Map([...test.matchAll(/const ([A-Z_]+): &str = r#"([\s\S]*?)"#;/g)]
  .map(match => [match[1], match[2]]));
const assertions = [...test.matchAll(/check\(([A-Z_]+), &(\[[^\n]+\])\);/g)]
  .map(match => [match[1], JSON.parse(match[2])]);
assert.equal(programs.size, 17, 'all fixture programs must be discovered');
assert.equal(assertions.length, programs.size, 'every program needs expected lines');
let referenceCases = 0;
// Preserve the engine's existing registration-identity/snapshot expectations,
// but execute and report Node's distinct observations instead of silently
// presenting these three native-only cases as parity passes.
const divergentReferences = new Map([
  ['NATIVE_LISTENER_REPLACEMENT', ['0', '0']],
  ['NATIVE_ONCE_REENTRANCY', ['once,replacement,abort,replacement']],
  ['NATIVE_REMOVE_DURING_DISPATCH', ['first', 'first', 'first']],
]);
let referenceDifferences = 0;
for (const [name, expected] of assertions) {
  assert.ok(programs.has(name), name);
  const different = divergentReferences.get(name);
  if (name.startsWith('NATIVE_') && !different) continue;
  const result = spawnSync(process.execPath, ['--input-type=commonjs', '-'], {
    input: programs.get(name), encoding: 'utf8', timeout: 5000,
  });
  if (result.error) throw result.error;
  if (result.stderr) process.stderr.write(result.stderr);
  assert.equal(result.status, 0, name);
  assert.equal(result.stdout.trimEnd(), (different || expected).join('\n'), name);
  if (different) {
    assert.notDeepEqual(different, expected, name);
    console.log(`Node reference difference (not a parity pass) ${name}`);
    referenceDifferences++;
    continue;
  }
  console.log(`PASS Node reference ${name}`);
  referenceCases++;
}
assert.equal(referenceCases, 12);
assert.equal(referenceDifferences, 3);
console.log(JSON.stringify({ node: process.version, referenceCases,
  referenceDifferences,
  nativePolicyCasesNotExecuted: 5, nativeBudgetCaseNotExecuted: 1,
  nativeRustExecuted: false }));
