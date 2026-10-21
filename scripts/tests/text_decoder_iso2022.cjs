'use strict';
// Live reference only. This runner does NOT execute the Rust decoder. Keep
// normative expected output even when Node's ICU-backed decoder differs.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const fixture = path.join(__dirname, '../../crates/franken-engine/tests/fixtures/text_decoder/iso2022.json');
const cases = JSON.parse(fs.readFileSync(fixture, 'utf8'));
let passed = 0, failed = 0;
for (const test of cases) {
  const run = spawnSync(process.execPath, ['-e', test.source], { encoding: 'utf8', timeout: 10000 });
  try {
    assert.ifError(run.error);
    assert.equal(run.status, 0, run.stderr);
    assert.deepEqual(run.stdout.trimEnd().split('\n'), test.expected);
    passed++;
    console.log('PASS ' + test.name);
  } catch (error) {
    failed++;
    console.error('FAIL ' + test.name + (test.reference_note ? ': ' + test.reference_note : ''));
    console.error(error.message);
  }
}
console.log(JSON.stringify({ runtime: process.version, reference_only: true, passed, failed }));
process.exitCode = failed ? 1 : 0;
