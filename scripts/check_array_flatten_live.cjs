'use strict';
// Runs the same source/expected pairs as the native public evaluator test.
// This checks reference expectations only; it is not a native-engine verdict.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const input = process.argv[2] || path.join(__dirname, '..', 'crates', 'franken-engine',
  'tests', 'fixtures', 'array_flatten_live.json');
const cases = JSON.parse(fs.readFileSync(input, 'utf8'));
for (const test of cases) {
  const actual = vm.runInNewContext(test.source, {}, { timeout: 10000, filename: test.name });
  assert.equal(actual, test.expected, test.name);
  console.log(`PASS ${test.name}`);
}
console.log(JSON.stringify({ node: process.version, v8: process.versions.v8, passed: cases.length }));
