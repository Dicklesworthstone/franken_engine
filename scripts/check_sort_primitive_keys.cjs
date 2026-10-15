#!/usr/bin/env node
'use strict';
// Execute every shared source case in a fresh V8 context, retaining failures.
// This validates reference expectations, not the native Rust implementation.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const file = process.argv[2] || path.join(__dirname, '..', 'crates', 'franken-engine', 'tests', 'fixtures', 'array_sort_primitive_keys.json');
const cases = JSON.parse(fs.readFileSync(file, 'utf8'));
let failed = 0;
for (const test of cases) {
  try {
    const actual = String(vm.runInNewContext(test.source, Object.create(null), {timeout: 5000}));
    const pass = actual === test.expected;
    if (!pass) failed++;
    console.log(JSON.stringify({name: test.name, pass, expected: test.expected, actual}));
  } catch (error) {
    failed++;
    console.log(JSON.stringify({name: test.name, pass: false, error: String(error)}));
  }
}
console.log(JSON.stringify({node: process.version, v8: process.versions.v8, cases: cases.length, failed}));
process.exitCode = failed ? 1 : 0;
