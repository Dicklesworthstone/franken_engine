'use strict';
// Reference oracle only: this does not execute the Rust implementation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '../crates/franken-engine/tests/fixtures/array_mutation');
const program = path.join(root, 'property_operations.js');
const expected = fs.readFileSync(path.join(root, 'property_operations.expected'), 'utf8');
const run = spawnSync(process.execPath, [program], { encoding: 'utf8', timeout: 20000 });
if (run.error) throw run.error;
assert.equal(run.status, 0, run.stderr);
assert.equal(run.stdout, expected);
console.log(JSON.stringify({ host: process.version,
  checked_lines: expected.trimEnd().split('\n').length,
  scope: 'live_node_reference', native_rust_executed: false }));
