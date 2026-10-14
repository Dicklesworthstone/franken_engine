'use strict';
// Live Node reference for the exact native integration-test source. This is
// NOT execution of FrankenEngine or verification of its IFC label assertions.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.join(__dirname, '../crates/franken-engine/tests/fixtures/set_algebra');
const source = fs.readFileSync(path.join(root, 'protocol_observations.js'), 'utf8');
const expected = fs.readFileSync(path.join(root, 'protocol_observations.expected'), 'utf8').trimEnd();
const actual = vm.runInNewContext(source, {}, { timeout: 10000, filename: 'set-protocol.js' });
assert.equal(actual, expected);
console.log(JSON.stringify({ runtime: process.version, expectedLines: expected.split('\n').length,
  protocolFailureCases: 12, matches: true, nativeRustExecuted: false }));
