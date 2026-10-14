'use strict';
// Reference expectation check only. This does NOT execute the Rust engine.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const directory = path.resolve(__dirname, '../../crates/franken-engine/tests/fixtures/atomics');
const result = spawnSync(process.execPath, [path.join(directory, 'notify_queue.js')], {
  encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024,
});
assert.ifError(result.error);
assert.equal(result.status, 0, result.stderr);
assert.equal(result.stderr, '');
assert.equal(result.stdout.trimEnd(), fs.readFileSync(path.join(directory, 'notify_queue.expected'), 'utf8').trimEnd());
console.log('Node reference: all six notification scenarios matched (' + process.version + ')');
