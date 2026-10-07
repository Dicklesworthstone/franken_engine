#!/usr/bin/env node
'use strict';
// Reference expectations only: this does NOT run the Rust cloning implementation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const file = fs.readFileSync(path.join(__dirname,
  '../crates/franken-engine/tests/structured_clone_graph.rs'), 'utf8');
const programs = new Map([...file.matchAll(/const ([A-Z_]+): &str = r#"([\s\S]*?)"#;/g)]
  .map(match => [match[1], match[2]]));
const expectations = [...file.matchAll(/check\(([A-Z_]+), &(\[[^\n]+\])\);/g)]
  .map(match => [match[1], JSON.parse(match[2])]);
assert.equal(programs.size, 12, 'fixture discovery');
assert.equal(expectations.length, programs.size, 'every fixture has expected output');
for (const [name, expected] of expectations) {
  assert.ok(programs.has(name), name);
  const result = spawnSync(process.execPath, ['--input-type=commonjs', '-'], {
    input: programs.get(name), encoding: 'utf8', timeout: 5000,
  });
  if (result.error) throw result.error;
  if (result.stderr) process.stderr.write(result.stderr);
  assert.equal(result.status, 0, name);
  assert.equal(result.stdout.trimEnd(), expected.join('\n'), name);
  console.log(`PASS Node reference ${name}`);
}
console.log(JSON.stringify({ node: process.version, referencePrograms: programs.size,
  nativeRustExecuted: false }));
