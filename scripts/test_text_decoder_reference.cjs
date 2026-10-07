'use strict';
// Reference side only. The Rust test file is the canonical native consumer.
// No JavaScript decoder imitates the implementation under test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = fs.readFileSync(path.join(__dirname, '../crates/franken-engine/tests/text_decoder_streaming.rs'), 'utf8');
const programs = new Map([...test.matchAll(/const ([A-Z0-9_]+): &str = r#"([\s\S]*?)"#;/g)].map(m => [m[1], m[2]]));
const cases = [...test.matchAll(/check\(([A-Z0-9_]+), ("(?:[^"\\]|\\.)*")\);/g)].map(m => [m[1], JSON.parse(m[2])]);
assert.equal(cases.length, programs.size, 'all fixtures need exact output checks');
assert.ok(cases.length > 0);
assert.equal(process.argv.length, 2, 'this runner currently checks Node reference output only');
for (const [name, expected] of cases) {
  const result = spawnSync(process.execPath, ['--input-type=commonjs', '-'], {
    input: programs.get(name), encoding: 'utf8', timeout: 5000,
  });
  if (result.error) throw result.error;
  if (result.stderr) process.stderr.write(result.stderr);
  assert.equal(result.status, 0, name);
  assert.equal(result.stdout.trimEnd(), expected, name);
  console.log(`PASS reference ${name}`);
}
console.log(JSON.stringify({ node: process.version, referenceCases: cases.length, nativeRustExecuted: false }));
