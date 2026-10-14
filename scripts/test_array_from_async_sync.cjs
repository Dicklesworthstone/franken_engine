'use strict';
// A live Node reference, NOT native Rust verification. Native expected output
// always remains the specification-derived `expected` field. Known Node 22
// disagreements and nonsettling probes are reported separately, never as passes.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const cases = JSON.parse(fs.readFileSync(path.join(__dirname,
  '../crates/franken-engine/tests/fixtures/array_from_async/sync_protocol.json'), 'utf8'));
const results = [];
for (const fixture of cases) {
  const code = `const vm = require('node:vm');
    const timer=setTimeout(()=>{console.error('REFERENCE_TIMEOUT');process.exitCode=2;},1500);
    Promise.resolve(vm.runInThisContext(${JSON.stringify(fixture.source)})).then(
      ()=>clearTimeout(timer),error=>{clearTimeout(timer);console.error(error);process.exitCode=1;});`;
  const child = spawnSync(process.execPath, ['-e', code], { encoding: 'utf8', timeout: 2500 });
  const actual = child.stdout.trimEnd();
  const agreement = child.status === 0 && actual === fixture.expected;
  const recorded = process.version === 'v22.16.0' && fixture.node_v22_16_0;
  const nonsettling = (child.error && child.error.code === 'ETIMEDOUT') ||
    (child.status === 2 && child.stderr.trim() === 'REFERENCE_TIMEOUT');
  let classification = agreement ? 'spec-agreement' : 'unexpected';
  if (!agreement && recorded) {
    if (recorded.nonsettling && nonsettling) classification = 'nonsettling-reference';
    else if (child.status === 0 && actual === recorded.output) classification = 'documented-reference-difference';
  }
  results.push({ name: fixture.name, classification, status: child.status,
    actual, expected: fixture.expected, stderr: child.stderr,
    error: child.error ? String(child.error) : null,
    reason: recorded ? recorded.reason : null });
}
const count = kind => results.filter(x => x.classification === kind).length;
console.log(JSON.stringify({ runtime: process.version, proof_class: 'node-reference-only',
  total: results.length, agreement: count('spec-agreement'),
  documented_differences: count('documented-reference-difference'),
  nonsettling: count('nonsettling-reference'), unexpected: count('unexpected'), results }, null, 2));
process.exitCode = count('unexpected') ? 1 : 0;
