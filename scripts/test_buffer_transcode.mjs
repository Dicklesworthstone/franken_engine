#!/usr/bin/env node
// Source-level semantic differential, NOT a native-engine benchmark or proof.
// Native execution: cargo test -p frankenengine-engine --test buffer_transcode
// An optional source path supports a planted pre-fix negative control.
import assert from 'node:assert/strict';
import * as native from 'node:buffer';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const sourcePath = process.argv[2] || new URL('../crates/franken-engine/src/lowering_pipeline/buffer_module.js', import.meta.url);
const source = readFileSync(sourcePath, 'utf8');
const globals = { Buffer, Blob, atob, btoa, TextDecoder, ArrayBuffer, Uint8Array, Object, String, Error, TypeError };
const candidate = vm.runInNewContext(source, globals, { timeout: 5000 });
const encodings = ['utf8', 'utf16le', 'ascii', 'latin1'];
const cases = [[], [0], [0x80, 0xff], [0xe2, 0x82], [0, 0xd8], [0, 0xd8, 0x41],
  [0x41, 0, 0xff], [0xef, 0xbb, 0xbf, 0x41], [...Buffer.from('A😀é€')], [0x3d, 0xd8, 0, 0xde]];
let seed = 123456789;
for (let index = 0; index < 4096; index++) {
  const bytes = [];
  for (let byte = 0; byte < index % 17; byte++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    bytes.push(seed >>> 24);
  }
  cases.push(bytes);
}
function outcome(transcode, bytes, from, to) {
  try { return { hex: transcode(bytes, from, to).toString('hex') }; }
  catch (error) { return { name: error.name, code: error.code, errno: error.errno }; }
}
let comparisons = 0;
for (const bytes of cases) {
  const input = Buffer.from(bytes);
  for (const from of encodings) {
    for (const to of encodings) {
      assert.deepEqual(outcome(candidate.transcode, input, from, to), outcome(native.transcode, input, from, to),
        `${input.toString('hex')}: ${from} -> ${to}`);
      comparisons++;
    }
  }
}
const fixture = readFileSync(new URL('../crates/franken-engine/tests/fixtures/buffer_transcode/conversions.js', import.meta.url), 'utf8');
for (const module of [native, candidate]) {
  const output = [];
  vm.runInNewContext(fixture, {
    ...globals,
    require(name) { assert.equal(name, 'node:buffer'); return module; },
    console: { log(line) { output.push(line); } },
  }, { timeout: 10000 });
  assert.deepEqual(output, ['buffer transcode: 42 checks']);
}
console.log(JSON.stringify({ node: process.version, source_sha256: createHash('sha256').update(source).digest('hex'), comparisons, fixture_checks: 42 }));
