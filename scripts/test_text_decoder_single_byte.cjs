'use strict';
// A live Node reference, never a substitute for the native Rust tests.
// Differences fail this command and are reported, not converted to passes.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.join(__dirname, '../crates/franken-engine/tests/fixtures');
const fixture = JSON.parse(fs.readFileSync(path.join(root, 'text_decoder_single_byte.json'), 'utf8'));
const program = fs.readFileSync(path.join(root, 'text_decoder_single_byte.js'), 'utf8');
const results = [];
for (const entry of fixture.encodings) {
  const output = [];
  let failure;
  try {
    vm.runInNewContext(program, {
      __case: entry, TextDecoder, Uint8Array, DataView, Error, TypeError, RangeError,
      console: { log: value => output.push(value) },
    }, { filename: entry.name + '.js', timeout: 5000 });
  } catch (error) { failure = { name: error.name, message: error.message, code: error.code }; }
  const missing = entry.high.filter(value => value === null).length;
  const expected = 'LEGACY_SINGLE_BYTE_OK ' + entry.name + ' ' + missing;
  const matches = failure === undefined && output.length === 1 && output[0] === expected;
  results.push({ encoding: entry.name, matches, output, expected, failure });
}
const agreed = results.filter(result => result.matches).length;
console.log(JSON.stringify({ runtime: process.version, total: results.length, agreed,
  differed: results.length - agreed, proof: 'Node reference only; native Rust not executed', results }, null, 2));
if (agreed !== results.length) process.exitCode = 1;
