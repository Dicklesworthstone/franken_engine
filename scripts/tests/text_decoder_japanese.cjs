'use strict';
// Run the unchanged native-test programs on an incumbent, not a JS substitute
// for the candidate. A difference is a failure, not a waiver or a native pass.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const fixtures = JSON.parse(fs.readFileSync(path.join(__dirname,
  '../../crates/franken-engine/tests/fixtures/text_decoder/japanese.json'), 'utf8'));
const results = [];
for (const fixture of fixtures) {
  const output = [];
  let error = null;
  try {
    new vm.Script(fixture.source, { filename: fixture.name + '.js' }).runInNewContext({
      TextDecoder,
      console: { log(...values) { output.push(values.map(String).join(' ')); } },
    }, { timeout: 10000 });
  } catch (caught) { error = { name: caught.name, message: caught.message }; }
  const agreement = error === null && JSON.stringify(output) === JSON.stringify(fixture.expected);
  results.push({ name: fixture.name, agreement, expected: fixture.expected, actual: output, error });
}
console.log(JSON.stringify({ runtime: process.version, proof: 'node-reference-only',
  total: results.length, agreements: results.filter(result => result.agreement).length,
  differences: results.filter(result => !result.agreement).length, results }, null, 2));
if (results.some(result => !result.agreement)) process.exitCode = 1;
