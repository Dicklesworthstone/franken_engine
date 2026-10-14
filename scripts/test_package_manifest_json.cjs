'use strict';
// Validate the shared native-test fixtures against live Node. This does not
// compile or execute FrankenEngine. No package install or network is needed.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const cases = JSON.parse(fs.readFileSync(path.join(__dirname,
  '../crates/franken-engine/tests/fixtures/package_manifest_json.json'), 'utf8'));
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fe-manifest-json-'));
const files = ['first.cjs', 'last.cjs', 'require.cjs', 'import.cjs', 'index.js'];
const lines = { require: [], import: [] };
for (const entry of cases) {
  const directory = path.join(root, entry.id, 'node_modules/pkg');
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'package.json'), entry.manifest);
  for (const file of files) {
    fs.writeFileSync(path.join(directory, file), 'module.exports = ' + JSON.stringify(file) + ';\n');
  }
  fs.writeFileSync(path.join(directory, 'probe.cjs'),
    'module.exports = require(' + JSON.stringify(entry.specifier) + ');\n');
  fs.writeFileSync(path.join(directory, 'probe.mjs'),
    'import value from ' + JSON.stringify(entry.specifier) + '; export default value;\n');
  lines.require.push('console.log(' + JSON.stringify(entry.id) + ', require(' +
    JSON.stringify('./' + entry.id + '/node_modules/pkg/probe.cjs') + '));');
  lines.import.push('import value' + lines.import.length + ' from ' +
    JSON.stringify('./' + entry.id + '/node_modules/pkg/probe.mjs') + '; console.log(' +
    JSON.stringify(entry.id) + ', value' + lines.import.length + ');');
}
for (const mode of ['require', 'import']) {
  const filename = path.join(root, mode === 'require' ? 'entry.cjs' : 'entry.mjs');
  fs.writeFileSync(filename, lines[mode].join('\n'));
  const result = spawnSync(process.execPath, [filename], { encoding: 'utf8', timeout: 10000 });
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error) throw result.error;
  assert.equal(result.status, 0, mode + ' reference execution');
  assert.deepEqual(result.stdout.trimEnd().split('\n'), cases.map(entry => entry.id + ' ' + entry[mode]));
}
console.log(JSON.stringify({ runtime: process.version, cases: cases.length,
  referenceExecutions: 2, checkedLines: cases.length * 2, root,
  verification: 'live Node reference only; native Rust remains a separate test' }));
