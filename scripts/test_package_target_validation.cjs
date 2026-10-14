'use strict';
// Live Node verification of the native package-target regression corpus.
// No alternate JS resolver and no claim that these checks execute Rust.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRequire } = require('node:module');
const { pathToFileURL } = require('node:url');
const cases = JSON.parse(fs.readFileSync(path.join(__dirname,
  '../crates/franken-engine/tests/fixtures/package_target_validation.json'), 'utf8'));
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fe-package-targets-'));
function expected(entry, internal) {
  return entry.value !== null ? { value: entry.value } : { error:
    entry.node_error === 'excluded'
      ? internal ? 'ERR_PACKAGE_IMPORT_NOT_DEFINED' : 'ERR_PACKAGE_PATH_NOT_EXPORTED'
      : entry.node_error };
}
(async () => {
  let checks = 0;
  let differingErrorClasses = 0;
  for (const [index, entry] of cases.entries()) {
    const directory = path.join(root, String(index), 'node_modules/pkg');
    fs.mkdirSync(directory, { recursive: true });
    const pattern = entry.capture !== null;
    const target = JSON.parse(entry.target);
    fs.writeFileSync(path.join(directory, 'package.json'), JSON.stringify({ name: 'pkg',
      exports: { [pattern ? './*' : '.']: target },
      imports: { [pattern ? '#x/*' : '#x']: target } }));
    for (const file of new Set(['first.cjs', 'last.cjs', entry.value].filter(x => x !== null))) {
      fs.writeFileSync(path.join(directory, file), 'module.exports = ' + JSON.stringify(file) + ';\n');
    }
    const requireFromPackage = createRequire(path.join(directory, 'probe.cjs'));
    for (const internal of [false, true]) {
      const specifier = (internal ? '#x' : 'pkg') + (pattern ? '/' + entry.capture : '');
      let actual;
      try { actual = { value: requireFromPackage(specifier) }; }
      catch (error) { actual = { error: error.code || error.name }; }
      assert.deepEqual(actual, expected(entry, internal), entry.id + ' require ' + internal);
      const probe = path.join(directory, 'probe-' + internal + '.mjs');
      fs.writeFileSync(probe, 'export default await import(' + JSON.stringify(specifier) +
        ').then(m => ({value:m.default}), e => ({error:e.code || e.name}));\n');
      const loaded = await import(pathToFileURL(probe).href);
      assert.deepEqual(loaded.default, expected(entry, internal), entry.id + ' import ' + internal);
      checks += 2;
    }
    if (entry.node_error !== entry.error) differingErrorClasses++;
  }
  console.log(JSON.stringify({ runtime: process.version, cases: cases.length, checks,
    differingErrorClasses, root,
    note: 'URIError is retained as an explicit Node observation; the native boundary uses invalid-specifier diagnostics. Rust tests are separate.' }));
})().catch(error => { console.error(error); process.exitCode = 1; });
