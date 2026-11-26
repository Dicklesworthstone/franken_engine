#!/usr/bin/env node
// Exercise the delivered ESM with an independent Node runtime. This verifies
// module loading semantics; it makes no React rendering or browser claim.
// Usage: node scripts/e2e/react_client_dynamic_imports.mjs /path/to/frankenctl
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

assert.equal(process.argv.length, 3, "Pass the built frankenctl binary as the only argument");
const frankenctl = resolve(process.argv[2]);
assert.ok(existsSync(frankenctl), `frankenctl binary does not exist: ${frankenctl}`);
const project = mkdtempSync(join(tmpdir(), "franken-react-dynamic-imports-"));

function run(command, args, timeout = 30_000) {
  const result = spawnSync(command, args, {
    cwd: project,
    encoding: "utf8",
    timeout,
    maxBuffer: 8 * 1024 * 1024,
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null, `${command} terminated with ${result.signal}`);
  return result;
}

function build(entry, outDir, root = project) {
  return run(frankenctl, [
    "react", "build", "--entry", entry, "--target", "client",
    "--root", root, "--out-dir", outDir,
  ]);
}

function expectSuccess(result, label) {
  assert.equal(
    result.status, 0,
    `${label} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  return result.stdout;
}

function expectRefusal(entry, outDir, code, root = project) {
  const result = build(entry, outDir, root);
  assert.notEqual(result.status, 0, `Expected ${code} for ${entry}`);
  assert.ok(result.stderr.includes(code), `${code} missing from stderr:\n${result.stderr}`);
  assert.equal(existsSync(outDir), false, "A refused graph must not publish partial assets");
}

try {
  const sources = {
    "entry.js": [
      "import { label } from './constants.js';",
      "globalThis.lazyRuns = 0;",
      "console.log(label + ':start');",
      "const pending = import /* keep the call lazy */ ('./lazy.js');",
      "console.log(label + ':scheduled');",
      "const lazy = await pending;",
      "console.log(label + ':loaded ' + lazy.answer);",
      "const again = await import('./lazy.js');",
      "console.log(label + ':cached ' + (again === lazy) + ' ' + globalThis.lazyRuns);",
      "const loadAgain = () => import('./lazy.js');",
      "console.log(label + ':nested ' + (await loadAgain()).answer);",
      "const describe = async () => `entry:template ${(await import('./lazy.js')).answer}`;",
      "console.log(await describe());",
      "const text = \"import('./ghost.js')\";",
      String.raw`const regex = /import\('\.\/ghost.js'\)/;`,
      "const object = { import(path) { return path; } };",
      "console.log(label + ':inert ' + (regex.test(text) && object.import('./ghost.js') === './ghost.js'));",
      "",
    ].join("\n"),
    "constants.js": "export const label = 'entry';\n",
    "lazy.js": [
      "globalThis.lazyRuns += 1;",
      "console.log('lazy:evaluated');",
      "export const answer = 42;",
      "",
    ].join("\n"),
  };
  writeFileSync(join(project, "package.json"), '{"type":"module"}\n');
  for (const [name, source] of Object.entries(sources)) {
    writeFileSync(join(project, name), source);
  }

  const entry = join(project, "entry.js");
  const outDir = join(project, "dist");
  const report = JSON.parse(expectSuccess(build(entry, outDir), "client build"));
  assert.equal(report.blocked, false);
  assert.equal(typeof report.build_directory, "string");
  assert.deepEqual(report.build.import_map, {});
  assert.deepEqual(
    report.build.modules.map((module) => module.source_path),
    ["constants.js", "entry.js", "lazy.js"],
  );
  for (const module of report.build.modules) {
    const asset = join(report.build_directory, module.asset_path);
    assert.equal(readFileSync(asset, "utf8"), module.code, "Published code differs from receipt");
    assert.equal(typeof module.source_map, "string");
    assert.equal(readFileSync(`${asset}.map`, "utf8"), module.source_map);
    assert.equal(JSON.parse(module.source_map).sourcesContent[0], sources[module.source_path]);
  }
  const repeated = JSON.parse(expectSuccess(build(entry, outDir), "repeat client build"));
  assert.deepEqual(repeated.build, report.build, "An unchanged graph must rebuild deterministically");
  assert.equal(repeated.build_directory, report.build_directory);

  const expected = [
    "entry:start",
    "entry:scheduled",
    "lazy:evaluated",
    "entry:loaded 42",
    "entry:cached true 1",
    "entry:nested 42",
    "entry:template 42",
    "entry:inert true",
    "",
  ].join("\n");
  const original = expectSuccess(run(process.execPath, [entry], 10_000), "original ESM");
  const emittedEntry = join(report.build_directory, report.build.entry_asset);
  const emitted = expectSuccess(run(process.execPath, [emittedEntry], 10_000), "emitted ESM");
  assert.equal(original, expected, "The independent runtime fixture must match its stated contract");
  assert.equal(emitted, expected, "Emitted lazy order or namespace caching changed");
  assert.equal(emitted, original);

  const computed = join(project, "computed.js");
  writeFileSync(computed, "const path = './lazy.js'; export const load = () => import(path);\n");
  expectRefusal(computed, join(project, "computed-dist"), "FE-REACT-BUILD-DYNAMIC");

  const missing = join(project, "missing.js");
  writeFileSync(missing, "export const neverCalled = () => import('./absent.js');\n");
  expectRefusal(missing, join(project, "missing-dist"), "FE-REACT-BUILD-MISSING");

  const confined = join(project, "confined");
  mkdirSync(confined);
  const escaping = join(confined, "entry.js");
  writeFileSync(escaping, "export const load = () => import('../lazy.js');\n");
  expectRefusal(escaping, join(project, "escaping-dist"), "FE-REACT-BUILD-ROOT", confined);

  const jsonSources = {
    "json-entry.js": [
      "import './json-poison.js';",
      "import data, { default as again } from './config.json' with { type: 'json' };",
      "import * as ns from './config.json' with { type: 'json' };",
      "import { config, values } from './json-reexport.js';",
      "console.log(data === again && data === ns.default && data === config && data === values.default);",
      "console.log(Object.keys(ns).join(','));",
      "console.log(Object.getPrototypeOf(data) === Object.prototype, Object.hasOwn(data, '__proto__'), data.__proto__.safe);",
      "console.log(data.duplicate, 1 / data.negativeZero, data.overflow, data.rounded);",
      "console.log(data.lone.charCodeAt(0), data['\\udfff'].charCodeAt(0), data['\\udfff'].charCodeAt(1));",
      "console.log(data.separators.charCodeAt(0), data.separators.charCodeAt(1));",
      "data.shared = 7; console.log(config.shared, ns.default.shared);",
      "const load = () => import('./config.json', { with: { type: 'json' } });",
      "const dynamic = await load(); console.log(dynamic === ns, dynamic.default.shared);",
      "const lazyOnly = await import('./lazy-only.json', { with: { type: 'json' } });",
      "console.log(lazyOnly.default.answer, Object.keys(lazyOnly).join(','));",
      "",
    ].join("\n"),
    "json-poison.js": "JSON.parse = () => { throw new Error('a JSON module must not call a replaced JSON.parse'); };\n",
    "json-reexport.js": [
      "export { default as config } from './config.json' with { type: 'json' };",
      "export * as values from './config.json' with { type: 'json' };",
      "",
    ].join("\n"),
    "lazy-only.json": '{"answer":42}\n',
    "config.json": String.raw`{"__proto__":{"safe":true},"duplicate":1,"duplicate":2,"negativeZero":-0,"overflow":1e400,"rounded":9007199254740993,"lone":"\ud800","\udfff":"\u2028\u2029","separators":"` + "\u2028\u2029" + '"}\n',
  };
  for (const [name, source] of Object.entries(jsonSources)) {
    writeFileSync(join(project, name), source);
  }
  const jsonEntry = join(project, "json-entry.js");
  const jsonOut = join(project, "json-dist");
  const jsonReport = JSON.parse(expectSuccess(build(jsonEntry, jsonOut), "typed JSON client build"));
  assert.equal(jsonReport.build.modules.length, 5);
  assert.deepEqual(
    JSON.parse(expectSuccess(build(jsonEntry, jsonOut), "repeat typed JSON build")).build,
    jsonReport.build,
    "JSON data and compiler output must rebuild deterministically",
  );
  const jsonAsset = jsonReport.build.modules.find((module) => module.source_path === "config.json");
  assert.ok(jsonAsset);
  assert.equal(JSON.parse(jsonAsset.source_map).sourcesContent[0], jsonSources["config.json"]);
  assert.equal(readFileSync(join(jsonReport.build_directory, jsonAsset.asset_path), "utf8"), jsonAsset.code);
  assert.equal(readFileSync(join(jsonReport.build_directory, `${jsonAsset.asset_path}.map`), "utf8"), jsonAsset.source_map);
  const jsonExpected = [
    "true",
    "default",
    "true true true",
    "2 -Infinity Infinity 9007199254740992",
    "55296 8232 8233",
    "8232 8233",
    "7 7",
    "true 7",
    "42 default",
    "",
  ].join("\n");
  const nativeJson = expectSuccess(run(process.execPath, [jsonEntry]), "Node JSON module loader");
  const compiledJson = expectSuccess(
    run(process.execPath, [join(jsonReport.build_directory, jsonReport.build.entry_asset)]),
    "emitted JSON modules",
  );
  assert.equal(nativeJson, jsonExpected);
  assert.equal(compiledJson, nativeJson, "JSON values, namespaces or data-property semantics changed");

  for (const [name, source, code] of [
    ["untyped-json.js", "import './config.json';", "FE-REACT-BUILD-ATTRIBUTES"],
    ["named-json.js", "import { duplicate } from './config.json' with { type: 'json' };", "FE-REACT-BUILD-EXPORT"],
    ["wrong-json-type.js", "import './json-poison.js' with { type: 'json' };", "FE-REACT-BUILD-ATTRIBUTES"],
    ["unknown-json-attribute.js", "import './config.json' with { type: 'json', integrity: 'unchecked' };", "FE-REACT-BUILD-ATTRIBUTES"],
    ["malformed-lazy-json.js", "export const load = () => import('./invalid.json', { with: { type: 'json' } });", "FE-REACT-BUILD-JSON"],
    ["computed-json-options.js", "export const load = () => import('./config.json', { with: { type: getType() } });", "FE-REACT-BUILD-DYNAMIC"],
    ["malformed-json.js", "import './invalid.json' with { type: 'json' };", "FE-REACT-BUILD-JSON"],
  ]) {
    writeFileSync(join(project, name), source);
    writeFileSync(join(project, "invalid.json"), '{"x":1,}\n');
    expectRefusal(join(project, name), join(project, `${name}-dist`), code);
  }

  console.log("PASS: emitted client ESM preserves lazy order, module caching, nested calls and template substitutions.");
  console.log("PASS: computed, missing and escaping imports are refused before publication.");
  console.log("PASS: typed JSON modules match Node for shared defaults, __proto__, duplicate keys, exact UTF-16 and numeric edges.");
  console.log("PASS: malformed JSON, named JSON exports and incorrect import attributes are refused before publication.");
  console.log(`Fixtures: ${project}`);
} catch (error) {
  console.error(`React client dynamic-import check failed; fixtures retained at ${project}`);
  throw error;
}
