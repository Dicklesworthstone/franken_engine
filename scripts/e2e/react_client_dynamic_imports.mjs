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

  console.log("PASS: emitted client ESM preserves lazy order, module caching, nested calls and template substitutions.");
  console.log("PASS: computed, missing and escaping imports are refused before publication.");
  console.log(`Fixtures: ${project}`);
} catch (error) {
  console.error(`React client dynamic-import check failed; fixtures retained at ${project}`);
  throw error;
}
