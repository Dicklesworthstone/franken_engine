#!/usr/bin/env node
'use strict';
// Exact shipped JS with Node's native Buffer/WeakMap operations. This is NOT
// execution of FrankenEngine's Rust parser, lowerer, interpreter, GC or IFC.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const reference = require('node:string_decoder');
const root = path.resolve(__dirname, '..');
const sourcePath = process.argv[2] || path.join(root,
  'crates/franken-engine/src/lowering_pipeline/string_decoder_module.js');
const source = fs.readFileSync(sourcePath, 'utf8');
const candidate = new Function('return ' + source)();
const Native = reference.StringDecoder;
const Candidate = candidate.StringDecoder;
let sequenceChecks = 0;
let apiChecks = 0;

function trace(Constructor, encoding, chunks) {
  const decoder = new Constructor(encoding);
  const output = [];
  for (const chunk of chunks) {
    output.push([decoder.write(Buffer.from(chunk)), decoder.lastNeed, decoder.lastTotal]);
  }
  output.push([decoder.end(), decoder.lastNeed, decoder.lastTotal]);
  return output;
}
function compare(encoding, chunks) {
  assert.deepEqual(trace(Candidate, encoding, chunks), trace(Native, encoding, chunks),
    `${encoding} ${JSON.stringify(chunks)}`);
  sequenceChecks++;
}
function api(name, scenario) {
  assert.deepEqual(scenario(Candidate), scenario(Native), name);
  apiChecks++;
}

// Predeclared denominator: 7*256 singleton streams, all 256^2 UTF-8
// two-single-byte streams, and 4*512*(16+1) deterministic split/random streams.
const encodings = ['utf8', 'utf16le', 'base64', 'base64url', 'hex', 'ascii', 'latin1'];
for (const encoding of encodings) {
  for (let byte = 0; byte < 256; byte++) compare(encoding, [[byte]]);
}
for (let first = 0; first < 256; first++) {
  for (let second = 0; second < 256; second++) compare('utf8', [[first], [second]]);
}
for (const encoding of encodings.slice(0, 4)) {
  for (let seed = 1; seed <= 512; seed++) {
    let state = seed;
    const random = () => state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const input = Array.from({ length: 16 }, () => random() >>> 24);
    for (let cut = 0; cut < input.length; cut++) compare(encoding, [input.slice(0, cut), input.slice(cut)]);
    compare(encoding, input.map(byte => [byte]));
  }
}
assert.equal(sequenceChecks, 102144);

function outcome(call) {
  try { return ['value', call()]; }
  catch (error) { return ['error', error.name, error.code]; }
}
for (const encoding of [undefined, null, '', 'UTF8', 'UTF-8', 'utf16le', 'UTF-16LE',
  'ucs2', 'UCS-2', 'ASCII', 'LATIN1', 'binary', 'HEX', 'BASE64', 'BASE64URL',
  false, 0, 1, true, {}, ['utf8'], 'invalid']) {
  api('encoding ' + String(encoding), C => outcome(() => new C(encoding).encoding));
}
for (const input of [undefined, null, false, 0, {}, [], new ArrayBuffer(0), '', 'text',
  Buffer.from('abc'), new Uint16Array([0x6261]), new DataView(new Uint8Array([97, 98]).buffer)]) {
  for (const method of ['write', 'end']) api(method + ' input', C => {
    const decoder = new C(); decoder.write(Buffer.from([0xe2]));
    const result = outcome(() => decoder[method](input));
    return [result, decoder.lastNeed, decoder.end()];
  });
}
for (const encoding of encodings) {
  for (const offset of [undefined, 0, 1, -1, 100, 1.5, '1', NaN]) {
    api('text reset ' + encoding + ' ' + offset, C => {
      const d = new C(encoding);
      d.write(Buffer.from([0xe2]));
      return [d.text(Buffer.from([0x41, 0xe2, 0x82, 0xac]), offset), d.lastNeed, d.end()];
    });
  }
}
api('carry view identity, mutation, descriptors', C => {
  const d = new C(); d.write(Buffer.from([0xe2]));
  const first = d.lastChar, second = d.lastChar;
  first[0] = 0xe3;
  return [first === second, second[0], d.end(Buffer.from([0x82, 0xac])),
    ['lastChar', 'lastNeed', 'lastTotal'].map(key => {
      const p = Object.getOwnPropertyDescriptor(C.prototype, key);
      return [p.enumerable, p.configurable, p.set === undefined];
    }), [C.length, d.write.length, d.end.length, d.text.length]];
});
api('narrow raw views cannot be redirected through own properties', C => {
  const all = new Uint8Array([0, 0, 0xe2, 0x82, 0xac, 65, 0, 0]);
  const words = new Uint16Array(all.buffer, 2, 2);
  Object.defineProperties(words, { buffer: { value: new ArrayBuffer(0) },
    byteLength: { value: 0 }, byteOffset: { value: 0 } });
  return new C().end(words);
});
api('large chunk followed by input mutation keeps only copied carry', C => {
  const input = Buffer.alloc(65536, 65); input[input.length - 1] = 0xe2;
  const d = new C();
  const decoded = d.write(input); input.fill(0);
  return [decoded.length, decoded[0], d.lastChar.length, d.lastNeed,
    d.end(Buffer.from([0x82, 0xac]))];
});

// Use the exact Rust fixture programs and their declared expected output.
const rust = fs.readFileSync(path.join(root, 'crates/franken-engine/tests/string_decoder_module.rs'), 'utf8');
const programs = new Map([...rust.matchAll(/const ([A-Z0-9_]+): &str = r#"([\s\S]*?)"#;/g)]
  .map(match => [match[1], match[2]]));
const cases = [...rust.matchAll(/check\(([A-Z0-9_]+), ("(?:[^"\\]|\\.)*"), ParseGoal::(Script|Module)\);/g)];
assert.equal(programs.size, 12);
assert.equal(cases.length, programs.size);
let sharedFixtures = 0;
let esmReferenceOnly = 0;
for (const [, name, expectedText, goal] of cases) {
  const expected = JSON.parse(expectedText);
  const program = programs.get(name);
  if (goal === 'Module') {
    const child = spawnSync(process.execPath, ['--input-type=module', '-'], {
      input: program, encoding: 'utf8', timeout: 3000,
    });
    if (child.error) throw child.error;
    if (child.stderr) process.stderr.write(child.stderr);
    assert.equal(child.status, 0, name);
    assert.equal(child.stdout.trimEnd(), expected, name);
    esmReferenceOnly++;
    continue;
  }
  for (const module of [reference, candidate]) {
    const lines = [];
    new Function('require', 'console', program)(name => {
      assert.ok(name === 'string_decoder' || name === 'node:string_decoder');
      return module;
    }, { log: (...args) => lines.push(args.map(String).join(' ')) });
    assert.equal(lines.join('\n'), expected, name);
  }
  sharedFixtures++;
}
console.log(JSON.stringify({ node: process.version, sequenceChecks, apiChecks,
  sharedFixtures, esmReferenceOnly, nativeRustExecuted: false,
  scope: 'Exact decoder JavaScript on Node Buffer/WeakMap; no native-engine verdict' }, null, 2));
