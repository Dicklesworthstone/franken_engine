'use strict';
// Source-level A/B with live Node stream in every case. This does NOT time
// FrankenEngine's Rust parser/interpreter, policy, or host-call boundaries.
// Usage: node scripts/bench_stream_buffering.cjs /path/to/parent/stream_module.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const nativeStream = require('node:stream');
const { loadStream, defaultSource, tick, writableProbe } = require('./tests/stream_buffering.cjs');
const parent = process.argv[2];
if (!parent) throw new Error('A parent stream_module.js path is required for the A/B comparison');
const lanes = { parent: loadStream(parent), candidate: loadStream(defaultSource), node: nativeStream };

async function construction(stream) {
  for (let i = 0; i < 1000; i++) new stream.Readable({ read() {} }).destroy();
  await tick();
  return 1000;
}
async function singleItem(stream) {
  let sum = 0;
  for (let i = 0; i < 1000; i++) {
    const r = new stream.Readable({ objectMode: true, read() {} });
    r.push(i); sum += r.read(); r.destroy();
  }
  await tick();
  return sum;
}
async function steady(stream) {
  const r = new stream.Readable({ objectMode: true, highWaterMark: 16, read() {} });
  for (let i = 0; i < 64; i++) r.push(i);
  let sum = 0;
  for (let i = 0; i < 200000; i++) { sum += r.read(); r.push(i); }
  r.destroy();
  await tick();
  return sum;
}
async function prepend(stream) {
  const r = new stream.Readable({ objectMode: true, read() {} });
  for (let i = 0; i < 65536; i++) r.unshift(i);
  r.push(null);
  let sum = 0;
  for (let i = 0; i < 65536; i++) sum += r.read();
  r.destroy();
  await tick();
  return sum;
}
async function writes(stream, vector) {
  let release;
  let sum = 0;
  let count = 0;
  let callbacks = 0;
  const options = { objectMode: true, highWaterMark: 16,
    write(value, encoding, cb) { sum += value; count++; release = cb; },
  };
  if (vector) options.writev = function (entries, cb) {
    for (const entry of entries) { sum += entry.chunk; count++; }
    release = cb;
  };
  const w = new stream.Writable(options);
  w.cork();
  function completed(error) { assert.ifError(error); callbacks++; }
  for (let i = 0; i < 65536; i++) w.write(i, completed);
  w.uncork();
  while (release) { const done = release; release = undefined; done(); }
  w.end();
  await tick();
  assert.equal(count, 65536); assert.equal(callbacks, 65536);
  assert.equal(w.writableLength, 0); assert.equal(w.writableFinished, true);
  return sum;
}
async function pipeline(stream) {
  let sum = 0;
  let count = 0;
  const source = stream.Readable.from(Array.from({ length: 2048 }, (_, i) => i));
  const transform = new stream.PassThrough({ objectMode: true, highWaterMark: 16 });
  const sink = new stream.Writable({ objectMode: true, highWaterMark: 16,
    write(value, encoding, cb) { sum += value; count++; process.nextTick(cb); },
  });
  await new Promise((resolve, reject) => stream.pipeline(source, transform, sink,
    error => error ? reject(error) : resolve()));
  assert.equal(count, 2048);
  return sum;
}
// Include cold construction, tiny queues, vector writes and a pipeline as
// countermetrics; do not report only the large-queue cases we optimized.
const cases = [
  ['construct_1000', construction, 1000],
  ['single_item_1000', singleItem, 499500],
  ['steady_fifo_200000', steady, 19987104096],
  ['prepend_drain_65536', prepend, 2147450880],
  ['buffered_writes_65536', stream => writes(stream, false), 2147450880],
  ['vector_writes_65536', stream => writes(stream, true), 2147450880],
  ['backpressured_pipeline_2048', pipeline, 2096128],
];
const samples = {};
const measured = 7;
const warmups = 2;
const names = Object.keys(lanes);
async function main() {
  for (const [name, run, expected] of cases) {
    samples[name] = {};
    for (const lane of names) samples[name][lane] = [];
    for (let iteration = 0; iteration < warmups + measured; iteration++) {
      for (let j = 0; j < names.length; j++) {
        const lane = names[(iteration + j) % names.length];
        const start = performance.now();
        const actual = await run(lanes[lane]);
        const elapsed = performance.now() - start;
        assert.equal(actual, expected, `${name}: ${lane} output`);
        if (iteration >= warmups) samples[name][lane].push(elapsed);
      }
    }
  }
  const summary = {};
  for (const [name] of cases) {
    summary[name] = {};
    for (const lane of names) {
      const sorted = [...samples[name][lane]].sort((a, b) => a - b);
      summary[name][lane] = { median_ms: sorted[3], min_ms: sorted[0], max_ms: sorted[6] };
    }
  }
  const work = {};
  for (const lane of ['parent', 'candidate']) {
    const result = await writableProbe(lanes[lane], 65536);
    work[lane] = { copiedSuffixEntries: result.moved, compactions: result.compactions };
  }
  const digest = filename => crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
  console.log(JSON.stringify({ scope: 'engine-owned stream JavaScript hosted by Node; NOT FrankenEngine execution',
    runtime: process.version, v8: process.versions.v8, platform: process.platform, arch: process.arch,
    warmups, measured, source_sha256: { parent: digest(parent), candidate: digest(defaultSource) },
    summary, writableWork: work, samples }, null, 2));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
