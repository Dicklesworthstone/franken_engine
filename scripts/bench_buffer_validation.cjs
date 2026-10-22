'use strict';
// Run from a checkout with a complete previous buffer_module.js as argv[2].
// Optionally supply an older snapshot as argv[3]. All roles use this Node
// process. This measures host JavaScript, NOT the native Franken interpreter.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
if (process.argv.length < 3 || process.argv.length > 4) {
  throw new Error('Usage: node scripts/bench_buffer_validation.cjs BEFORE_SOURCE [OLDER_SOURCE]');
}
const paths = {
  before: path.resolve(process.argv[2]),
  candidate: path.resolve(__dirname, '../crates/franken-engine/src/lowering_pipeline/buffer_module.js'),
};
if (process.argv[3]) paths.older = path.resolve(process.argv[3]);
const roles = {}, hashes = {};
for (const [name, file] of Object.entries(paths)) {
  const source = fs.readFileSync(file, 'utf8');
  hashes[name] = crypto.createHash('sha256').update(source).digest('hex');
  // Trusted local source snapshots only; never substitute this for a native candidate.
  roles[name] = new Function('return ' + source)();
}
roles.node = require('node:buffer');
const ascii = Buffer.alloc(1048576, 65);
const unicode = Buffer.from('é😀'.repeat(65536));
const badFirst = Buffer.from(ascii), badLast = Buffer.from(ascii);
badFirst[0] = 255; badLast[badLast.length - 1] = 255;
const workloads = [
  ['utf8-small', 'isUtf8', Buffer.from('package payload'), 12000],
  ['utf8-ascii-64k', 'isUtf8', ascii.subarray(0, 65536), 128],
  ['utf8-ascii-1m', 'isUtf8', ascii, 16],
  ['utf8-unicode', 'isUtf8', unicode, 32],
  ['utf8-bad-prefix', 'isUtf8', badFirst, 4000],
  ['utf8-bad-tail', 'isUtf8', badLast, 16],
  ['ascii-small', 'isAscii', Buffer.from('abc'), 12000],
  ['ascii-1m', 'isAscii', ascii, 16],
  ['ascii-unicode', 'isAscii', unicode, 4000],
];
const names = Object.keys(roles), rows = [];
let sink = 0;
for (const [workload, method, bytes, iterations] of workloads) {
  const expected = roles.node[method](bytes);
  for (const role of names) {
    assert.equal(roles[role][method](bytes), expected, role + ': ' + workload);
    for (let i = 0; i < 16; i++) roles[role][method](bytes);
  }
  for (let round = 0; round < 7; round++) {
    for (let offset = 0; offset < names.length; offset++) {
      const role = names[(round + offset) % names.length], fn = roles[role][method];
      const start = process.hrtime.bigint(), cpu = process.cpuUsage();
      for (let i = 0; i < iterations; i++) if (fn(bytes)) sink++;
      const used = process.cpuUsage(cpu);
      rows.push({ workload, role, round, bytes: bytes.length, iterations,
        wall_ms: Number(process.hrtime.bigint() - start) / 1e6,
        cpu_ms: (used.user + used.system) / 1000 });
    }
  }
}
function median(values) {
  values.sort((a, b) => a - b);
  return values[Math.floor(values.length / 2)];
}
const summary = workloads.map(([workload]) => {
  const row = { workload };
  for (const role of names) {
    const samples = rows.filter(x => x.workload === workload && x.role === role);
    row[role] = {
      wall_ms: median(samples.map(x => x.wall_ms / x.iterations)),
      cpu_ms: median(samples.map(x => x.cpu_ms / x.iterations)),
    };
  }
  row.candidate_over_before = row.candidate.wall_ms / row.before.wall_ms;
  row.candidate_over_node = row.candidate.wall_ms / row.node.wall_ms;
  return row;
});
console.log(JSON.stringify({ node: process.version, kind: 'host wall/CPU; not native performance',
  source_sha256: hashes, sink, rows, median_ms_per_call: summary }, null, 2));
