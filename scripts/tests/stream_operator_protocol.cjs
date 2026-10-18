'use strict';
// Node hosts the exact engine-owned operator factory, not another implementation.
// The separate live reference uses unmodified Node operators in this invocation.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const node = require('node:stream');
const root = path.resolve(__dirname, '../..');
const sourcePath = process.env.FRANKEN_STREAM_OPERATORS_SOURCE || path.join(root,
  'crates/franken-engine/src/lowering_pipeline/stream_operators.js');
const install = vm.runInThisContext(fs.readFileSync(sourcePath, 'utf8'), { filename: sourcePath });
class HostReadable extends node.Readable {
  static from(value, options) {
    const stream = node.Readable.from(value, options);
    Object.setPrototypeOf(stream, HostReadable.prototype);
    return stream;
  }
}
const methods = ['map','filter','flatMap','take','drop','toArray','forEach','some','every','find','reduce'];
for (const name of methods) Object.defineProperty(HostReadable.prototype, name,
  { value: undefined, writable: true, configurable: true });
install({ Readable: HostReadable });
for (const name of methods) if (typeof HostReadable.prototype[name] !== 'function') throw new Error('missing ' + name);
const cases = vm.runInThisContext(fs.readFileSync(path.join(root,
  'crates/franken-engine/tests/fixtures/stream_operator_protocol.js'), 'utf8'));
function bounded(run) {
  let timer;
  return Promise.race([Promise.resolve().then(run), new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error('case did not settle')), 3000);
  })]).finally(() => clearTimeout(timer));
}
(async () => {
  let failed = 0, candidatePassed = 0, candidateFailed = 0, referencePassed = 0, referenceFailed = 0;
  for (const [name, run, metadata] of cases) {
    for (const [label, R] of [['engine-factory', HostReadable], ['node-reference', node.Readable]]) {
      // These three lifecycle controls retain the engine's interruption policy,
      // not a claim that Node can cancel arbitrary never-settling iterators.
      if (label === 'node-reference' && metadata && metadata.reference === false) continue;
      try {
        await bounded(() => run(R)); console.log('PASS', label, name);
        if (label === 'engine-factory') candidatePassed++; else referencePassed++;
      } catch (error) {
        failed++;
        if (label === 'engine-factory') candidateFailed++; else referenceFailed++;
        console.error('FAIL', label, name, error && error.stack || error);
      }
    }
  }
  console.log('RESULT', JSON.stringify({ cases: cases.length, failed,
    candidatePassed, candidateFailed, referencePassed, referenceFailed }));
  if (failed) process.exitCode = 1;
})();
