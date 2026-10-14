const { Duplex: D, Readable, Writable, PassThrough } = require('node:stream');
const same = require('stream');
if (D !== same.Duplex || typeof D.from !== 'function') throw Error('module identity');
async function collect(stream) {
  const values = [];
  for await (const value of stream) values.push(value);
  return values;
}
function finish(stream) {
  return new Promise((resolve, reject) => stream.once('finish', resolve).once('error', reject));
}
(async function () {
  const existing = new PassThrough();
  if (D.from(existing) !== existing) throw Error('duplex identity');
  existing.destroy();
  const sources = await collect(D.from([1, Promise.resolve(2), 3]));
  const text = await collect(D.from('one chunk'));
  const bytes = await collect(D.from(Buffer.from([0, 255])));
  if (sources.join(',') !== '1,2,3' || text.length !== 1 || text[0] !== 'one chunk' ||
      bytes.length !== 1 || bytes[0][1] !== 255) throw Error('source conversion');
  const seen = [];
  const r = Readable.from([7, 8]);
  const w = new Writable({ objectMode: true, write(value, encoding, done) { seen.push(value); done(); } });
  const pair = D.from({ readable: r, writable: w });
  const ending = finish(pair);
  pair.write(40); pair.end(2);
  await ending;
  if (pair.readableEnded) throw Error('write completion consumed readable side');
  const read = await collect(pair);
  if (seen.join(',') !== '40,2' || read.join(',') !== '7,8') throw Error('pair directions');
  const transform = D.from(async function* (source) {
    for await (const value of source) yield value * 3;
  });
  const transformed = collect(transform);
  transform.write(2); transform.end(4);
  if ((await transformed).join(',') !== '6,12') throw Error('function transform');
  let total = 0;
  const sink = D.from(async source => { for await (const value of source) total += value; });
  const sinkFinished = finish(sink); sink.write(20); sink.end(22); await sinkFinished;
  if (total !== 42 || sink.readable) throw Error('async sink');
  if ((await collect(D.from(Promise.resolve(42))))[0] !== 42 ||
      (await collect(D.from(Promise.resolve(null)))).length !== 0) throw Error('promise values');
  const boom = Error('source refused');
  const rejected = D.from(Promise.reject(boom));
  const observed = await new Promise(resolve => rejected.once('error', resolve));
  if (observed !== boom) throw Error('idle rejection');
  let release;
  const pending = D.from(new Promise(resolve => { release = resolve; }));
  pending.on('error', () => {});
  const closed = new Promise(resolve => pending.once('close', resolve));
  pending.destroy(); await closed; release(99); await Promise.resolve();
  if (pending.readableLength !== 0) throw Error('late promise publication');
  console.log('DUPLEX_FROM_OK');
})();
