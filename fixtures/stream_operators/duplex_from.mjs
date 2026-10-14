import stream, { Duplex, Readable, Writable } from 'node:stream';
import { Duplex as Alias } from 'stream';
if (Duplex !== Alias || stream.Duplex !== Duplex) throw Error('ESM alias identity');
(async function () {
  const written = [];
  const output = Duplex.from({
    readable: Readable.from(['one', 'two']),
    writable: new Writable({ objectMode: true, write(value, encoding, done) { written.push(value); done(); } })
  });
  const finished = new Promise((resolve, reject) => output.once('finish', resolve).once('error', reject));
  output.end('input');
  const values = [];
  for await (const value of output) values.push(value);
  await finished;
  if (values.join(',') !== 'one,two' || written.join(',') !== 'input') throw Error('ESM conversion');
  console.log('DUPLEX_FROM_ESM_OK');
})();
