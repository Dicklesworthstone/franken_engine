import Stream, { duplexPair, promises } from 'node:stream';
(async () => {
  if (duplexPair !== Stream.duplexPair) throw new Error('named export identity');
  const [left, right] = duplexPair({ allowHalfOpen: false, highWaterMark: 1 });
  const chunks = [];
  right.setEncoding('utf8');
  right.on('data', chunk => chunks.push(chunk));
  left.resume();
  const completed = Promise.all([promises.finished(left), promises.finished(right)]);
  left.write(Buffer.from([97, 240, 159]));
  left.end(Buffer.from([152, 128, 98]));
  await completed;
  if (chunks.join('') !== 'a😀b') throw new Error('binary transport or decoding');
  console.log('DUPLEX_PAIR_ESM_OK a😀b');
})().catch(error => { console.log('DUPLEX_PAIR_ESM_FAILED', error.message); });
