import stream from 'node:stream';
import { Readable } from 'stream';
if (stream.Readable !== Readable) throw new Error('ESM stream alias identity mismatch');
const output = Readable.from([1, 2, 3]).map(async value => value * 3, { concurrency: 2 }).drop(1).take(1);
(async function () {
  const values = await output.toArray();
  if (JSON.stringify(values) !== '[6]') throw new Error('ESM operator mismatch');
  console.log('READABLE_OPERATORS_ESM_OK [6]');
})().catch(error => { console.error(error); throw error; });
