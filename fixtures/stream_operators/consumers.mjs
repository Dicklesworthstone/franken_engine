import consumers from 'node:stream/consumers';
import { text, json, buffer, arrayBuffer, blob } from 'stream/consumers';
import { Readable } from 'node:stream';
if (consumers.text !== text || consumers.blob !== blob) throw Error('ESM consumer identity');
const input = Readable.from([Buffer.from([0xef]), Buffer.from([0xbb, 0xbf, 65])]);
(async function () {
  const decoded = await text(input);
  const value = await json(['[1,', '2,3]']);
  const bytes = await buffer(['abc']);
  const raw = await arrayBuffer(['a']);
  const result = await blob(['x']);
  if (decoded !== 'A' || JSON.stringify(value) !== '[1,2,3]' || bytes.toString() !== 'abc' ||
      raw.byteLength !== 1 || result.size !== 1) throw Error('ESM consumer result mismatch');
  console.log('STREAM_CONSUMERS_ESM_OK');
})().catch(error => { console.error(error); throw error; });
