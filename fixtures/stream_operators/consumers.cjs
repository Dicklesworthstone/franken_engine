'use strict';
const consumers = require('stream/consumers');
const alias = require('node:stream/consumers');
const { Readable } = require('node:stream');
if (consumers !== alias || consumers.text !== alias.text) throw Error('consumer alias identity');
// A constructor-only facade must not intercept this source: consumers use
// the complete stream's iterator protocol inside the engine-owned module.
const source = Readable.from([Buffer.from([0xf0, 0x9f]), Buffer.from([0x98, 0x80])]);
(async function () {
  const decoded = await consumers.text(source);
  const bytes = Uint8Array.from([99, 65, 66, 88]);
  const collected = await consumers.buffer([new DataView(bytes.buffer, 1, 2), '!']);
  const raw = await consumers.arrayBuffer([collected]);
  const blob = await consumers.blob(['a', Buffer.from('b')]);
  const value = await consumers.json(['{"ok":', 'true}']);
  if (decoded !== '\u{1f600}' || collected.toString() !== 'AB!' || raw.byteLength !== 3 ||
      await blob.text() !== 'ab' || value.ok !== true) throw Error('consumer result mismatch');
  let closed = false;
  async function* invalid() { try { yield {}; yield 'unreachable'; } finally { closed = true; } }
  try { await consumers.text(invalid()); throw Error('invalid chunk accepted'); }
  catch (error) { if (!(error instanceof TypeError) || !closed) throw error; }
  console.log('STREAM_CONSUMERS_OK');
})().catch(error => { console.error(error); throw error; });
