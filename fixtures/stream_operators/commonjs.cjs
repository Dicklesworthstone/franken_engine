'use strict';
// Run unchanged through Node's reference CLI and FrankenEngine/franken_node's
// native script entry points. No require mocking or external-engine fallback.
const stream = require('node:stream');
const { Readable, Writable } = require('stream');
if (stream.Readable !== Readable || stream.Writable !== Writable) throw new Error('split stream module identity');
// Keep construction at top level to exercise facade-vs-module routing.
const mapped = Readable.from([1, 2, 3, 4])
  .map(async value => value * 2, { concurrency: 2, highWaterMark: 1 })
  .filter(value => value > 2)
  .flatMap(value => [value, value + 1]);
(async function () {
  const values = await mapped.toArray();
  const total = await Readable.from(values).reduce((sum, value) => sum + value, 0);
  const found = await Readable.from(values).find(value => value === 7);
  const every = await Readable.from(values).every(value => value > 0);
  const some = await Readable.from(values).some(value => value === 99);
  let seen = 0;
  await Readable.from(values).forEach(async () => { seen++; }, { concurrency: 3 });
  const window = await Readable.from(values).drop(2).take(3).toArray();
  const result = { values, total, found, every, some, seen, window };
  const actual = JSON.stringify(result);
  const expected = '{"values":[4,5,6,7,8,9],"total":39,"found":7,"every":true,"some":false,"seen":6,"window":[6,7,8]}';
  if (actual !== expected) throw new Error('operator mismatch: ' + actual);
  console.log('READABLE_OPERATORS_OK ' + actual);
})().catch(error => { console.error(error); throw error; });
