const stream = require('stream');
const r = new stream.Readable({ objectMode: true, highWaterMark: 16, read() {} });
for (let i = 0; i < 64; i++) r.push(i);
let sum = 0;
for (let i = 0; i < 4096; i++) {
  const value = r.read();
  if (value !== (i < 64 ? i : i - 64)) throw new Error('FIFO order');
  sum += value;
  r.push(i);
}
for (let i = 0; i < 33; i++) r.unshift(-i - 1);
for (let i = 33; i > 0; i--) {
  if (r.read() !== -i) throw new Error('prepend order');
}
r.push(null);
for (let i = 4032; i < 4096; i++) {
  if (r.read() !== i) throw new Error('wrapped tail');
}
if (r.read() !== null || r.readableLength !== 0) throw new Error('EOF');
console.log('fifo', sum, r.readableLength);
r.destroy();
