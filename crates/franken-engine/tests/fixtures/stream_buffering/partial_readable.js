const stream = require('stream');
const r = new stream.Readable({ encoding: 'utf8', read() {} });
let reference = '';
let checksum = 0;
const chunks = ['ab', '\uD83D\uDE00', '\uD800X', '\uDC00', '\u0000'];
for (let i = 0; i < 128; i++) {
  const chunk = chunks[i % chunks.length];
  if (i % 3 === 0) { r.unshift(chunk); reference = chunk + reference; }
  else { r.push(chunk); reference += chunk; }
  if (i % 4 === 0) {
    const n = Math.min(reference.length, 1 + i % 9);
    const value = r.read(n);
    if (value !== reference.slice(0, n)) throw new Error('UTF-16 partial read');
    for (let j = 0; j < value.length; j++) checksum += value.charCodeAt(j);
    reference = reference.slice(n);
  }
}
r.push(null);
const tail = r.read();
if (tail !== reference || r.readableLength !== 0) throw new Error('text tail');
console.log('text', checksum, tail.length);
r.destroy();
const b = new stream.Readable({ read() {} });
for (let i = 0; i < 16; i++) b.push(Buffer.from([i, i + 16]));
const prefix = b.read(7);
b.unshift(Buffer.from([254, 255]));
const middle = b.read(6);
b.push(null);
console.log('bytes', prefix.toString('hex'), middle.toString('hex'), b.read().toString('hex'));
b.destroy();
