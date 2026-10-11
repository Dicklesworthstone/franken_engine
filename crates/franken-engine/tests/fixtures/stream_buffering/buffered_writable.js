const stream = require('stream');
let release;
let written = 0;
let callbacks = 0;
let sum = 0;
const log = [];
const w = new stream.Writable({
  objectMode: true, highWaterMark: 16,
  write(value, encoding, done) {
    if (value !== written++) throw new Error('write order');
    sum += value;
    release = done;
  }
});
w.on('drain', () => log.push('drain'));
w.on('finish', () => log.push('finish'));
w.on('close', () => console.log('write', written, callbacks, sum, log.join(',')));
w.cork();
for (let i = 0; i < 2048; i++) {
  w.write(i, function (error) {
    if (error || callbacks++ !== i) throw new Error('callback order');
  });
}
w.uncork();
while (release) {
  const done = release;
  release = undefined;
  done();
}
if (w.writableLength !== 0 || w.writableBuffer.length !== 0) throw new Error('undrained');
w.end(() => log.push('end-callback'));
