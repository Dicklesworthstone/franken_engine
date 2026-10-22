const { Readable, Writable } = require('stream');
const log = [];
const readable = new Readable({
  read() { this.push('x'); this.push(null); }
});
const writable = new Writable({
  write(chunk, encoding, callback) { log.push('write:' + chunk); callback(); }
});
const stream = require('node:stream');
console.log('identity:' + (readable instanceof Reflect.get(stream, 'Readable')) +
  ',' + (writable instanceof Reflect.get(stream, 'Writable')));
readable.on('data', chunk => log.push('data:' + chunk));
readable.on('end', () => log.push('end'));
writable.on('finish', () => log.push('finish'));
writable.write('a', () => log.push('written'));
writable.end(() => log.push('ended'));
queueMicrotask(() => log.push('microtask'));
function local(require) { return require('stream').marker; }
console.log('shadow:' + local(() => ({ marker: 'local' })));
setTimeout(() => console.log('order:' + log.join(',')), 10);
