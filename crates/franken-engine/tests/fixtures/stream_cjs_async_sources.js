const { Readable } = require('stream');
const promised = [];
const generated = [];
const cancelled = [];
const rejected = [];

Readable.from([
  Promise.resolve('a'),
  { then(resolve) { queueMicrotask(() => resolve('b')); } },
  'c'
]).on('data', value => promised.push(value))
  .on('end', () => promised.push('end'));

async function* values() {
  yield Promise.resolve(1);
  await Promise.resolve();
  yield 2;
}
Readable.from(values()).on('data', value => generated.push(value))
  .on('end', () => generated.push('end'));

async function* untilCancelled() {
  try {
    yield 'first';
    yield 'unreachable';
  } finally {
    await Promise.resolve();
    cancelled.push('finally');
  }
}
const cancellation = Readable.from(untilCancelled());
cancellation.on('data', value => { cancelled.push(value); cancellation.destroy(); });
cancellation.on('close', () => cancelled.push('close'));

const failure = new Error('producer failed');
Readable.from([Promise.reject(failure)])
  .on('error', error => rejected.push(error === failure ? 'same-error' : 'wrong-error'))
  .on('close', () => rejected.push('close')).resume();

setTimeout(() => {
  console.log('promised:' + promised.join(','));
  console.log('generated:' + generated.join(','));
  console.log('cancelled:' + cancelled.join(','));
  console.log('rejected:' + rejected.join(','));
}, 20);
