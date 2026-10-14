import Stream, { addAbortSignal, duplexPair } from 'node:stream';
(async () => {
  if (addAbortSignal !== Stream.addAbortSignal) throw new Error('named identity');
  const [left, right] = duplexPair();
  const controller = new AbortController();
  const errors = [];
  left.on('error', error => errors.push(error)); right.on('error', error => errors.push(error));
  const closed = Promise.all([
    new Promise(resolve => left.once('close', resolve)),
    new Promise(resolve => right.once('close', resolve))
  ]);
  addAbortSignal(controller.signal, left); addAbortSignal(controller.signal, right);
  controller.abort(false); await closed;
  if (errors.length !== 2 || !left.destroyed || !right.destroyed) throw new Error('pair close');
  for (const error of errors) {
    if (error.name !== 'AbortError' || error.code !== 'ABORT_ERR' || error.cause !== false)
      throw new Error('reason identity');
  }
  console.log('STREAM_ABORT_SIGNAL_ESM_OK');
})().catch(error => { console.log('STREAM_ABORT_SIGNAL_ESM_FAILED', error.message); });
