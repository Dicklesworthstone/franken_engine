'use strict';
const { duplexPair: transport } = require('node:stream');
const { Readable: Source, Transform: Mapper, Writable: Sink, promises } = require('stream');
(async () => {
  const [client, server] = transport({ objectMode: true, highWaterMark: 1 });
  const answers = [];
  await Promise.all([
    promises.pipeline(Source.from([1, 2, 3, 4]), client),
    promises.pipeline(server, new Mapper({ objectMode: true,
      transform(value, encoding, done) { done(null, value * 10); }
    }), server),
    promises.pipeline(client, new Sink({ objectMode: true,
      write(value, encoding, done) { answers.push(value); done(); }
    }))
  ]);
  if (answers.join(',') !== '10,20,30,40') throw new Error('bidirectional pipeline');
  const [a, b] = transport({ objectMode: true, highWaterMark: 1 });
  const object = { payload: 7 };
  const received = [];
  b.on('data', value => { received.push(value); });
  a.resume();
  const complete = Promise.all([promises.finished(a), promises.finished(b)]);
  a.end(object); b.end(); await complete;
  if (received.length !== 1 || received[0] !== object) throw new Error('object identity');
  console.log('DUPLEX_PAIR_OK 10,20,30,40 true');
})().catch(error => { console.log('DUPLEX_PAIR_FAILED', error.message); });
