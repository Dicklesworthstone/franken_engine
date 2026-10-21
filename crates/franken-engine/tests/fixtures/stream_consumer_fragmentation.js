(async function (consumer, index) {
  function equal(actual, expected) {
    if (actual !== expected) throw new Error('consumer mismatch: ' + actual + ' != ' + expected);
  }
  if (index === 0) {
    async function* input() {
      for (let i = 0; i < 512; i++) { yield ''; yield new Uint8Array(0); }
      yield new Uint8Array([0xef, 0xbb]);
      yield new Uint8Array([0xbf, 0xe2]);
      yield '';
      yield new Uint8Array([0x82, 0xac]);
    }
    equal(await consumer.text(input()), '€');
  } else if (index === 1) {
    async function* input() {
      for (let i = 0; i < 257; i++) yield 'x';
      yield '\ud83d'; yield '\ude00'; yield '\ud800'; yield '\udfff';
    }
    equal(await consumer.text(input()), 'x'.repeat(257) + '\ud83d\ude00\ud800\udfff');
  } else if (index === 2) {
    async function* input() {
      yield new Uint8Array([0xe2]);
      for (let i = 0; i < 128; i++) yield 'x';
      yield new Uint8Array([0x82]); yield 'y';
      yield new Uint8Array([0xac, 0xff, 0xe2, 0x82]);
    }
    equal(await consumer.text(input()), 'x'.repeat(128) + 'y€��');
  } else if (index === 3) {
    const input = JSON.stringify({ numbers: [0, 1, 2, 3], name: '😀€', padding: 'x'.repeat(130) });
    async function* pieces() { for (let i = 0; i < input.length; i++) yield input[i]; }
    equal(JSON.stringify(await consumer.json(pieces())), input);
  } else if (index === 4) {
    let closed = 0;
    async function* invalid() { try { yield 'x'; yield {}; } finally { closed++; } }
    let rejected = false;
    try { await consumer.text(invalid()); } catch (error) { rejected = error.name === 'TypeError'; }
    equal(rejected, true); equal(closed, 1);
    for (const reason of [undefined, null, false, 0]) {
      async function* fails() { yield 'x'; throw reason; }
      let caught = false;
      try { await consumer.text(fails()); } catch (error) { equal(error, reason); caught = true; }
      equal(caught, true);
    }
  } else if (index === 5) {
    const large = '😀'.repeat(8192);
    async function* input() { yield 'a'; yield 'b'; yield large; yield 'c'; yield 'd'; }
    equal(await consumer.text(input()), 'ab' + large + 'cd');
    async function* reused() {
      const data = new Uint8Array([120, 65, 66, 120]);
      yield new DataView(data.buffer, 1, 2);
      data[1] = 67; data[2] = 68;
      yield new Uint8Array(data.buffer, 1, 2);
    }
    equal(await consumer.text(reused()), 'ABCD');
  } else if (index === 6) {
    const methods = ['text', 'json', 'blob', 'arrayBuffer', 'buffer'];
    let observed = 0;
    const previous = Object.getOwnPropertyDescriptor(Array.prototype, '0');
    Object.defineProperty(Array.prototype, '0', {
      configurable: true,
      set(value) {
        observed++;
        Object.defineProperty(this, '0', {
          value: '"CORRUPTED"', writable: true, enumerable: true, configurable: true
        });
      }
    });
    try {
      for (let i = 0; i < methods.length; i++) {
        const method = methods[i];
        async function* input() { yield method === 'json' ? '"original"' : 'original'; }
        let actual = await consumer[method](input());
        if (method === 'blob') actual = await actual.text();
        else if (method === 'arrayBuffer' || method === 'buffer') actual = new TextDecoder().decode(actual);
        equal(actual, 'original');
      }
      equal(observed, 0);
    } finally {
      if (previous === undefined) delete Array.prototype[0];
      else Object.defineProperty(Array.prototype, '0', previous);
    }
  } else if (index === 7) {
    let observed = 0;
    const previous = Object.getOwnPropertyDescriptor(Object.prototype, '0');
    async function* input() {
      for (let i = 0; i < 64; i++) yield 'x';
      Object.defineProperty(Object.prototype, '0', {
        configurable: true,
        set(value) {
          observed++;
          Object.defineProperty(this, '0', {
            value: 'CORRUPTED', writable: true, enumerable: true, configurable: true
          });
        }
      });
      for (let i = 0; i < 129; i++) yield 'y';
    }
    try {
      equal(await consumer.text(input()), 'x'.repeat(64) + 'y'.repeat(129));
      equal(observed, 0);
    } finally {
      if (previous === undefined) delete Object.prototype[0];
      else Object.defineProperty(Object.prototype, '0', previous);
    }
  } else if (index === 8) {
    const prototype = Object.getPrototypeOf([][Symbol.iterator]());
    const previous = Object.getOwnPropertyDescriptor(prototype, 'next');
    const reason = { privateCursor: true };
    let observed = 0;
    const methods = ['blob', 'arrayBuffer', 'buffer'];
    Object.defineProperty(prototype, 'next', {
      configurable: true,
      get() { observed++; throw reason; }
    });
    try {
      for (let i = 0; i < methods.length; i++) {
        const method = methods[i];
        async function* input() { yield 'original'; }
        let actual = await consumer[method](input());
        if (method === 'blob') actual = await actual.text();
        else actual = new TextDecoder().decode(actual);
        equal(actual, 'original');
      }
      equal(observed, 0);
    } finally { Object.defineProperty(prototype, 'next', previous); }
  } else if (index === 9) {
    let nextReads = 0, nextCalls = 0, closes = 0;
    const reason = { inputFailure: true };
    const cursor = Object.create(null);
    Object.defineProperty(cursor, 'next', { get() {
      nextReads++;
      return function () {
        nextCalls++;
        return { done: false, value: nextCalls === 1 ? 'prefix' : {} };
      };
    } });
    cursor.return = function () { closes++; return { done: true }; };
    const input = { [Symbol.asyncIterator]() { return cursor; } };
    let caught = false;
    try { await consumer.text(input); }
    catch (error) { caught = error.name === 'TypeError'; }
    equal(caught, true); equal(nextReads, 1); equal(nextCalls, 2); equal(closes, 1);
    async function* fails() { yield 'prefix'; throw reason; }
    caught = false;
    try { await consumer.blob(fails()); }
    catch (error) { caught = error === reason; }
    equal(caught, true);
  } else throw new Error('unknown consumer case');
})
