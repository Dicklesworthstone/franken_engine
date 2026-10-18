(function readableProtocolCases() {
  'use strict';
  function assert(condition, message) { if (!condition) throw new Error(message); }
  function same(actual, expected, message) {
    assert(JSON.stringify(actual) === JSON.stringify(expected), message + ': ' + JSON.stringify(actual));
  }
  async function collect(stream) {
    const result = [];
    for await (const value of stream) result.push(value);
    return result;
  }
  function source(values, hooks) {
    hooks = hooks || {};
    let index = 0;
    const counts = { nextGets: 0, reads: 0, values: 0, closes: 0, returnGets: 0 };
    const iterator = {
      get next() {
        counts.nextGets++;
        if (hooks.next) return hooks.next(counts);
        return function () {
          assert(this === iterator, 'next receiver');
          counts.reads++;
          if (index === values.length) return { done: true, get value() { throw new Error('terminal value read'); } };
          const value = values[index++];
          let reads = 0;
          return { done: false, get value() {
            counts.values++;
            reads++;
            if (hooks.value) return hooks.value(value, reads);
            return value;
          } };
        };
      },
      get return() {
        counts.returnGets++;
        if (hooks.returnGet) return hooks.returnGet(counts);
        return function () {
          assert(this === iterator, 'return receiver');
          counts.closes++;
          return { done: true };
        };
      }
    };
    return { counts, iterator, [Symbol.asyncIterator]() { return iterator; } };
  }
  async function use(R, method, input) {
    const p = R.prototype;
    switch (method) {
      case 'map': return collect(p.map.call(input, x => x * 2));
      case 'filter': return collect(p.filter.call(input, x => x > 0));
      case 'flatMap': return collect(p.flatMap.call(input, x => [x, x]));
      case 'take': return collect(p.take.call(input, 3));
      case 'drop': return collect(p.drop.call(input, 1));
      case 'toArray': return p.toArray.call(input);
      case 'forEach': {
        const output = [];
        await p.forEach.call(input, x => { output.push(x); });
        return output;
      }
      case 'some': return p.some.call(input, x => x === 2);
      case 'every': return p.every.call(input, x => x > 0);
      case 'find': return p.find.call(input, x => x === 2);
      case 'reduce': return p.reduce.call(input, (a, x) => a + x, 0);
    }
    throw new Error('unknown operator');
  }
  const expected = { map: [2, 4, 6], filter: [1, 2, 3], flatMap: [1, 1, 2, 2, 3, 3],
    take: [1, 2, 3], drop: [2, 3], toArray: [1, 2, 3], forEach: [1, 2, 3],
    some: true, every: true, find: 2, reduce: 6 };
  return [
    ['all eleven operators capture next once', async R => {
      for (const method of Object.keys(expected)) {
        const input = source([1, 2, 3]);
        same(await use(R, method, input), expected[method], method);
        assert(input.counts.nextGets === 1, method + ' reread next');
      }
    }],
    ['concurrent operators read each result value once', async R => {
      for (const method of ['map', 'filter', 'flatMap', 'some', 'every', 'find']) {
        const input = source([1, 2, 3], { value(value, reads) {
          assert(reads === 1, method + ' read a chunk twice'); return value;
        } });
        same(await use(R, method, input), expected[method], method);
      }
    }],
    ['filter publishes the exact value seen by its predicate', async R => {
      let seen;
      const input = source([1], { value() { return {}; } });
      const output = await collect(R.prototype.filter.call(input, value => { seen = value; return true; }));
      assert(output.length === 1 && output[0] === seen, 'filter changed chunk identity');
    }],
    ['discarded drop and take-zero chunks still read value', async R => {
      for (const method of ['drop', 'take']) {
        const input = source([1, 2, 3]);
        await collect(R.prototype[method].call(input, method === 'drop' ? 2 : 0));
        assert(input.counts.values === (method === 'drop' ? 3 : 1), method + ' skipped value access');
      }
    }],
    ['replacing next after acquisition cannot replace the producer', async R => {
      for (const method of Object.keys(expected)) {
        let count = 0;
        const iterator = { next() {
          iterator.next = function () { throw new Error('replacement next ran'); };
          return count === 3 ? { done: true } : { done: false, value: ++count };
        }, return() { return { done: true }; } };
        const input = { [Symbol.asyncIterator]() { return iterator; } };
        same(await use(R, method, input), expected[method], method);
      }
    }],
    ['primitive iterator results fail without mapper publication or return', async R => {
      for (const value of [undefined, null, false, 1, 'chunk', Symbol('step')]) {
        for (const method of ['map', 'take', 'toArray']) {
          let closes = 0, reads = 0;
          const iterator = { next() { return ++reads === 1 ? value : { done: true }; },
            return() { closes++; return { done: true }; } };
          const input = { [Symbol.asyncIterator]() { return iterator; } };
          let caught = false;
          try { await use(R, method, input); }
          catch (error) { caught = error instanceof TypeError; }
          assert(caught && reads === 1 && closes === 0, method + ' accepted/closed primitive result');
        }
      }
    }],
    ['function iterator results remain valid objects', async R => {
      let count = 0;
      const input = { [Symbol.asyncIterator]() { return { next() {
        const result = function () {};
        result.done = count === 2; result.value = ++count;
        return result;
      } }; } };
      same(await R.prototype.toArray.call(input), [1, 2], 'function result');
    }],
    ['next and result access failures do not call return', async R => {
      for (const phase of ['call', 'reject', 'done', 'value']) {
        for (const method of ['map', 'take', 'toArray']) {
          const sentinel = new Error(phase); let closes = 0;
          const iterator = {
            next() {
              if (phase === 'call') throw sentinel;
              if (phase === 'reject') return Promise.reject(sentinel);
              return { get done() { if (phase === 'done') throw sentinel; return false; },
                get value() { throw sentinel; } };
            },
            return() { closes++; throw new Error('unexpected close'); }
          };
          const input = { [Symbol.asyncIterator]() { return iterator; } };
          let caught;
          try { await use(R, method, input); } catch (error) { caught = error; }
          assert(caught === sentinel && closes === 0, method + ' replaced ' + phase + ' failure');
        }
      }
    }],
    ['normal short circuit acquires return only once with its receiver', async R => {
      for (const method of ['some', 'find', 'take']) {
        const input = source([1, 2, 3]);
        if (method === 'take') await collect(R.prototype.take.call(input, 1));
        else await use(R, method, input);
        assert(input.counts.returnGets === 1 && input.counts.closes === 1, method + ' repeated return lookup');
      }
    }],
    ['normal short circuit rejects noncallable return', async R => {
      for (const method of ['some', 'find', 'take']) {
        const input = source([1, 2, 3], { returnGet() { return 7; } });
        let caught = false;
        try { await use(R, method, input); } catch (error) { caught = error instanceof TypeError; }
        assert(caught, method + ' ignored noncallable return');
      }
    }],
    ['normal short circuit rejects primitive return results', async R => {
      for (const returned of [undefined, null, false, 9]) {
        const input = source([1, 2, 3], { returnGet() { return () => Promise.resolve(returned); } });
        let caught = false;
        try { await R.prototype.some.call(input, () => true); }
        catch (error) { caught = error instanceof TypeError; }
        assert(caught, 'some accepted primitive return result');
      }
    }],
    ['body rejection survives throwing return getters and rejected cleanup', async R => {
      for (const method of ['forEach', 'reduce', 'some']) {
        for (const getter of [false, true]) {
          const sentinel = new Error('body');
          const input = source([1, 2, 3], { returnGet() {
            if (getter) throw new Error('cleanup getter');
            return () => Promise.reject(new Error('cleanup rejection'));
          } });
          let caught;
          try {
            const fn = () => { throw sentinel; };
            if (method === 'reduce') await R.prototype.reduce.call(input, fn, 0);
            else await R.prototype[method].call(input, fn);
          } catch (error) { caught = error; }
          assert(caught === sentinel && input.counts.returnGets === 1, method + ' replaced body failure');
        }
      }
    }],
    ['falsy terminal-operation errors retain exact identity', async R => {
      for (const reason of [undefined, null, false, 0, -0, '', Symbol('reason'), {}]) {
        for (const method of ['forEach', 'reduce']) {
          const input = source([1], { returnGet() { throw new Error('cleanup'); } });
          let rejected = false, caught;
          try {
            const fn = () => Promise.reject(reason);
            if (method === 'reduce') await R.prototype.reduce.call(input, fn, 0);
            else await R.prototype.forEach.call(input, fn);
          } catch (error) { rejected = true; caught = error; }
          assert(rejected && Object.is(caught, reason), method + ' replaced falsy throw');
        }
      }
    }],
    ['async values are not unwrapped before the visitor', async R => {
      const value = Promise.resolve(8);
      let seen;
      const input = source([value]);
      await R.prototype.forEach.call(input, chunk => { seen = chunk; });
      assert(seen === value, 'unwrapped an async iterator value');
    }],
    ['ordered concurrent mapping retains pressure and errors', async R => {
      let active = 0, peak = 0;
      const input = source([1, 2, 3, 4, 5, 6]);
      const output = await collect(R.prototype.map.call(input, async x => {
        active++; peak = Math.max(peak, active);
        await Promise.resolve(); active--; return x * 3;
      }, { concurrency: 3, highWaterMark: 1 }));
      same(output, [3, 6, 9, 12, 15, 18], 'ordered map');
      assert(peak <= 3 && active === 0 && input.counts.nextGets === 1, 'mapper concurrency/record');
    }],
    ['long stream visits next getter once without collecting a worker backlog', async R => {
      let count = 0, nextGets = 0, sum = 0;
      const input = { [Symbol.asyncIterator]() { return { get next() {
        nextGets++;
        return function () { return count === 4096 ? { done: true } : { value: count++, done: false }; };
      } }; } };
      await R.prototype.forEach.call(input, value => { sum += value; });
      assert(count === 4096 && sum === 8386560 && nextGets === 1, 'long stream');
    }],
    ['cancellation still closes an outstanding source read', async R => {
      const controller = new AbortController(), reason = { cancelled: true };
      let destroyed = 0, closed = 0, rejectRead;
      const input = { [Symbol.asyncIterator]() { return {
        next() {
          Promise.resolve().then(() => controller.abort(reason));
          return new Promise((resolve, reject) => { rejectRead = reject; });
        },
        return() { closed++; return Promise.resolve({ done: true }); }
      }; }, destroy() { destroyed++; rejectRead(new Error('read interrupted')); } };
      let caught;
      try { await R.prototype.toArray.call(input, { signal: controller.signal }); }
      catch (error) { caught = error; }
      assert(caught && caught.code === 'ABORT_ERR' && caught.cause === reason, 'lost cancellation');
      assert(destroyed === 1 && closed === 1, 'pending producer was not closed once');
    }, { reference: false }],
    ['throwing destroy cannot suppress iterator cleanup or replace the body failure', async R => {
      const sentinel = new Error('visitor');
      const input = source([1, 2, 3]);
      let destroys = 0;
      input.destroy = function () { destroys++; throw new Error('destroy'); };
      let caught;
      try { await R.prototype.forEach.call(input, () => { throw sentinel; }); }
      catch (error) { caught = error; }
      assert(caught === sentinel && destroys === 1 && input.counts.closes === 1,
        'failed destruction replaced the body or skipped iterator return');
    }, { reference: false }],
    ['cancelling a stalled mapper retires the source without waiting for the callback', async R => {
      const controller = new AbortController(), reason = new Error('stop');
      const input = source([1, 2, 3]);
      let calls = 0;
      const operation = R.prototype.forEach.call(input, () => {
        calls++;
        Promise.resolve().then(() => controller.abort(reason));
        return new Promise(() => {});
      }, { signal: controller.signal });
      let caught;
      try { await operation; } catch (error) { caught = error; }
      assert(caught && caught.code === 'ABORT_ERR' && caught.cause === reason, 'stalled visitor did not abort');
      assert(calls === 1 && input.counts.closes === 1, 'started another visitor or failed to close');
    }, { reference: false }]
  ];
})()
