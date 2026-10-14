// This same program is executed by the Rust interpreter test and live Node.
// It uses only the single-agent contract, not a simulated second worker.
(async function () {
  function check(condition, message) { if (!condition) throw new Error(message); }
  function watch(view, index, name, seen, promises, timeout) {
    const expected = view instanceof BigInt64Array ? 0n : 0;
    const result = Atomics.waitAsync(view, index, expected, timeout);
    check(result.async === true, 'waiter must be asynchronous');
    const observed = result.value.then(function (value) {
      check(value === 'ok', 'unexpected waiter outcome');
      seen.push(name);
    });
    promises.push(observed);
  }

  {
    const data = new SharedArrayBuffer(32);
    const a = new Int32Array(data), alias = new Int32Array(data, 4);
    const other = new Int32Array(new SharedArrayBuffer(32));
    const seen = [], promises = [];
    watch(a, 1, 'a', seen, promises);
    watch(a, 0, 'zero', seen, promises);
    watch(alias, 0, 'b', seen, promises);
    watch(other, 1, 'other', seen, promises);
    watch(a, 1, 'c', seen, promises);
    const counts = [Atomics.notify(alias, 0, 2), Atomics.notify(a, 1, 1),
      Atomics.notify(other, 1), Atomics.notify(a, 0), Atomics.notify(a, 1)];
    await Promise.all(promises);
    check(seen.join(',') === 'a,b,c,other,zero', 'byte-address FIFO or buffer identity');
    check(counts.join(',') === '2,1,1,1,0', 'notification counts');
    console.log('fifo', seen.join(','), counts.join(','));
  }

  {
    const data = new SharedArrayBuffer(32);
    const big = new BigInt64Array(data), small = new Int32Array(data);
    const alias = new Int32Array(data, 8);
    const seen = [], promises = [];
    watch(big, 1, 'big', seen, promises);
    watch(small, 2, 'small', seen, promises);
    const first = Atomics.notify(alias, 0, 1), second = Atomics.notify(big, 1);
    await Promise.all(promises);
    check(first === 1 && second === 1 && seen.join(',') === 'big,small', 'shared byte location across widths');
    console.log('widths', seen.join(','), first, second);
  }

  {
    const view = new Int32Array(new SharedArrayBuffer(4));
    const seen = [], promises = [], trace = [];
    for (let i = 0; i < 4; i++) watch(view, 0, i, seen, promises);
    for (const count of [0, -0, -5, -Infinity, NaN, 0.9]) {
      check(Atomics.notify(view, 0, count) === 0, 'zero normalized count');
    }
    for (const count of [1n, Symbol('count')]) {
      let rejected = false;
      try { Atomics.notify(view, 0, count); } catch (error) { rejected = error instanceof TypeError; }
      check(rejected, 'invalid count conversion');
    }
    check(Atomics.notify(view, 0, 1.9) === 1, 'fractional count');
    const index = { valueOf() { trace.push('index'); return 0; } };
    const count = { valueOf() { trace.push('count'); check(Atomics.notify(view, 0, 1) === 1, 'nested notify'); return 1; } };
    check(Atomics.notify(view, index, count) === 1, 'outer notify after coercion');
    check(Atomics.notify(view, 0) === 1, 'omitted count');
    await Promise.all(promises);
    check(seen.join(',') === '0,1,2,3' && trace.join(',') === 'index,count', 'coercion order');
    console.log('coercion', seen.join(','), trace.join(','));
  }

  {
    const view = new Int32Array(new SharedArrayBuffer(4));
    const seen = [], promises = [];
    let late, nestedCount;
    for (let i = 0; i < 3; i++) {
      const result = Atomics.waitAsync(view, 0, 0);
      promises.push(result.value.then(function (value) {
        check(value === 'ok', 'reaction result');
        seen.push(i);
        if (i === 0) {
          late = Atomics.waitAsync(view, 0, 0).value.then(function (value) {
            check(value === 'ok', 'late outcome'); seen.push('late');
          });
          nestedCount = Atomics.notify(view, 0);
        }
      }));
    }
    const count = Atomics.notify(view, 0);
    await Promise.all(promises);
    await late;
    check(count === 3 && nestedCount === 1 && seen.join(',') === '0,1,2,late', 'reaction reentry');
    console.log('reentry', count, nestedCount, seen.join(','));
  }

  {
    const view = new Int32Array(new SharedArrayBuffer(4));
    const seen = [], promises = [];
    check(Atomics.waitAsync(view, 0, 1).value === 'not-equal', 'mismatched value');
    const immediate = Atomics.waitAsync(view, 0, 0, 0);
    check(!immediate.async && immediate.value === 'timed-out', 'zero timeout');
    for (let i = 0; i < 16; i++) watch(view, 0, i, seen, promises, 1000000);
    const count = Atomics.notify(view, 0);
    await Promise.all(promises);
    check(count === 16 && seen.every((value, index) => value === index), 'finite waiter order');
    check(Atomics.notify(view, 0) === 0, 'retired finite waiters');
    console.log('finite', count, seen.length);
  }

  {
    const view = new Int32Array(new SharedArrayBuffer(4));
    const seen = [], promises = [];
    for (let i = 0; i < 512; i++) watch(view, 0, i, seen, promises);
    const ordinary = new Int32Array(1);
    let conversions = 0;
    check(Atomics.notify(ordinary, 0, { valueOf() { conversions++; return Infinity; } }) === 0,
      'unshared notification has no waiter list');
    check(conversions === 1, 'unshared notification still converts count');
    let badCount = false;
    try { Atomics.notify(ordinary, 0, 1n); } catch (error) { badCount = error instanceof TypeError; }
    check(badCount, 'unshared notification must not skip invalid count');
    check(Atomics.notify(view, 0, Infinity) === 512, 'bulk notification count');
    await Promise.all(promises);
    check(seen.every((value, index) => value === index), 'bulk FIFO');
    check(Atomics.notify(view, 0) === 0, 'bulk retirement');
    console.log('bulk', seen.length, seen.reduce((sum, value) => sum + value, 0));
  }
})().catch(error => console.log('FAIL', error.message));
