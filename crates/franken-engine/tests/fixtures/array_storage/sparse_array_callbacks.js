// Shared observable semantics. Keep the Node reference length bounded; native
// maximum-length/resource cases live separately in the Rust integration test.
const length = 131072;
function sparse() { const a = []; a.length = length; return a; }
function report(name, body) { console.log(name + ' ' + body()); }
report('forEach-live', () => {
  const a = sparse(); a[0] = 'zero'; a[100000] = 'last'; const seen = [];
  a.forEach((value, k) => {
    seen.push(k + ':' + value);
    if (k === 0) { a[1] = 'one'; a[50000] = 'middle'; delete a[100000]; }
    if (k === 50000) { a[65536] = 'later'; a[length] = 'outside'; }
  });
  return seen.join(',') + ' length=' + a.length;
});
report('map-species-live', () => {
  const a = sparse(); a[0] = 1; a[100000] = 3; const seen = [];
  a.constructor = { [Symbol.species]: function(n) {
    seen.push('C' + n); a[50000] = 2;
    return new Proxy({ length: n }, { defineProperty(target, key, descriptor) {
      seen.push('d' + key);
      if (key === '0') a[75000] = 4;
      return Reflect.defineProperty(target, key, descriptor);
    }});
  }};
  const result = a.map((value, k) => { seen.push('m' + k); return value * 10; });
  return seen.join(',') + ' values=' +
    [result[0], result[50000], result[75000], result[100000]].join(',') +
    ' length=' + result.length + ' hole=' + (1 in result);
});
report('filter-identity', () => {
  const a = sparse(); const x = {}, y = {}, z = {}; a[5] = x; a[70000] = y;
  const result = a.filter((value, k) => {
    if (k === 5) { delete a[70000]; a[90000] = z; }
    return true;
  });
  return result.length + ' ' + (result[0] === x) + ' ' + (result[1] === z);
});
for (const method of ['some', 'every']) {
  report(method + '-short-circuit', () => {
    const a = sparse(); a[0] = 1; a[100000] = 3; const seen = [];
    const result = a[method]((value, k) => {
      seen.push(k); if (k === 0) a[70000] = 2;
      return method === 'some' ? k >= 70000 : k < 70000;
    });
    return result + ' ' + seen.join(',');
  });
}
report('reduce-no-initial', () => {
  const a = sparse(); a[0] = 1; a[100000] = 3; const seen = [];
  const total = a.reduce((sum, value, k) => {
    seen.push(k); if (k === 100000) a[120000] = 4; return sum + value;
  });
  return total + ' ' + seen.join(',');
});
report('reduceRight-live', () => {
  const a = sparse(); a[0] = 1; a[100000] = 3; const seen = [];
  const total = a.reduceRight((sum, value, k) => {
    seen.push(k);
    if (k === 100000) { a[50000] = 2; delete a[0]; a[1000] = 1; }
    return sum + value;
  }, 0);
  return total + ' ' + seen.join(',');
});
report('indexOf-getter', () => {
  const a = sparse(); let calls = 0;
  Object.defineProperty(a, '1', { get() { calls++; a[70000] = 'needle'; return 'first'; }});
  return a.indexOf('needle') + ' ' + calls;
});
report('lastIndexOf-getter', () => {
  const a = sparse(); let calls = 0;
  Object.defineProperty(a, '100000', { get() { calls++; a[50000] = 'needle'; return 'last'; }});
  return a.lastIndexOf('needle') + ' ' + calls;
});
report('inherited-accessor', () => {
  const a = sparse(); const prototype = Object.create(Array.prototype); const seen = [];
  Object.defineProperty(prototype, '40000', {
    get() { seen.push('get'); a[90000] = 'new'; return 'inherited'; }, configurable: true
  });
  Object.setPrototypeOf(a, prototype);
  a.forEach((value, k) => { seen.push(k + ':' + value); });
  return seen.join(',');
});
report('prototype-replacement', () => {
  const a = sparse(); a[0] = 1; const prototype = Object.create(Array.prototype); const seen = [];
  prototype[50000] = 2;
  a.forEach((value, k) => {
    seen.push(k + ':' + value);
    if (k === 0) Object.setPrototypeOf(a, prototype);
    if (k === 50000) prototype[70000] = 3;
  });
  return seen.join(',');
});
report('shrink-keeps-captured-length', () => {
  const a = sparse(); a[0] = 1; a[100000] = 3;
  const prototype = Object.create(Array.prototype); prototype[80000] = 2;
  Object.setPrototypeOf(a, prototype); const seen = [];
  a.forEach((value, k) => { seen.push(k + ':' + value); if (k === 0) a.length = 2; });
  return seen.join(',') + ' length=' + a.length;
});
report('proxy-prototype-is-observable', () => {
  const a = sparse(); a[0] = 1; const token = {}; const seen = [];
  Object.setPrototypeOf(a, new Proxy(Array.prototype, {
    has(target, key) { seen.push('has:' + key); throw token; }
  }));
  let same = false;
  try { Array.prototype.forEach.call(a, (value, k) => { seen.push('cb:' + k); }); }
  catch (error) { same = error === token; }
  return same + ' ' + seen.join(',');
});
report('frozen-readers', () => {
  const a = sparse(); a[50000] = 7; Object.freeze(a);
  const seen = []; a.forEach((value, k) => { seen.push(k + ':' + value); });
  return seen.join(',') + ' ' + a.indexOf(7) + ' ' + a.lastIndexOf(7);
});
report('fromIndex-conversion', () => {
  const a = sparse(); let calls = 0;
  const start = { valueOf() { calls++; a[70000] = 9; return 50000; }};
  return a.indexOf(9, start) + ' ' + calls;
});
report('hole-versus-undefined', () => {
  const a = sparse(); a[90000] = undefined;
  return a.indexOf(undefined) + ' ' + a.lastIndexOf(undefined) + ' ' + a.includes(undefined);
});
report('nested-cursors', () => {
  const a = sparse(); a[0] = 1; a[100000] = 3; const seen = []; let inner = '';
  a.forEach((value, k) => {
    seen.push(k);
    if (k === 0) {
      a[50000] = 2;
      const nested = []; a.forEach((v, i) => { nested.push(i); }); inner = nested.join(',');
      delete a[50000]; a[75000] = 4;
    }
  });
  return seen.join(',') + ' inner=' + inner;
});
report('abrupt-stops-before-future-read', () => {
  const a = sparse(); a[0] = 1; const token = {}; let future = 0; let same = false;
  Object.defineProperty(a, '100000', { get() { future++; return 3; }});
  try { a.forEach(() => { throw token; }); } catch (error) { same = error === token; }
  return same + ' ' + future;
});
