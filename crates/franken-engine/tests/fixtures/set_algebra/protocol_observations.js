// Shared public-protocol countermetric for the native observation-scope change.
// No host effects or secret labels: exact getter/call order must remain unchanged.
(function () {
  'use strict';
  const lines = [];
  const methods = ['union', 'intersection', 'difference', 'symmetricDifference',
    'isSubsetOf', 'isSupersetOf', 'isDisjointFrom'];
  for (const size of [1, 10]) {
    for (const method of methods) {
      const trace = [];
      let other;
      const prototype = {
        get size() {
          if (this !== other) throw new Error('size receiver');
          trace.push('size');
          return { valueOf() { trace.push('number'); return size; } };
        },
        get has() {
          if (this !== other) throw new Error('has receiver');
          trace.push('has');
          return function (value) {
            if (this !== other) throw new Error('has call receiver');
            trace.push('h' + value);
            // Exercise nested builtin observation scopes before continuing.
            if (!new Set([5]).isSubsetOf(new Set([5]))) throw new Error('nested');
            return value === 2 || value === 3;
          };
        },
        get keys() {
          if (this !== other) throw new Error('keys receiver');
          trace.push('keys');
          return function () {
            if (this !== other) throw new Error('keys call receiver');
            trace.push('k');
            let count = 0;
            const iterator = {
              get next() {
                trace.push('next');
                return function () {
                  if (this !== iterator) throw new Error('next call receiver');
                  const index = count++;
                  trace.push('n' + index);
                  return {
                    get done() { trace.push('d' + index); return index === 2; },
                    get value() {
                      if (index === 2) throw new Error('read completed value');
                      trace.push('v' + index); return index + 2;
                    }
                  };
                };
              },
              get return() {
                trace.push('return');
                return function () {
                  if (this !== iterator) throw new Error('return call receiver');
                  trace.push('r'); return {};
                };
              }
            };
            return iterator;
          };
        }
      };
      other = Object.create(prototype);
      const result = new Set([1, 2])[method](other);
      lines.push(method + '/' + size + ':' +
        (typeof result === 'boolean' ? result : Array.from(result).join(',')) + ':' + trace.join(','));
    }
  }
  // Failed protocol steps do not run IteratorClose; an early predicate does.
  for (const failure of ['next', 'done', 'value']) {
    for (const reason of [undefined, null, false, 0]) {
      let closed = 0;
      const iterator = {
        next() {
          if (failure === 'next') throw reason;
          return {
            get done() { if (failure === 'done') throw reason; return false; },
            get value() { throw reason; }
          };
        },
        return() { closed++; return {}; }
      };
      let caught = false;
      try {
        new Set([1]).union({ size: 0, has() { return false; }, keys() { return iterator; } });
      } catch (error) { caught = error === reason; }
      if (!caught || closed !== 0) throw new Error('protocol failure boundary');
    }
  }
  lines.push('abrupt:12 exact throws,0 closes');
  function callable() {}
  callable.size = 2;
  callable.has = function (value) { return value === 1; };
  callable.keys = function () { return [1, 3].values(); };
  lines.push('callable:' + Array.from(new Set([1, 2]).intersection(callable)).join(','));
  const backing = { size: 1, has(value) { return value === 2; }, keys() { return [2].values(); } };
  const seen = [];
  const wrapped = new Proxy(backing, {
    get(target, key, receiver) { seen.push(key); return Reflect.get(target, key, receiver); }
  });
  lines.push('proxy:' + Array.from(new Set([1, 2]).intersection(wrapped)).join(',') + ':' + seen.join(','));
  const zero = new Set([-0]).union(new Set([0]));
  lines.push('zero:' + zero.size + ':' + (1 / Array.from(zero)[0]));
  return lines.join('\n');
})()
