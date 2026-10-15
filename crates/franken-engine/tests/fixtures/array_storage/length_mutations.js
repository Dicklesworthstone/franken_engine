// Shared reference inputs. Large-but-bounded spans let Node execute every
// observable case; maximum-length and resource checks are native-only tests.
const N = 131072;
function sparse() { const a = []; a.length = N; return a; }
function report(name, value) { console.log(name + ' ' + JSON.stringify(value)); }
function failure(body) { try { body(); return 'none'; } catch (e) { return e.name; } }
{
  const a = sparse(), head = {}, tail = {}; a[0] = head; a[7] = undefined;
  a[70000] = 8; a[N - 1] = tail; a['01'] = 'named';
  const first = a.shift();
  report('shift-sparse', [first === head, a.length, 0 in a, 6 in a, a[6] === undefined,
    a[69999], a[N - 2] === tail, N - 1 in a, a['01']]);
}
{
  const a = sparse(), x = {}, y = {}, old = {}; a[0] = old; a[70000] = 7;
  const length = a.unshift(x, y);
  report('unshift-sparse', [length, a.length, a[0] === x, a[1] === y, a[2] === old,
    3 in a, a[70002], 70000 in a]);
}
{
  const a = sparse(), token = {}; const prototype = Object.create(Array.prototype);
  prototype[80000] = 8; Object.setPrototypeOf(a, prototype);
  Object.defineProperty(a, '0', { configurable: true, get() { a.length = 2; return token; }});
  const first = a.shift();
  report('shift-captured-length', [first === token, a.length, a[79999], 0 in a,
    Object.hasOwn(a, '80000')]);
}
{
  const a = sparse(); let calls = 0; a[100000] = 10;
  Object.defineProperty(a, '1', { configurable: true, get() {
    calls++; a[50000] = 5; delete a[100000]; return 1;
  }});
  a.shift();
  report('shift-getter-live', [calls, a[0], a[49999], 99999 in a, 1 in a]);
}
{
  const a = sparse(); const seen = []; a[70000] = 7;
  Object.defineProperty(a, '70002', { configurable: true, get() { return 2; },
    set(value) { seen.push(value); a[50000] = 5; }
  });
  a.unshift('x', 'y');
  report('unshift-setter-live', [seen, a[50002], a[70004], a[0], a[1], a.length]);
}
{
  const a = sparse(), token = {}; let later = 0;
  Object.defineProperty(a, '0', { configurable: true, get() { throw token; }});
  Object.defineProperty(a, '70000', { get() { later++; return 7; }});
  let same = false; try { a.shift(); } catch (e) { same = e === token; }
  report('first-getter-throws', [same, later, a.length]);
}
{
  const a = sparse(); Object.defineProperty(a, '0', {value: 7, configurable: false});
  a[70000] = 9;
  report('shift-delete-refusal', [failure(() => a.shift()), a[0], a[70000], a.length]);
}
{
  const a = sparse(); a[0] = 1;
  Object.defineProperty(a, String(N - 1), {value: 9, writable: true, configurable: false});
  report('shift-tail-refusal', [failure(() => a.shift()), 0 in a, a[N - 2], a[N - 1], a.length]);
}
{
  const a = sparse(); a[0] = 0; a[1] = 1; a[100000] = 10;
  Object.defineProperty(a, '3', {value: 3, writable: false, configurable: true});
  report('unshift-write-refusal', [failure(() => a.unshift('x', 'y')), a[0], a[1], a[3],
    a[5], a[100002], 100000 in a, a.length]);
}
{
  const seen = []; const o = { get length() { seen.push('length'); return N; },
    set length(n) { seen.push('set:' + n); }, get 0() { seen.push('element'); throw 0; }};
  const result = Array.prototype.unshift.call(o);
  report('unshift-no-items', [result, seen]);
}
{
  let reads = 0; const o = {length: 9007199254740991,
    get 0() { reads++; throw 'unexpected'; }};
  report('unshift-safe-length-refusal', [failure(() => Array.prototype.unshift.call(o, 1)), reads]);
}
{
  const seen = []; const o = {0: 'first', 70000: 'last',
    get length() { seen.push('length'); return {valueOf() { seen.push('number'); return N; }}; },
    set length(n) { seen.push('set:' + n); }};
  const first = Array.prototype.shift.call(o);
  report('shift-length-coercion', [first, seen, o[69999], Object.hasOwn(o, '0')]);
}
for (const method of ['shift', 'unshift']) {
  const seen = []; const a = [1, , 3]; const p = new Proxy(a, {
    get(t, k, r) { seen.push('g' + String(k)); return Reflect.get(t, k, r); },
    has(t, k) { seen.push('h' + String(k)); return Reflect.has(t, k); },
    set(t, k, v, r) { seen.push('s' + String(k)); return Reflect.set(t, k, v, r); },
    deleteProperty(t, k) { seen.push('d' + String(k)); return Reflect.deleteProperty(t, k); }
  });
  const result = method === 'shift' ? Array.prototype.shift.call(p) : Array.prototype.unshift.call(p, 9);
  report('proxy-' + method, [result, seen, a, Object.keys(a)]);
}
{
  const o = {0: 1, 70000: 7}; Object.defineProperty(o, 'length', {value: N, writable: false});
  report('shift-final-length-refusal', [failure(() => Array.prototype.shift.call(o)),
    Object.hasOwn(o, '0'), o[69999], o.length]);
}
{
  const a = new Uint8Array([1, 2]), b = new Uint8Array([1, 2]);
  report('typed-receivers', [failure(() => Array.prototype.shift.call(a)), Array.from(a),
    failure(() => Array.prototype.unshift.call(b, 9)), Array.from(b)]);
}
{
  const a = sparse(); a[0] = a; a[90000] = a;
  report('cyclic-identity', [a.shift() === a, a[89999] === a, a.length]);
}
{
  const a = sparse(), x = {}; a[0] = 'head'; a[70000] = x; a[120000] = 9;
  const removed = a.splice(100, 80000, 'new');
  report('splice-shrink', [removed.length, Object.keys(removed), removed[69900] === x,
    a.length, a[0], a[100], a[40001], 70000 in a, 120000 in a]);
}
{
  const a = sparse(), x = {}; a[7] = x; a[100000] = 3;
  const removed = a.splice(5, 0, 'x', 'y');
  report('splice-grow', [removed.length, a.length, a[5], a[6], a[9] === x, a[100002],
    7 in a, 100000 in a]);
}
{
  const a = sparse(); a[0] = 1; a[100000] = 3; const trace = [];
  a.constructor = { [Symbol.species]: function(n) {
    trace.push('C' + n); a[50000] = 2;
    return new Proxy({}, { defineProperty(t, k, d) {
      trace.push('d' + k); if (k === '0') a[70000] = 4;
      return Reflect.defineProperty(t, k, d);
    }, set(t, k, v) {
      trace.push('s' + k + ':' + v); return Reflect.set(t, k, v);
    }});
  }};
  const r = a.splice(0, N);
  report('splice-species-live', [trace, r[0], r[50000], r[70000], r[100000], r.length,
    a.length, Object.keys(a)]);
}
{
  const a = sparse(), trace = []; a[10] = 1; a[100000] = 3;
  Object.defineProperty(a, '20', {configurable: true, get() {
    trace.push('get20'); a[70000] = 2; return 9;
  }});
  const r = a.splice(10, 100000);
  report('splice-removed-getter', [trace, Object.keys(r), r[0], r[10], r[69990], r[99990], a.length]);
}
{
  const a = sparse(), trace = []; a[100000] = 8;
  Object.defineProperty(a, '34464', {configurable: true,
    get() { return 1; }, set(v) { trace.push(v); a[90000] = 9; a[120000] = 12; }});
  const r = a.splice(0, 65536);
  report('splice-tail-live', [r.length, r[34464], trace, a[24464], a[54464],
    90000 in a, 120000 in a, a.length]);
}
{
  const a = sparse(), trace = []; a[100000] = 8;
  Object.defineProperty(a, '100003', {configurable: true, get() { return 4; },
    set(v) { trace.push(v); a[50000] = 5; }});
  const r = a.splice(10, 0, 1, 2, 3);
  report('splice-grow-live', [r.length, trace, a[50003], a[100006], a[10], a[12], a.length]);
}
{
  const a = sparse(); a[5] = 1;
  Object.defineProperty(a, '90000', {value: 9, writable: true, configurable: false});
  a[120000] = 12;
  report('splice-delete-refusal', [failure(() => a.splice(0, N)), a[5], a[90000],
    120000 in a, a.length]);
}
{
  const a = sparse(); a[100000] = 8;
  Object.defineProperty(a, '34464', {value: 3, writable: false, configurable: true});
  report('splice-write-refusal', [failure(() => a.splice(0, 65536)), a[34464], a[100000],
    a.length, 1 in a]);
}
{
  const a = sparse(), token = {}; let moved = 0;
  a[0] = 1; Object.defineProperty(a, '100000', {get() { moved++; return 3; }});
  a.constructor = {[Symbol.species]: function() { return new Proxy({}, {
    defineProperty() { throw token; }
  }); }};
  let same = false; try { a.splice(0, 1); } catch (e) { same = e === token; }
  report('splice-species-failure', [same, moved, a[0], a.length]);
}
{
  const a = sparse(); a[4] = 4; let n = -1;
  a.constructor = {[Symbol.species]: function(length) { n = length; return a; }};
  const r = a.splice(3, 65536);
  report('splice-source-alias', [r === a, n, a[1], a.length, Object.keys(a)]);
}
{
  const a = sparse(), trace = []; a[70000] = 7;
  const r = a.splice({valueOf() {trace.push('start'); a[50000] = 5; return 40000;}},
    {valueOf() {trace.push('count'); a[90000] = 9; return 65536;}}, 'x');
  report('splice-coercions', [trace, Object.keys(r), r[10000], r[30000], r[50000], a[40000], a.length]);
}
{
  const prototype = {}; Object.defineProperty(prototype, '70000', {get() {return 7;}});
  const o = Object.create(prototype); o.length = N; o[100000] = 10;
  const r = Array.prototype.splice.call(o, 65536, 65536);
  report('splice-inherited-removal', [r.length, Object.keys(r), r[4464], r[34464],
    o.length, o[70000], Object.hasOwn(o, '100000')]);
}
{
  const trace = [], target = [1, , 3, 4], p = new Proxy(target, {
    get(t,k,r) { trace.push('g' + String(k)); return Reflect.get(t,k,r); },
    has(t,k) { trace.push('h' + String(k)); return Reflect.has(t,k); },
    set(t,k,v,r) { trace.push('s' + String(k)); return Reflect.set(t,k,v,r); },
    deleteProperty(t,k) { trace.push('d' + String(k)); return Reflect.deleteProperty(t,k); }
  });
  const r = Array.prototype.splice.call(p, 1, 2, 8);
  report('splice-proxy-order', [trace, r, Object.keys(r), target]);
}
{
  const o = {70000: 7}; Object.defineProperty(o, 'length', {value: N, writable: false});
  report('splice-final-length-refusal', [failure(() => Array.prototype.splice.call(o, 0, N)),
    Object.hasOwn(o, '70000'), o.length]);
}
{
  const o = {length: 9007199254740991}; let reads = 0;
  Object.defineProperty(o, '0', {get() {reads++; return 0;}});
  report('splice-safe-length-refusal', [failure(() => Array.prototype.splice.call(o, 0, 0, 1)), reads]);
}
{
  const a = sparse(); a[5] = 5; let constructions = 0;
  a.constructor = {[Symbol.species]: function(n) {constructions++; return {length: n};}};
  const r = a.splice();
  report('splice-no-arguments', [constructions, r.length, a[5], a.length]);
}
