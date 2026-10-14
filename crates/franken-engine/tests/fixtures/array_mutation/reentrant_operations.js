// Observable callbacks may invalidate an array-storage proof after dispatch.
// Do not freeze comparator invocation counts: the spec permits different sorts.
function state(a) {
  let text = a.length + ':';
  for (let i = 0; i < a.length; i++) {
    const d = Object.getOwnPropertyDescriptor(a, String(i));
    text += (i ? ',' : '') + (!d ? '-' : 'value' in d ? String(d.value) : 'accessor');
  }
  return text;
}
function test(name, body) {
  try { console.log(name + ' ' + body()); }
  catch (e) { console.log(name + ' unexpected:' + e.name); }
}
function errorOf(body) {
  try { body(); return 'ok'; } catch (e) { return e.name; }
}

test('sort-readonly-during-compare', () => {
  const a = [3, 2, 1]; let changed = false;
  const error = errorOf(() => a.sort((x, y) => {
    if (!changed) { changed = true; Object.defineProperty(a, '1', {writable: false}); }
    return x - y;
  }));
  return error + ' ' + state(a);
});
test('sort-setter-during-compare', () => {
  const a = [3, 2, 1]; let changed = false, writes = '';
  const result = a.sort((x, y) => {
    if (!changed) {
      changed = true;
      Object.defineProperty(a, '1', {set(v) { writes += v; }, configurable: true});
    }
    return x - y;
  });
  return (result === a) + ' ' + state(a) + ' ' + writes;
});
test('sort-freeze-during-compare', () => {
  const a = [3, 2, 1];
  const error = errorOf(() => a.sort((x, y) => { Object.freeze(a); return x - y; }));
  return error + ' ' + state(a);
});
test('sort-shrink-during-compare', () => {
  const a = [3, 2, 1];
  a.sort((x, y) => { a.length = 0; return x - y; });
  return state(a);
});
test('sort-inherited-setter-after-delete', () => {
  const a = [3, 2, 1]; let changed = false, writes = '';
  a.sort((x, y) => {
    if (!changed) {
      changed = true; delete a[1];
      const proto = Object.create(Array.prototype);
      Object.defineProperty(proto, '1', {set(v) { writes += v; }, configurable: true});
      Object.setPrototypeOf(a, proto);
    }
    return x - y;
  });
  return state(a) + ' ' + writes;
});
test('sort-result-conversion-invalidates', () => {
  const a = [3, 2, 1]; let changed = false;
  const error = errorOf(() => a.sort((x, y) => ({valueOf() {
    if (!changed) { changed = true; Object.defineProperty(a, '2', {writable: false}); }
    return x - y;
  }})));
  return error + ' ' + state(a);
});
test('sort-throw-preserves-original', () => {
  const a = [3, 2, 1], token = {};
  let same = false;
  try { a.sort(() => { throw token; }); } catch (e) { same = e === token; }
  return same + ' ' + state(a);
});
test('sort-undefined-and-holes', () => {
  const a = [3, undefined, , 1]; let undefinedSeen = false;
  a.sort((x, y) => { undefinedSeen = undefinedSeen || x === undefined || y === undefined; return x - y; });
  return state(a) + ' ' + undefinedSeen;
});
test('sort-stable-identity', () => {
  const a = [{k: 1, id: 'a'}, {k: 0, id: 'b'}, {k: 1, id: 'c'}, {k: 0, id: 'd'}];
  a.sort((x, y) => x.k - y.k);
  return a.map(x => x.id).join('');
});

test('splice-own-setter', () => {
  const a = [10, 20, 30]; let writes = '';
  Object.defineProperty(a, '0', {get() {return 10;}, set(v) {writes += v;}, configurable: true});
  const removed = a.splice(0, 1);
  return state(a) + ' ' + state(removed) + ' ' + writes;
});
test('splice-readonly-after-partial-move', () => {
  const a = [10, 20, 30, 40];
  Object.defineProperty(a, '1', {writable: false});
  const error = errorOf(() => a.splice(0, 1));
  return error + ' ' + state(a);
});
test('splice-locked-delete-after-moves', () => {
  const a = [10, 20, 30];
  Object.defineProperty(a, '2', {configurable: false});
  const error = errorOf(() => a.splice(0, 1));
  return error + ' ' + state(a);
});
test('splice-species-invalidates-destination', () => {
  const a = [10, 20, 30]; let calls = 0;
  a.constructor = {[Symbol.species]: function(n) {
    calls++; Object.defineProperty(a, '0', {writable: false}); return new Array(n);
  }};
  const error = errorOf(() => a.splice(0, 1));
  return error + ' ' + state(a) + ' ' + calls;
});
test('splice-species-shrinks-source', () => {
  const a = [10, 20, 30];
  a.constructor = {[Symbol.species]: function(n) { a.length = 1; return new Array(n); }};
  const removed = a.splice(0, 1);
  return state(a) + ' ' + state(removed);
});
test('splice-removed-result-defines-not-sets', () => {
  const a = [10, 20, 30], result = {}; let inheritedCalls = 0;
  const proto = {};
  Object.defineProperty(proto, '0', {set(v) {inheritedCalls++;}, configurable: true});
  Object.setPrototypeOf(result, proto);
  a.constructor = {[Symbol.species]: function() {return result;}};
  const removed = a.splice(0, 1);
  return (removed === result) + ' ' + state(result) + ' ' + inheritedCalls + ' ' + state(a);
});
test('splice-result-trap-invalidates-source', () => {
  const a = [10, 20, 30]; let definitions = '';
  a.constructor = {[Symbol.species]: function() {return new Proxy({}, {
    defineProperty(target, key, d) {
      definitions += key + ';';
      if (key === '0') Object.defineProperty(a, '0', {writable: false});
      return Reflect.defineProperty(target, key, d);
    }
  });}};
  const error = errorOf(() => a.splice(0, 1));
  return error + ' ' + definitions + ' ' + state(a);
});
test('splice-noop-still-consults-species', () => {
  const a = [10, 20]; let observed = '';
  a.constructor = {[Symbol.species]: function(n) {observed += n; return {};}};
  const r = a.splice();
  return observed + ' ' + state(a) + ' ' + state(r);
});
test('splice-coercions-before-species', () => {
  const a = [10, 20, 30]; let order = '';
  a.constructor = {[Symbol.species]: function(n) {order += 'S'; return new Array(n);}};
  const start = {valueOf() {order += 'A'; return 1;}};
  const count = {valueOf() {order += 'B'; return 1;}};
  const r = a.splice(start, count, 99);
  return order + ' ' + state(a) + ' ' + state(r);
});
test('splice-result-length-throws-before-source-writes', () => {
  const a = [10, 20, 30];
  const result = {set length(v) {throw new RangeError('length');}};
  a.constructor = {[Symbol.species]: function() {return result;}};
  const error = errorOf(() => a.splice(0, 1));
  return error + ' ' + state(a) + ' ' + result[0];
});
test('splice-insertion-and-explicit-undefined', () => {
  const a = [1, 2, 3]; const r = a.splice(1, undefined, 8, 9);
  return state(a) + ' ' + state(r);
});
test('splice-species-getter-throws-identity', () => {
  const a = [1, 2, 3], token = {}; let same = false;
  Object.defineProperty(a, 'constructor', {get() {throw token;}});
  try { a.splice(0, 1); } catch (e) { same = e === token; }
  return same + ' ' + state(a);
});
test('splice-holes-stay-holes', () => {
  const a = [1, , 3, , 5]; const r = a.splice(1, 3, 8);
  return state(a) + ' ' + state(r);
});
