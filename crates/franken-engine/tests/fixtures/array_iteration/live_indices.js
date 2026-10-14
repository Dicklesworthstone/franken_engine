// Shared semantic expectations. Run on the real engine AND on unmodified Node.
// Callbacks may change unread properties; only the initial length is fixed.
function check(name, expected, body) {
  const actual = String(body());
  if (actual !== expected) throw new Error(name + ': expected ' + expected + ', got ' + actual);
  console.log(name + ' ' + actual);
}
function walk(method, source, callback, extra) {
  return Array.prototype[method].call(source, callback, extra);
}
check('forEach-inserts', '0:a;50000:b;90000:z;', () => {
  const o = {length: 131072, 0: 'a', 90000: 'z'}; let seen = '';
  walk('forEach', o, (v, k) => { seen += k + ':' + v + ';'; if (k === 0) o[50000] = 'b'; });
  return seen;
});
check('same-count-replacement', '0,40000', () => {
  const o = {length: 131072, 0: 1, 50000: 2}; const seen = [];
  walk('forEach', o, (v, k) => { seen.push(k); if (k === 0) { delete o[50000]; o[40000] = 3; } });
  return seen.join(',');
});
check('map-future-property', '131072 0,50000,90000 8', () => {
  const o = {length: 131072, 0: 1, 90000: 3};
  const r = walk('map', o, (v, k) => { if (k === 0) o[50000] = 4; return v * 2; });
  return r.length + ' ' + Object.keys(r).join(',') + ' ' + r[50000];
});
check('filter-future-property', '1,4,3', () => {
  const o = {length: 131072, 0: 1, 90000: 3};
  return walk('filter', o, (v, k) => { if (k === 0) o[50000] = 4; return true; }).join(',');
});
check('some-future-property', 'true 0,50000', () => {
  const o = {length: 131072, 0: 1}; const seen = [];
  const r = walk('some', o, (v, k) => { seen.push(k); if (k === 0) o[50000] = 7; return v === 7; });
  return r + ' ' + seen.join(',');
});
check('every-future-property', 'false 0,50000', () => {
  const o = {length: 131072, 0: 1}; const seen = [];
  const r = walk('every', o, (v, k) => { seen.push(k); if (k === 0) o[50000] = 0; return v > 0; });
  return r + ' ' + seen.join(',');
});
check('reduce-adds', '6 0,50000,90000', () => {
  const o = {length: 131072, 0: 1, 90000: 3}; const seen = [];
  const r = walk('reduce', o, (acc, v, k) => { seen.push(k); if (k === 0) o[50000] = 2; return acc + v; }, 0);
  return r + ' ' + seen.join(',');
});
check('reduce-initial-getter', '6 50000,90000', () => {
  const o = {length: 131072, 90000: 3}; const seen = [];
  Object.defineProperty(o, '0', {get() { o[50000] = 2; return 1; }});
  const r = Array.prototype.reduce.call(o, (acc, v, k) => { seen.push(k); return acc + v; });
  return r + ' ' + seen.join(',');
});
check('reduceRight-adds', '6 90000,50000,0', () => {
  const o = {length: 131072, 0: 1, 90000: 3}; const seen = [];
  const r = walk('reduceRight', o, (acc, v, k) => { seen.push(k); if (k === 90000) o[50000] = 2; return acc + v; }, 0);
  return r + ' ' + seen.join(',');
});
check('reduceRight-initial-getter', '6 50000,0', () => {
  const o = {length: 131072, 0: 1}; const seen = [];
  Object.defineProperty(o, '90000', {get() { o[50000] = 2; return 3; }});
  const r = Array.prototype.reduceRight.call(o, (acc, v, k) => { seen.push(k); return acc + v; });
  return r + ' ' + seen.join(',');
});
check('getter-replaces-prototype', '0:a;20000:p;', () => {
  const o = {length: 131072, 30000: 'old'}; let seen = '';
  Object.defineProperty(o, '0', {get() {
    delete o[30000]; Object.setPrototypeOf(o, {20000: 'p'}); return 'a';
  }});
  walk('forEach', o, (v, k) => { seen += k + ':' + v + ';'; });
  return seen;
});
check('inherited-nonenumerable', '0:a;20000:own;60000:p;', () => {
  const p = Object.create(null); Object.defineProperty(p, '60000', {value: 'p'});
  p[20000] = 'shadowed'; const o = Object.create(p);
  o.length = 131072; o[0] = 'a'; o[20000] = 'own'; let seen = '';
  walk('forEach', o, (v, k) => { seen += k + ':' + v + ';'; });
  return seen;
});
check('prototype-getter-adds', '0:a;40000:b;', () => {
  const p = {}; const o = Object.create(p); o.length = 131072; let seen = '';
  Object.defineProperty(p, '0', {get() { o[40000] = 'b'; return 'a'; }});
  walk('forEach', o, (v, k) => { seen += k + ':' + v + ';'; });
  return seen;
});
check('fixed-length-and-no-revisit', '0,50000 1', () => {
  const o = {length: 131072, 0: 1}; const seen = [];
  walk('forEach', o, (v, k) => { seen.push(k); if (k === 0) {
    o.length = 1; o[50000] = 2; o[131072] = 3; delete o[0]; o[0] = 9;
  }});
  return seen.join(',') + ' ' + o.length;
});
check('callback-receiver-and-this', 'true true', () => {
  const o = {length: 131072, 1000: 1}, receiver = {}; let same = false, bound = false;
  walk('forEach', o, function(v, k, source) { same = source === o; bound = this === receiver; }, receiver);
  return same + ' ' + bound;
});
check('indexOf-getter-adds', '50000', () => {
  const o = {length: 131072};
  Object.defineProperty(o, '0', {get() { o[50000] = 'hit'; return 'miss'; }});
  return Array.prototype.indexOf.call(o, 'hit');
});
check('lastIndexOf-getter-adds', '50000', () => {
  const o = {length: 131072};
  Object.defineProperty(o, '100000', {get() { o[50000] = 'hit'; return 'miss'; }});
  return Array.prototype.lastIndexOf.call(o, 'hit');
});
check('indexOf-from-conversion', '40000 1', () => {
  const o = {length: 131072}; let calls = 0;
  const start = {valueOf() { calls++; o[40000] = 'hit'; return 100; }};
  return Array.prototype.indexOf.call(o, 'hit', start) + ' ' + calls;
});
check('from-boundaries', '-1 -1 0 0 -1', () => {
  const o = {length: 131072, 0: 7};
  return [Array.prototype.indexOf.call(o, 7, Infinity),
    Array.prototype.lastIndexOf.call(o, 7, -Infinity),
    Array.prototype.indexOf.call(o, 7, NaN),
    Array.prototype.lastIndexOf.call(o, 7, undefined),
    Array.prototype.indexOf.call(o, NaN)].join(' ');
});
check('large-named-index', '4294967295 4294967295', () => {
  const o = {length: 4294967297, 4294967295: 'hit'};
  return Array.prototype.indexOf.call(o, 'hit', 4294967294) + ' ' +
    Array.prototype.lastIndexOf.call(o, 'hit', 4294967296);
});
check('proxy-installed-during-callback', 'true 1,2', () => {
  const o = {length: 131072, 0: 'a'}, has = [];
  const r = walk('some', o, (v, k) => {
    if (k === 0) Object.setPrototypeOf(o, new Proxy({2: 'hit'}, {
      has(target, key) { has.push(key); return key in target; }
    }));
    return v === 'hit';
  });
  return r + ' ' + has.join(',');
});
check('first-proxy-trap-throw', 'true get:length;has:0;', () => {
  const token = {}; let log = '', same = false;
  const o = new Proxy({length: 131072}, {
    get(target, key) { log += 'get:' + key + ';'; return target[key]; },
    has(target, key) { log += 'has:' + key + ';'; throw token; },
    ownKeys() { throw new Error('must not enumerate proxy'); }
  });
  try { walk('forEach', o, () => {}); } catch (e) { same = e === token; }
  return same + ' ' + log;
});
check('new-getter-throw-identity', 'true 0', () => {
  const o = {length: 131072, 0: 1}, token = {}; const seen = []; let same = false;
  try { walk('forEach', o, (v, k) => {
    seen.push(k); Object.defineProperty(o, '50000', {get() { throw token; }});
  }); } catch (e) { same = e === token; }
  return same + ' ' + seen.join(',');
});
check('nested-cursors', '0,40000,70000 0,40000,70000', () => {
  const o = {length: 131072, 0: 1, 70000: 3}; const outer = [], inner = [];
  walk('forEach', o, (v, k) => {
    outer.push(k);
    if (k === 0) walk('forEach', o, (w, n) => { inner.push(n); if (n === 0) o[40000] = 2; });
  });
  return outer.join(',') + ' ' + inner.join(',');
});
check('find-family-visits-holes', '0,1,2,3 3,2,1,0 1 2', () => {
  const o = {length: 4, 0: 'a', 3: 'z'}; const a = [], b = [];
  walk('find', o, (v, k) => { a.push(k); return false; });
  walk('findLast', o, (v, k) => { b.push(k); return false; });
  return a.join(',') + ' ' + b.join(',') + ' ' + walk('findIndex', o, v => v === undefined)
    + ' ' + walk('findLastIndex', o, v => v === undefined);
});
check('noncanonical-names', '0', () => {
  const o = {length: 131072, 0: 1, '00': 2, '01': 3, '-0': 4, '+1': 5, '1e3': 6, '1.0': 7};
  Object.defineProperty(o, '\ud800', {value: 8}); const seen = [];
  walk('forEach', o, (v, k) => seen.push(k));
  return seen.join(',');
});
check('empty-reduce-and-initial', 'TypeError 9', () => {
  const o = {length: 131072}; let error = '';
  try { Array.prototype.reduce.call(o, (a, v) => a + v); } catch (e) { error = e.name; }
  return error + ' ' + walk('reduce', o, (a, v) => a + v, 9);
});
