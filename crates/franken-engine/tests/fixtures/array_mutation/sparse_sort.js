// sort's skipped holes are not storage. An abrupt first observation must run
// before any attempt to allocate one Value for every index in a huge length.
function report(name, body) {
  try { console.log(name + ' ' + body()); }
  catch (error) { console.log(name + ' unexpected:' + error.name); }
}
report('array-first-getter', () => {
  const a = []; a.length = 4294967295;
  const token = {}; let calls = 0, same = false;
  Object.defineProperty(a, '0', {get() { calls++; throw token; }, configurable: true});
  try { a.sort((x, y) => x - y); } catch (error) { same = error === token; }
  return same + ' ' + calls + ' ' + a.length;
});
report('proxy-first-has', () => {
  const token = {}; let trace = '', same = false;
  const a = new Proxy({length: 4194304}, {
    get(target, key) { trace += 'get:' + key + ';'; return target[key]; },
    has(target, key) { trace += 'has:' + key + ';'; throw token; }
  });
  try { Array.prototype.sort.call(a); } catch (error) { same = error === token; }
  return same + ' ' + trace;
});
report('proxy-first-get', () => {
  const token = {}; let trace = '', same = false;
  const a = new Proxy({length: 4194304}, {
    get(target, key) {
      trace += 'get:' + key + ';';
      if (key === 'length') return target.length;
      throw token;
    },
    has(target, key) { trace += 'has:' + key + ';'; return true; }
  });
  try { Array.prototype.sort.call(a, (x, y) => x - y); }
  catch (error) { same = error === token; }
  return same + ' ' + trace;
});
report('capture-growth', () => {
  const a = []; a.length = 257;
  for (let i = 0; i < 65; i++) a[i * 4] = 64 - i;
  a.sort((x, y) => x - y);
  return a.length + ' ' + a.slice(0, 65).join(',') + ' ' + (65 in a) + ' ' + (256 in a);
});
report('getter-changes-unread-elements', () => {
  const a = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]; let trace = '';
  Object.defineProperty(a, '0', {
    get() { trace += 'g'; delete a[9]; a[8] = 20; return 9; },
    set(value) { trace += 's' + value; }, configurable: true
  });
  a.sort((x, y) => x - y);
  return trace + ' ' + a.slice(1, 9).join(',') + ' ' + (9 in a);
});
report('growth-comparator-reentry', () => {
  const a = []; for (let i = 32; i >= 0; i--) a.push(i);
  let first = true, nested = '';
  a.sort((x, y) => {
    if (first) { first = false; nested = [4, 1, 3, 2].sort((p, q) => p - q).join(','); }
    return x - y;
  });
  return nested + ' ' + a[0] + ' ' + a[16] + ' ' + a[32] + ' ' + a.length;
});
