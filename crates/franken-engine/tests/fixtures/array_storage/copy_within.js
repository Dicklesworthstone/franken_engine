// Shared reference fixture. Native tests execute this without replacing builtins.
const copy = (object, ...args) => Array.prototype.copyWithin.call(object, ...args);
const proxy = (target, handler) => new Proxy(target, handler);
function sparse(length) { const value = []; value.length = length; return value; }
function show(value) {
  return Object.keys(value).filter(key => key !== 'length')
    .map(key => key + ':' + String(value[key])).join('|');
}
function report(name, run) { console.log(name + ' ' + run()); }
report('overlap-right', () => {
  const a = sparse(131072);
  a[0] = 'a'; a[10] = 'b'; a[70000] = 'c'; a[119999] = 'd';
  a[120000] = 'outside'; a[120001] = 'old'; a[130000] = 'stay';
  const result = copy(a, 2, 0, 120000);
  return (result === a) + ' ' + a.length + ' ' + show(a);
});
report('overlap-left', () => {
  const a = sparse(131072);
  a[1] = 'stale'; a[2] = 'a'; a[70000] = 'b'; a[131070] = 'tail'; a[131071] = 'c';
  copy(a, 0, 2);
  return a.length + ' ' + show(a);
});
report('destination-only', () => {
  const a = sparse(262144); a[5] = 'erase'; a[100000] = 'erase'; a[200000] = 'copy';
  copy(a, 0, 131072);
  return show(a);
});
report('identity-and-undefined', () => {
  const a = sparse(262144); const value = {};
  a[131073] = value; a[200000] = undefined; a[10] = 'erase';
  copy(a, 0, 131072);
  return (a[1] === value) + ' ' + (1 in a) + ' ' + (68928 in a) + ' ' +
    (a[68928] === undefined) + ' ' + (10 in a) + ' ' + Object.keys(a).join(',');
});
report('getter-inserts-future', () => {
  const a = sparse(400000); const log = [];
  Object.defineProperty(a, '0', {get() { log.push('get0'); a[70000] = 'new'; return 'first'; }});
  copy(a, 200000, 0, 131072);
  return log.join(',') + ' ' + a[200000] + ' ' + a[270000] + ' ' + (270001 in a);
});
report('setter-mutates-both-ranges', () => {
  const a = sparse(400000); const log = []; const p = Object.create(Array.prototype);
  a[0] = 'first'; a[90000] = 'remove';
  Object.defineProperty(p, '200000', {set(value) {
    log.push('set:' + value); a[70000] = 'new'; delete a[90000]; a[290000] = 'stale';
  }});
  Object.setPrototypeOf(a, p); copy(a, 200000, 0, 131072);
  return log.join(',') + ' ' + a[270000] + ' ' + (90000 in a) + ' ' + (290000 in a);
});
report('reverse-getter-inserts-earlier', () => {
  const a = sparse(200000); let calls = 0;
  Object.defineProperty(a, '100000', { configurable: true, get() {
    calls++; a[50000] = 'new'; return 'last';
  }});
  copy(a, 1, 0, 131072);
  return calls + ' ' + a[100001] + ' ' + a[50001] + ' ' + (100000 in a) + ' ' + (50000 in a);
});
report('inherited-non-enumerable', () => {
  const a = sparse(262144); const p = Object.create(Array.prototype); const log = [];
  Object.defineProperty(p, '150000', {get() { log.push('inherited'); return 'x'; }});
  a[100] = 'erase'; Object.setPrototypeOf(a, p); copy(a, 0, 131072);
  return log.join(',') + ' ' + a[18928] + ' ' + (100 in a);
});
report('prototype-replacement', () => {
  const a = sparse(400000); const p = Object.create(Array.prototype); p[70000] = 'new';
  Object.defineProperty(a, '0', {get() { Object.setPrototypeOf(a, p); return 'first'; }});
  copy(a, 200000, 0, 131072);
  return a[200000] + ' ' + a[270000];
});
report('delete-refusal-is-ordered', () => {
  const a = sparse(262144); a[131072] = 'first'; a[1] = 'erase'; a[100000] = 'untouched';
  Object.defineProperty(a, '50000', {value:'locked', enumerable:true});
  let error = ''; try { copy(a, 0, 131072); } catch(e) { error = e.name; }
  return error + ' ' + a[0] + ' ' + (1 in a) + ' ' + a[50000] + ' ' + a[100000];
});
report('setter-throw-stops-read', () => {
  const a = sparse(400000); const token = {}; let later = 0; const p = Object.create(Array.prototype);
  a[0] = 'first'; Object.defineProperty(a, '70000', {get() {later++; return 7; }});
  Object.defineProperty(p, '200000', {set() {throw token; }}); Object.setPrototypeOf(a,p);
  let same = false; try {copy(a,200000,0,131072);} catch(e) {same = e === token;}
  return same + ' ' + later + ' ' + (270000 in a);
});
report('proxy-traps-keep-order', () => {
  const a = [1,,3]; const log = [];
  const p = proxy(a, {
    get(target,key,receiver) {log.push('g'+key); return Reflect.get(target,key,receiver);},
    has(target,key) {log.push('h'+key); return Reflect.has(target,key);},
    set(target,key,value) {log.push('s'+key+':'+value); return Reflect.set(target,key,value);},
    deleteProperty(target,key) {log.push('d'+key); return Reflect.deleteProperty(target,key);}
  });
  copy(p,0,1); return log.join(',') + ' ' + show(a);
});
report('empty-frozen-and-same-range', () => {
  const a = Object.freeze(sparse(131072)); copy(a,1,0);
  const b = sparse(131072); let gets = 0; let sets = 0;
  Object.defineProperty(b,'50000',{get() {gets++;return 1;},set() {sets++;}});
  copy(b,0,0); return a.length + ' ' + gets + ' ' + sets;
});
report('coercion-captured-length', () => {
  const a = sparse(262144); const log = []; a[131072] = 8;
  const to = {valueOf() {log.push('to'); return 0;}};
  const from = {valueOf() {log.push('from'); a.length = 200000; a[190000] = 9; return 131072;}};
  const end = {valueOf() {log.push('end'); return 262144;}};
  copy(a,to,from,end); return log.join(',') + ' ' + a.length + ' ' + a[0] + ' ' + a[58928];
});
report('numeric-looking-names', () => {
  const a = sparse(262144); a['01'] = 'leading'; a['4294967295'] = 'named';
  a[131080] = 'x'; copy(a,0,131072);
  return a[8] + ' ' + a['01'] + ' ' + a['4294967295'] + ' ' + a.length;
});
report('nested-move', () => {
  const a = sparse(400000); const b = sparse(262144); b[200000] = 'inner';
  Object.defineProperty(a,'0',{get() {copy(b,0,131072); a[70000]='later'; return 'outer';}});
  copy(a,200000,0,131072); return a[200000] + ' ' + a[270000] + ' ' + b[68928];
});
