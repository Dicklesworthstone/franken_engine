// Construct actual forward gaps, rather than dense arrays with later deletes.
function check(condition, message) { if (!condition) throw new Error(message); }
const a = [];
for (let i = 0; i < 16; i++) a[i] = i;
a[18] = 18;
console.log('gap', a.length, Object.keys(a).join(','), 16 in a, 17 in a);
a[16] = undefined;
console.log('undefined', Object.hasOwn(a, 16), 17 in a, a[16] === a[17]);
a[17] = 17;
console.log('repaired', a.length, a[18], Object.keys(a).length);
const token = {};
a[21] = token;
console.log('identity', a[21] === token, Object.hasOwn(a, 20));
const inherited = Object.create(Array.prototype);
Object.defineProperty(inherited, '20', { get() { return 'prototype'; }, configurable: true });
Object.setPrototypeOf(a, inherited);
console.log('inherited', a[20], 20 in a, Object.hasOwn(a, 20));
a['01'] = 'named'; a['4294967295'] = 'non-index'; a['\ud800'] = 'exact';
console.log('names', a.length, a['01'], a['4294967295'], a['\ud800']);
const copy = a.slice(17, 22);
console.log('slice', copy.length, copy[0], copy[1], 2 in copy, copy[3], copy[4] === token);
Object.setPrototypeOf(a, Array.prototype);
console.log('removed-inherited', a[20], 20 in a);

const growing = [];
for (let i = 0; i < 64; i++) growing[i] = i;
let last = 63, sum = 2016, holes = 0;
for (let i = 0; i < 257; i++) {
  if (i % 8 === 0) { last += 2; holes++; } else { last++; }
  growing[last] = last; sum += last;
}
let seen = 0, total = 0;
growing.forEach(value => { seen++; total += value; });
check(total === sum && seen === 321, 'forward builder contents');
check(growing.length === 321 + holes, 'forward builder holes');
console.log('builder', growing.length, seen, holes, total);
let absent = 0;
for (let i = 0; i < growing.length; i++) {
  if (!(i in growing)) { absent++; growing[i] = -i; }
}
console.log('backfill', absent, Object.keys(growing).length, growing.length);
const length = growing.length;
growing.copyWithin(0, 64, 68);
console.log('copyWithin', growing.slice(0, 4).join(','), growing.length === length);
growing.length = 16;
growing[19] = 19;
console.log('truncate-regrow', growing.length, 16 in growing, 18 in growing, growing[19]);

const edge = [1, 2, 3];
edge[5] = 5;
Object.defineProperty(edge, '4', { value: 44, writable: false, configurable: true });
console.log('descriptor', Object.getOwnPropertyDescriptor(edge, '4').writable, edge[4]);
edge[4294967294] = 9;
console.log('remote', edge.length, Object.keys(edge).join(','), edge[4294967294], 4294967293 in edge);
edge.length = 6;
console.log('remote-shrink', edge.length, Object.keys(edge).join(','));

const sortable = [];
for (let i = 0; i < 16; i++) sortable[i] = 16 - i;
sortable[18] = 0;
sortable.sort((x, y) => x - y);
console.log('sort', sortable.length, sortable.slice(0, 17).join(','), 17 in sortable, 18 in sortable);
const sparse = [1, 2, 3, 4, 5, 6]; sparse[8] = 8;
console.log('json', JSON.stringify(sparse));
const readonly = [0, 1, 2, 3, 4, 5, 6, 7];
Object.defineProperty(readonly, 'length', { writable: false });
let threw = false;
try { Object.defineProperty(readonly, '10', { value: 10 }); } catch (e) { threw = e instanceof TypeError; }
console.log('locked-length', threw, readonly.length, 10 in readonly);
