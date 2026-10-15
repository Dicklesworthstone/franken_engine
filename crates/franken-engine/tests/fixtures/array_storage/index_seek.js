// Numeric indices and irrelevant metadata share one ordinary object. A sparse
// callback cursor must not rescan every key for each widely separated value.
const o = {length: 131072};
for (let i = 0; i < 256; i++) o[1 + i * 257] = i;
for (let i = 0; i < 512; i++) o['metadata-' + i] = 'not an index';
let count = 0, sum = 0, first = -1, last = -1;
Array.prototype.forEach.call(o, (value, index) => {
  if (count === 0) first = index;
  count++; sum += value; last = index;
});
console.log('forward', count, sum, first, last);
let reverseCount = 0, previous = o.length, decreasing = true;
const reverseSum = Array.prototype.reduceRight.call(o, (total, value, index) => {
  reverseCount++; decreasing = decreasing && index < previous; previous = index;
  return total + value;
}, 0);
console.log('reverse', reverseCount, reverseSum, decreasing, previous);
const proto = {};
Object.defineProperty(proto, '70000', {value: 7, configurable: true});
const live = Object.create(proto);
live.length = 131072; live[10000] = 1; live[90000] = 9;
let visits = '';
Array.prototype.forEach.call(live, (value, index) => {
  visits += index + ':' + value + ';';
  if (index === 10000) {
    // Keep the own-key count unchanged while moving an unread entry.
    delete live[90000]; live[50000] = 5;
    Object.defineProperty(proto, '30000', {value: 3, configurable: true});
  }
});
console.log('live', visits);
const holes = {length: 131072};
for (let i = 0; i < 256; i++) holes[i] = i;
for (let i = 64; i < 160; i++) delete holes[i];
let holeCount = 0, holeSum = 0;
Array.prototype.forEach.call(holes, value => {holeCount++; holeSum += value;});
console.log('hole-run', holeCount, holeSum, 64 in holes, 160 in holes);
