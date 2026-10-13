// Shared source-to-runtime oracle: execute this file unchanged in Node and FrankenEngine.
var results = [];
function emit(name, value) { results.push(name + '=' + value); }
function show(set) { return Array.from(set).join(','); }
function unusedKeys() { throw new Error('keys must not be called'); }

{
  let set = new Set([1, 2, 3]);
  let seen = [];
  let result = set.intersection({ size: 10, keys: unusedKeys, has(value) {
    seen.push(value);
    if (value === 1) { set.delete(1); set.delete(2); set.add(4); }
    return true;
  } });
  emit('intersection-delete-append', show(result) + '|' + seen.join(','));
}
{
  let set = new Set([1, 2]);
  let seen = [];
  let result = set.intersection({ size: 10, keys: unusedKeys, has(value) {
    seen.push(value);
    if (value === 1) { set.clear(); set.add(3); }
    return true;
  } });
  emit('intersection-clear-append', show(result) + '|' + seen.join(','));
}
{
  let set = new Set([1, 2]);
  let seen = [];
  let result = set.intersection({ size: 10, keys: unusedKeys, has(value) {
    seen.push(value);
    if (seen.length === 1) { set.delete(1); set.add(1); }
    return true;
  } });
  emit('intersection-revisit-dedup', show(result) + '|' + seen.join(','));
}
{
  let set = new Set([1]);
  let seen = [];
  let result = set.isSubsetOf({ size: 10, keys: unusedKeys, has(value) {
    seen.push(value);
    if (value === 1) { set.add(2); }
    return value === 1;
  } });
  emit('subset-sees-appended-failure', result + '|' + seen.join(','));
}
{
  let set = new Set([1]);
  let seen = [];
  let result = set.isDisjointFrom({ size: 10, keys: unusedKeys, has(value) {
    seen.push(value);
    if (value === 1) { set.add(2); }
    return value === 2;
  } });
  emit('disjoint-sees-appended-match', result + '|' + seen.join(','));
}
{
  let set = new Set([1, 2]);
  let seen = [];
  let result = set.isSubsetOf({ size: 10, keys: unusedKeys, has(value) {
    seen.push(value); set.delete(2); return value === 1;
  } });
  emit('subset-skips-deleted', result + '|' + seen.join(','));
}
{
  let set = new Set([1, 2, 3]);
  let seen = [];
  let result = set.difference({ size: 10, keys: unusedKeys, has(value) {
    seen.push(value);
    if (value === 1) { set.clear(); set.add(9); }
    return value === 2;
  } });
  emit('difference-keeps-copy', show(result) + '|' + seen.join(',') + '|' + show(set));
}
for (let method of ['union', 'symmetricDifference']) {
  let set = new Set([1, 2]);
  let log = [];
  let result = set[method]({ size: 1, has() { return false; }, keys() {
    log.push('keys'); set.delete(1); set.add(3);
    let done = false;
    return { get next() {
      log.push('get-next'); set.add(4);
      return function () {
        log.push('next');
        if (done) { return { done: true }; }
        done = true; return { value: 2, done: false };
      };
    } };
  } });
  emit(method + '-copy-after-iterator', show(result) + '|' + log.join(','));
}
{
  let set = new Set([1, 2]);
  let result = set.difference({ size: 1, has() { return false; }, keys() {
    set.clear(); set.add(9); return [2].values();
  } });
  emit('difference-copy-before-iterator', show(result) + '|' + show(set));
}
{
  let set = new Set([1, 2, 3]);
  let log = [];
  let result = set.intersection({ size: 10, keys: unusedKeys, has(value) {
    log.push('outer' + value);
    if (value === 1) {
      set.isSubsetOf({ size: 10, keys: unusedKeys, has(inner) {
        log.push('inner' + inner);
        if (inner === 1) { set.delete(1); set.delete(2); set.add(4); }
        return true;
      } });
    }
    return true;
  } });
  emit('nested-cursors', show(result) + '|' + log.join(','));
}
{
  let set = new Set([1, 2, 3]);
  let sentinel = {};
  let caught = false;
  try {
    set.intersection({ size: 10, keys: unusedKeys, has(value) {
      set.delete(value); throw sentinel;
    } });
  } catch (error) { caught = error === sentinel; }
  let seen = [];
  let result = set.isSubsetOf({ size: 10, keys: unusedKeys, has(value) {
    seen.push(value); set.delete(value); return true;
  } });
  emit('throw-cleans-cursor', caught + '|' + result + '|' + seen.join(',') + '|' + set.size);
}
{
  let set = new Set([1, 2]);
  Object.defineProperty(set, 'size', { get() { throw new Error('own size'); } });
  set[Symbol.iterator] = unusedKeys;
  set.values = unusedKeys;
  let result = set.intersection({ size: 10, keys: unusedKeys, has() { return true; } });
  emit('internal-data-not-guest-iteration', show(result));
}
{
  let set = new Set([1]);
  let nextReads = 0;
  let calls = 0;
  let result = set.union({ size: 1, has() { return false; }, keys() {
    return { get next() {
      nextReads++;
      return function () {
        calls++;
        if (calls === 1) { set.add(9); return { value: 2, done: false }; }
        return { done: true };
      };
    } };
  } });
  emit('copy-before-first-next', show(result) + '|' + show(set) + '|' + nextReads + '|' + calls);
}
{
  let log = [];
  let result = new Set([1, 2]).isSupersetOf({ size: 1, has() { return false; }, keys() {
    return { next() { log.push('next'); return { value: 9, done: false }; },
      return() { log.push('return'); return {}; } };
  } });
  emit('early-false-closes', result + '|' + log.join(','));
}
results.join('\n');
