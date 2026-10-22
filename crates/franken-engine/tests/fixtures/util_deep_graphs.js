function verifyUtilDeepGraphs(eq) {
  function check(value, message) { if (!value) throw new Error(message); }
  function chain(depth, leaf) {
    let value = leaf;
    for (let i = 0; i < depth; i++) value = { next: value };
    return value;
  }
  for (const depth of [0, 63, 64, 65, 96]) {
    check(eq(chain(depth, { value: 1 }), chain(depth, { value: 1 })), 'equal chain');
    check(!eq(chain(depth, { value: 1 }), chain(depth, { value: 2 })), 'unequal chain');
  }
  const self = {}; self.next = self;
  const ring = {}; let tail = ring;
  for (let i = 0; i < 72; i++) { tail.next = {}; tail = tail.next; }
  tail.next = ring;
  check(eq(self, ring) && eq(ring, self), 'one object can have several active partners');
  tail.extra = 1;
  check(!eq(self, ring) && !eq(ring, self), 'active partners do not imply equality');
  delete tail.extra;

  // A completed comparison must not suppress a later read of the same pair.
  let reads = 0;
  const left = { get value() { return ++reads; } };
  const right = { value: 1 };
  check(!eq(chain(72, { a: left, b: left }), chain(72, { a: right, b: right })),
    'completed pairs are not memoized');
  check(reads === 2, 'both sibling reads execute');

  const a = new Set([{ child: { value: 1 }, rank: 1 }, { child: { value: 1 }, rank: 2 }]);
  const b = new Set([{ child: { value: 1 }, rank: 2 }, { child: { value: 1 }, rank: 1 }]);
  const c = new Set([{ child: { value: 1 }, rank: 1 }, { child: { value: 1 }, rank: 1 }]);
  check(eq(chain(72, a), chain(72, b)), 'failed Set candidates roll back');
  check(!eq(chain(72, c), chain(72, b)), 'Set matching remains one-to-one');
  const ma = new Map([[{ id: 1 }, 'a'], [{ id: 1 }, 'b']]);
  const mb = new Map([[{ id: 1 }, 'b'], [{ id: 1 }, 'a']]);
  check(eq(chain(72, ma), chain(72, mb)), 'Map candidate values remain significant');

  const reason = { marker: 'exact thrown value' };
  const throwing = { get value() { throw reason; } };
  let caught = false;
  try { eq(chain(72, throwing), chain(72, { value: 1 })); }
  catch (error) { caught = true; check(error === reason, 'exception identity'); }
  check(caught && eq(chain(72, { value: 1 }), chain(72, { value: 1 })), 'retry after throw');
  let reentered = 0;
  const nested = { get value() {
    reentered++;
    check(eq(chain(72, { value: 2 }), chain(72, { value: 2 })), 'independent reentrant state');
    return 1;
  } };
  check(eq(chain(72, nested), chain(72, { value: 1 })) && reentered === 1, 'outer state survives reentry');
  return 'util deep graphs: chains, cycles, partners, rollback, getters, exceptions, reentry';
}

function verifyUtilPropertyWalk(eq, depth) {
  function check(value, message) { if (!value) throw new Error(message); }
  function nest(leaf) {
    let value = leaf;
    for (let i = 0; i < depth; i++) {
      value = i % 2 === 0 ? { next: value, rank: i } : [value, i];
    }
    return value;
  }
  check(eq(nest({ value: 1 }), nest({ value: 1 })), 'deep properties compare');
  check(!eq(nest({ value: 1 }), nest({ value: 2 })), 'deep property mismatch');
  const first = {}, second = {};
  first.self = first; second.self = second;
  check(eq(nest(first), nest(second)), 'deep property cycle');
  const reads = [];
  const left = { get first() { reads.push('left-first'); return { get value() {
    reads.push('left-child'); right.last = 2; return 1;
  } }; }, last: 2 };
  const right = { get first() { reads.push('right-first'); return { get value() {
    reads.push('right-child'); return 1;
  } }; }, last: 0 };
  check(eq(nest(left), nest(right)), 'later sibling read stays lazy');
  check(reads.join('|') === 'left-first|right-first|left-child|right-child', 'depth-first reads');
  const reason = { marker: 'deep property exception' };
  let caught = false;
  try { eq(nest({ get value() { throw reason; } }), nest({ value: 1 })); }
  catch (error) { caught = true; check(error === reason, 'deep exception identity'); }
  check(caught && eq(nest({ value: 1 }), nest({ value: 1 })), 'deep retry');
  return 'util property walk: depth, mixed arrays, cycles, getter order, failure cleanup';
}

function verifyUtilPayloadWalk(eq, depth) {
  function check(value, message) { if (!value) throw new Error(message); }
  function nest(leaf, kind) {
    let value = leaf;
    for (let i = 0; i < depth; i++) {
      if (kind === 0) value = new Map([['next', value]]);
      else if (kind === 1) value = new Map([[value, i]]);
      else if (kind === 2) value = new Set([value]);
      else {
        const error = new Error('payload');
        Object.defineProperty(error, kind === 3 ? 'cause' : 'errors', {
          value: kind === 3 ? value : [value], configurable: true
        });
        value = error;
      }
    }
    return value;
  }
  for (let kind = 0; kind < 5; kind++) {
    check(eq(nest({ value: 1 }, kind), nest({ value: 1 }, kind)), 'equal special payload');
    check(!eq(nest({ value: 1 }, kind), nest({ value: 2 }, kind)), 'unequal special payload');
  }
  const selfA = new Set(), selfB = new Set();
  selfA.add(selfA); selfB.add(selfB);
  check(eq(nest(selfA, 0), nest(selfB, 0)), 'nested collection cycles');
  const first = { key: 1 }, second = { key: 1 };
  check(eq(nest(new Map([[first, 1], [second, 2]]), 2),
    nest(new Map([[{ key: 1 }, 2], [{ key: 1 }, 1]]), 2)), 'failed values retry equivalent keys');
  check(!eq(nest(new Map([[{ key: 1 }, 1], [{ key: 1 }, 1]]), 2),
    nest(new Map([[{ key: 1 }, 1], [{ key: 1 }, 2]]), 2)), 'equal keys do not hide unequal Map values');
  check(!eq(nest(new Set([{ key: 1 }, { key: 1 }]), 2),
    nest(new Set([{ key: 1 }, { key: 2 }]), 2)), 'one-to-one candidate matching');
  const reason = { marker: 'payload throw' };
  let caught = false;
  try { eq(nest({ get value() { throw reason; } }, 0), nest({ value: 1 }, 0)); }
  catch (error) { caught = true; check(error === reason, 'exact thrown payload'); }
  check(caught && eq(nest({ value: 1 }, 0), nest({ value: 1 }, 0)), 'retry after payload throw');
  const right = new Error('payload');
  const left = new Error('payload');
  Object.defineProperty(left, 'cause', { get() { return { get value() { right.extra = 2; return 1; } }; } });
  Object.defineProperty(right, 'cause', { value: { value: 1 } });
  left.extra = 2; right.extra = 0;
  check(eq(nest(left, 2), nest(right, 2)), 'payload getter precedes ordinary properties');
  return 'util payload walk: collections, errors, retries, mutation, cycles';
}
