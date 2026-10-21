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
