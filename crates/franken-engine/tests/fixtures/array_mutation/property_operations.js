// The same program runs on the native orchestrator and the Node oracle.
// Snapshot descriptors, not values, so logging never invokes another getter.
function state(a) {
  let s = '';
  for (let i = 0; i < a.length; i++) {
    const d = Object.getOwnPropertyDescriptor(a, String(i));
    s += (i ? ',' : '') + (!d ? '-' : ('value' in d ? String(d.value) : 'accessor'));
  }
  return a.length + ':' + s;
}
function operation(a, name) {
  switch (name) {
    case 'push': return a.push(40);
    case 'pop': return a.pop();
    case 'shift': return a.shift();
    case 'unshift': return a.unshift(5);
    case 'reverse': return a.reverse();
    case 'fill': return a.fill(9);
  }
}
function run(label, method, prepare) {
  const a = [10, 20, 30];
  let log = '';
  function note(s) { log += (log ? ',' : '') + s; }
  prepare(a, note);
  let result = 'ok';
  try { operation(a, method); } catch (e) { result = e.name; }
  console.log(label + '/' + method + ' ' + result + ' ' + state(a) + ' ' + (log || '-'));
}
const methods = ['push', 'pop', 'shift', 'unshift', 'reverse', 'fill'];
for (const method of methods) {
  run('accessor', method, (a, note) => {
    Object.defineProperty(a, '1', {
      configurable: true, enumerable: true,
      get() { note('get1'); return 21; },
      set(v) { note('set1=' + v); }
    });
  });
  run('getter-only', method, (a, note) => {
    Object.defineProperty(a, '0', {
      configurable: true, get() { note('get0'); return 11; }
    });
  });
  run('readonly', method, a => {
    Object.defineProperty(a, '0', { writable: false });
  });
  run('locked-tail', method, a => {
    Object.defineProperty(a, '2', { configurable: false });
  });
  run('inherited', method, (a, note) => {
    delete a[1];
    const p = Object.create(Array.prototype);
    Object.defineProperty(p, '1', {
      configurable: true,
      get() { note('get-p1'); return 22; },
      set(v) { note('set-p1=' + v); }
    });
    Object.setPrototypeOf(a, p);
  });
}
run('tail-getter', 'pop', (a, note) => {
  Object.defineProperty(a, '2', { configurable: true, get() { note('get2'); return 33; } });
});
run('tail-readonly-deletable', 'pop', a => {
  Object.defineProperty(a, '2', { writable: false, configurable: true });
});
run('getter-throws', 'shift', (a, note) => {
  Object.defineProperty(a, '1', { get() { note('get1'); throw new RangeError('stop'); } });
});
run('setter-changes-next', 'fill', (a, note) => {
  Object.defineProperty(a, '0', { configurable: true, set(v) {
    note('set0=' + v);
    Object.defineProperty(a, '1', { writable: false });
  } });
});
run('setter-changes-next', 'reverse', (a, note) => {
  Object.defineProperty(a, '0', { configurable: true,
    get() { note('get0'); return 11; },
    set(v) { note('set0=' + v); Object.defineProperty(a, '2', { writable: false }); }
  });
});
for (const method of ['push', 'unshift']) {
  run('prototype-growth-setter', method, (a, note) => {
    const p = Object.create(Array.prototype);
    Object.defineProperty(p, '3', { set(v) { note('set-p3=' + v); } });
    Object.setPrototypeOf(a, p);
  });
  run('prototype-growth-readonly', method, a => {
    const p = Object.create(Array.prototype);
    Object.defineProperty(p, '3', { value: 99, writable: false });
    Object.setPrototypeOf(a, p);
  });
}
for (const method of methods) {
  run('sealed', method, a => Object.seal(a));
  run('nonextensible', method, a => Object.preventExtensions(a));
  run('frozen', method, a => Object.freeze(a));
}
// Empty writes and untouched accessors must not be rejected by preflight.
const empty = Object.freeze([]);
for (const method of ['fill', 'reverse', 'shift', 'pop']) {
  let result = 'ok';
  try { operation(empty, method); } catch (e) { result = e.name; }
  console.log('empty-frozen/' + method + ' ' + result);
}
const bounded = [1, 2, 3];
Object.defineProperty(bounded, '0', { get() { throw new Error('untouched'); } });
bounded.fill(7, 1, 2);
console.log('narrow-fill ' + state(bounded));
const maximum = [];
maximum.length = 4294967295;
let overflow = 'ok';
try { maximum.push(17); } catch (e) { overflow = e.name; }
console.log('overflow-push ' + overflow + ' ' + maximum.length + ' ' + maximum[4294967295]);
// A prototype trap can change later destinations during the same call.
let trapLog = '';
const proxiedPrototype = new Proxy(Object.create(Array.prototype), {
  set(target, key, value, receiver) {
    trapLog += key + '=' + value + ';';
    return Reflect.set(target, key, value, receiver);
  }
});
const growth = [1];
Object.setPrototypeOf(growth, proxiedPrototype);
growth.push(2, 3);
console.log('prototype-proxy ' + state(growth) + ' ' + trapLog);
// Same dispatch through borrowed methods, not just direct a.method calls.
const borrowed = [1, 2, 3];
let assigned = '';
Object.defineProperty(borrowed, '0', { set(v) { assigned += v; }, configurable: true });
Array.prototype.fill.call(borrowed, 4, 0, 1);
console.log('borrowed-fill ' + state(borrowed) + ' ' + assigned);
