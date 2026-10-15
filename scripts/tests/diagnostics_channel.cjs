'use strict';
// Exact shipped factory on host primitives, NOT Franken native execution.
const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const reference = require('node:diagnostics_channel');
const {AsyncLocalStorage} = require('node:async_hooks');
const source = process.env.DIAGNOSTICS_SOURCE || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/diagnostics_channel_module.js');
function candidate(extras = {}) {
  return vm.runInNewContext(fs.readFileSync(source, 'utf8'),
    {queueMicrotask, ...extras}, {filename: source});
}
let id = 0;
function compare(name, body) {
  test(name, async () => {
    const expected = await body(reference, 'reference:' + id++);
    const actual = await body(candidate(), 'candidate:' + id++);
    assert.deepEqual(actual, expected);
  });
}
compare('named string and symbol channels retain identity and distinct names', (dc, name) => {
  const one = dc.channel(name), symbol = Symbol(name);
  return [one === dc.channel(name), one !== dc.channel(name + 'other'),
    dc.channel(symbol) === dc.channel(symbol), dc.channel(Symbol(name)) !== dc.channel(symbol),
    one instanceof dc.Channel, one.hasSubscribers, dc.hasSubscribers(name), dc.hasSubscribers({})];
});
compare('synchronous publication preserves message/name identity and receiver', (dc, name) => {
  const c = dc.channel(name), message = {value: 1}, rows = [];
  function subscriber(m, n) { rows.push([m === message, n === name, this === undefined]); m.value++; }
  dc.subscribe(name, subscriber); c.subscribe(subscriber);
  const returns = [c.publish(message), c.unsubscribe(subscriber), c.hasSubscribers,
    dc.unsubscribe(name, subscriber), c.hasSubscribers, c.unsubscribe(subscriber)];
  return [rows, message.value, returns];
});
compare('publish snapshots subscriptions; nested publication sees mutations', (dc, name) => {
  const c = dc.channel(name), rows = []; let inside = false;
  const second = value => rows.push('second:' + value);
  const third = value => rows.push('third:' + value);
  const first = value => {
    rows.push('first:' + value);
    if (!inside) { inside = true; c.unsubscribe(second); c.subscribe(third); c.publish(2); }
  };
  c.subscribe(first); c.subscribe(second); c.publish(1); c.publish(3);
  return rows;
});
compare('invalid names and subscriptions retain error classes and codes', dc => {
  const rows = [];
  for (const name of [null, undefined, 1, {}, true]) {
    try { dc.channel(name); rows.push('unexpected'); } catch (e) { rows.push([e.name, e.code]); }
  }
  const c = dc.channel(Symbol());
  for (const fn of [null, undefined, 1, {}]) {
    try { c.subscribe(fn); rows.push('unexpected'); } catch (e) { rows.push([e.name, e.code]); }
    rows.push(c.unsubscribe(fn));
  }
  return rows;
});
compare('direct constructors replace the named registry entry without mutating held channels', (dc, name) => {
  const first = dc.channel(name), other = new dc.Channel(name);
  const rows = [];
  first.subscribe(value => rows.push('first:' + value));
  other.subscribe(value => rows.push('other:' + value));
  dc.channel(name).publish(1); first.publish(2);
  return [first !== other, other === dc.channel(name), rows];
});
compare('runStores binds in reverse order and publishes inside all stores', (dc, name) => {
  const c = dc.channel(name), a = new AsyncLocalStorage(), b = new AsyncLocalStorage(), rows = [];
  c.bindStore(a, x => { rows.push(['a', b.getStore()]); return x + ':a'; });
  c.bindStore(b, x => { rows.push(['b', a.getStore()]); return x + ':b'; });
  c.subscribe(x => rows.push(['publish', x, a.getStore(), b.getStore()]));
  const receiver = {};
  const result = c.runStores('x', function (arg) { rows.push(['call', this === receiver, arg, a.getStore(), b.getStore()]); return 42; }, receiver, 7);
  return [result, rows, a.getStore(), b.getStore()];
});
compare('store-only channels are active; rebinding and unbinding retain order and return values', (dc, name) => {
  const c = dc.channel(name), a = new AsyncLocalStorage(), b = new AsyncLocalStorage();
  const rows = [c.hasSubscribers];
  c.bindStore(a, x => x + 1); rows.push(c.hasSubscribers, dc.hasSubscribers(name));
  c.bindStore(b); c.bindStore(a, x => x + 2);
  rows.push(c.runStores(40, () => [a.getStore(), b.getStore()]));
  rows.push(c.unbindStore(a), c.hasSubscribers, c.unbindStore(a), c.unbindStore(b), c.hasSubscribers);
  return rows;
});
compare('async work inherits real bound stores and outer contexts are restored', async (dc, name) => {
  const c = dc.channel(name), store = new AsyncLocalStorage(); c.bindStore(store);
  return store.run('outer', async () => {
    const pending = c.runStores('inner', async () => { await Promise.resolve(); return store.getStore(); });
    const outside = store.getStore();
    return [await pending, outside, store.getStore()];
  });
});
compare('inactive traceSync is transparent including primitive context and thrown identity', (dc, name) => {
  const t = dc.tracingChannel(name), c = {}, marker = {}, receiver = {};
  const result = t.traceSync(function (x) { return [this === receiver, x]; }, c, receiver, marker);
  let thrown; try { t.traceSync(() => { throw marker; }, null); } catch (e) { thrown = e === marker; }
  return [result[0], result[1] === marker, Object.keys(c), thrown, t.traceSync(() => 1, 0)];
});
compare('traceSync emits success/failure in order with the original context and return', (dc, name) => {
  const t = dc.tracingChannel(name), c = {}, rows = [], error = {};
  for (const event of ['start','end','error']) t[event].subscribe(m => rows.push([event, m === c, m.result, m.error === error]));
  const value = t.traceSync(() => 42, c); let same = false;
  try { t.traceSync(() => { throw error; }, c); } catch (e) { same = e === error; }
  return [rows, value, same];
});
compare('tracing names and explicit channel collections use the same channels', (dc, name) => {
  const a = dc.tracingChannel(name), b = dc.tracingChannel(name), c = dc.tracingChannel(a);
  const fn = () => {}, listeners = {start:fn, end:fn}; a.subscribe(listeners);
  return [a !== b, a.start === b.start, c.start === a.start,
    a.start === dc.channel('tracing:' + name + ':start'), b.hasSubscribers,
    b.unsubscribe(listeners), a.hasSubscribers, a.unsubscribe(listeners)];
});
compare('store transforms may mutate bindings without changing the current wrapper chain', (dc, name) => {
  const c=dc.channel(name), a=new AsyncLocalStorage(), b=new AsyncLocalStorage();
  c.bindStore(a, () => 'a'); c.bindStore(b, () => { c.unbindStore(a); return 'b'; });
  const first=c.runStores(null,()=>[a.getStore(),b.getStore()]);
  return [first,c.runStores(null,()=>[a.getStore(),b.getStore()])];
});
test('subscriber and transformer failures enter uncaught job handling without stopping the caller', async () => {
  const jobs=[], dc=candidate({queueMicrotask:fn=>jobs.push(fn)}), c=dc.channel('failure');
  const original={}, rows=[]; c.subscribe(()=>{throw original}); c.subscribe(()=>rows.push('second'));
  assert.equal(c.publish(1),undefined);assert.deepEqual(rows,['second']);assert.equal(jobs.length,1);
  assert.throws(jobs.shift(),e=>e===original);
  c.bindStore({run(value, fn){rows.push(value);return fn();}},()=>{throw false});
  assert.equal(c.runStores(7,()=>42),42);assert.equal(jobs.length,2);
  assert.throws(jobs[0],e=>e===false);assert.throws(jobs[1],e=>e===original);
});
test('replaced Map methods cannot hijack registry or bound-store bookkeeping', () => {
  const realm = vm.createContext({queueMicrotask});
  const dc = vm.runInContext(fs.readFileSync(source, 'utf8'), realm);
  vm.runInContext(`
    for (const name of ['get','has','set','delete','forEach'])
      Map.prototype[name] = function () { throw Error('replaced Map method'); };
    WeakMap.prototype.get = WeakMap.prototype.set = function () { throw Error('replaced WeakMap method'); };
  `, realm);
  const c=dc.channel('protected'), store={run(value,fn){return fn()}};
  assert.equal(c,dc.channel('protected'));
  c.bindStore(store); c.bindStore(store); assert.equal(c.hasSubscribers,true);
  assert.equal(c.runStores('context',()=>42),42);
  assert.equal(c.unbindStore(store),true); assert.equal(c.hasSubscribers,false);
});
compare('large repeated publication does not lose subscribers or messages', (dc, name) => {
  const c=dc.channel(name), message={value:0};let sum=0,count=0;
  function add(x){sum+=x.value;count++;}
  for(let i=0;i<32;i++)c.subscribe(add);
  for(let i=0;i<4096;i++){message.value=i;c.publish(message);}
  for(let i=0;i<32;i++)assert.equal(c.unsubscribe(add),true);
  return [sum,count,c.hasSubscribers,c.unsubscribe(add)];
});
