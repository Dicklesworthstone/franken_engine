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

function watch(trace, context, rows) {
  for (const event of ['start','end','error','asyncStart','asyncEnd'])
    trace[event].subscribe(value => rows.push([event, value === context, value.result, value.error]));
}
compare('inactive promise and callback traces preserve unwrapped results and arguments', async (dc, name) => {
  const t=dc.tracingChannel(name), value=Promise.resolve(42), context={}, cb=()=>9;
  const same=t.tracePromise(()=>value,context)===value;
  const raw=t.tracePromise(()=>7,null);
  const callbackSame=t.traceCallback(x=>x,99,context,null,cb)===cb;
  let caught=false;try{t.tracePromise(()=>{throw false;});}catch(e){caught=e===false;}
  return [same,raw,callbackSame,caught,Object.keys(context),await value];
});
compare('active promise tracing observes returned values and actual async completion order', async (dc,name)=>{
  const out=[];
  for(const value of [42,null,Promise.resolve('ready'),{then(resolve){resolve('thenable');}}]){
    const t=dc.tracingChannel(name+out.length),c={},rows=[];watch(t,c,rows);
    const p=t.tracePromise(function(a,b){rows.push(['call',this.base,a,b]);return value;},c,{base:40},1,2);
    rows.push(['returned']);const result=await p;
    out.push([result,rows,c.result]);
  }
  return out;
});
compare('promise rejections retain every falsy error and bracket async completion', async(dc,name)=>{
  const out=[];
  for(const reason of [undefined,null,false,0,'','failure']){
    const t=dc.tracingChannel(name+out.length),c={},rows=[];watch(t,c,rows);
    let same=false;try{await t.tracePromise(()=>Promise.reject(reason),c);}catch(e){same=e===reason;}
    out.push([same,rows,Object.hasOwn(c,'error'),c.error]);
  }
  return out;
});
compare('promise tracing synchronous throws stay synchronous with start error end', (dc,name)=>{
  const t=dc.tracingChannel(name),c={},rows=[];watch(t,c,rows);let caught=false;
  try{t.tracePromise(()=>{throw false;},c);}catch(e){caught=e===false;}
  return [caught,rows,c];
});
compare('promise tracing uses actual start and asyncStart store scopes', async(dc,name)=>{
  const t=dc.tracingChannel(name),store=new AsyncLocalStorage(),rows=[];
  t.start.bindStore(store,()=> 'start-scope');t.asyncStart.bindStore(store,()=> 'async-scope');
  for(const event of ['start','end','error','asyncStart','asyncEnd'])t[event].subscribe(()=>rows.push([event,store.getStore()]));
  return store.run('outer',async()=>{
    const result=await t.tracePromise(async()=>{rows.push(['call',store.getStore()]);await Promise.resolve();rows.push(['resume',store.getStore()]);return 42;});
    return [result,rows,store.getStore()];
  });
});
compare('result setter failures reject without fabricating a traced function error',async(dc,name)=>{
  const t=dc.tracingChannel(name),rows=[],reason='setter';
  for(const event of ['start','end','error','asyncStart','asyncEnd'])t[event].subscribe(()=>rows.push(event));
  const context={set result(value){rows.push('setter:'+value);throw reason;}};
  let caught;try{await t.tracePromise(()=>42,context);}catch(e){caught=e;}
  return [caught,rows];
});
compare('concurrent promise traces retain their own contexts through reversed settlement',async(dc,name)=>{
  const t=dc.tracingChannel(name),rows=[];let resolveA,resolveB;
  for(const event of ['start','end','asyncStart','asyncEnd'])t[event].subscribe(c=>rows.push(event+':'+c.id+':'+c.result));
  const a={id:'a'},b={id:'b'};
  const pa=t.tracePromise(()=>new Promise(resolve=>resolveA=resolve),a);
  const pb=t.tracePromise(()=>new Promise(resolve=>resolveB=resolve),b);
  resolveB(2);await pb;resolveA(1);await pa;return [a,b,rows];
});
compare('callback argument position is relative and coerced before starting a trace',(dc,name)=>{
  const rows=[];
  for(const position of [undefined,-1,0,1,-2,null,'0',0.5,NaN,Infinity,99]){
    const t=dc.tracingChannel(name+rows.length),c={},events=[];watch(t,c,events);
    let call=false;
    try{const returned=t.traceCallback(cb=>{call=true;cb(null,42);return 7;},position,c,null,()=>{});rows.push([returned,call,c,events]);}
    catch(e){rows.push([e.name,e.code,call,c,events]);}
  }
  return rows;
});
compare('callback tracing retains both receivers and all callback arguments',(dc,name)=>{
  const t=dc.tracingChannel(name),context={},rows=[];watch(t,context,rows);
  const receiver={},callbackReceiver={};let seen;
  const result=t.traceCallback(function(a,cb,b){rows.push(['call',this===receiver,a,b]);return cb.call(callbackReceiver,null,42,'extra');},1,context,receiver,1,
    function(...args){seen=[this===callbackReceiver,...args];return 99;},2);
  return [result,seen,context,rows];
});
compare('delayed callbacks produce asynchronous spans after synchronous end',async(dc,name)=>{
  const t=dc.tracingChannel(name),c={},rows=[];watch(t,c,rows);let callback;
  const result=t.traceCallback(cb=>{callback=cb;return 19;},-1,c,null,()=>rows.push(['callback']));
  rows.push(['returned']);await Promise.resolve();callback(null,42);return [result,rows,c];
});
compare('callback error slots follow error-first truthiness without discarding arguments',(dc,name)=>{
  const rows=[];
  for(const error of [undefined,null,false,0,'','failure']){
    const t=dc.tracingChannel(name+rows.length),c={},events=[];watch(t,c,events);let values;
    t.traceCallback(cb=>cb(error,7,8),0,c,null,(...args)=>values=args);
    rows.push([values,c,events]);
  }
  return rows;
});
compare('multiple callback deliveries are traced independently and do not clear context fields',(dc,name)=>{
  const t=dc.tracingChannel(name),c={},rows=[];watch(t,c,rows);let cb;
  t.traceCallback(callback=>{cb=callback;},0,c,null,(...values)=>rows.push(['callback',...values]));
  cb('failure',1);cb(null,2);return [c,rows];
});
compare('callback throws always close async spans, but only synchronous invocation traces error',(dc,name)=>{
  const rows=[];
  for(const immediate of [true,false]){
    const t=dc.tracingChannel(name+rows.length),c={},events=[];watch(t,c,events);let cb,caught;
    try{t.traceCallback(callback=>{cb=callback;if(immediate)callback(null,4);},0,c,null,()=>{throw false;});if(!immediate)cb(null,4);}
    catch(e){caught=e===false;}
    rows.push([caught,c,events]);
  }
  return rows;
});
compare('callback continuation enters the asyncStart store and restores the caller scope',(dc,name)=>{
  const t=dc.tracingChannel(name),store=new AsyncLocalStorage(),rows=[];let cb;
  t.start.bindStore(store,()=> 'start-scope');t.asyncStart.bindStore(store,c=>'callback:'+c.result);
  for(const event of ['start','end','error','asyncStart','asyncEnd'])t[event].subscribe(()=>rows.push([event,store.getStore()]));
  store.run('outer',()=>{
    t.traceCallback(callback=>{cb=callback;rows.push(['function',store.getStore()]);},0,{},null,()=>rows.push(['callback',store.getStore()]));
    rows.push(['between',store.getStore()]);cb(null,42);rows.push(['after',store.getStore()]);
  });
  return rows;
});
compare('promise traces publish ordered completion across many invocations',async(dc,name)=>{
  const t=dc.tracingChannel(name);let start=0,end=0,asyncStart=0,asyncEnd=0,sum=0;
  const listeners={start:()=>start++,end:()=>end++,asyncStart:c=>{asyncStart++;sum+=c.result;},asyncEnd:()=>asyncEnd++};
  t.subscribe(listeners);for(let i=0;i<1024;i++)assert.equal(await t.tracePromise(async()=>i),i);
  t.unsubscribe(listeners);return [start,end,asyncStart,asyncEnd,sum,t.hasSubscribers];
});
test('real uncaught delivery preserves failures; microtask versus nextTick order is an explicit difference',()=>{
  const {spawnSync}=require('node:child_process');
  function probe(candidate){
    const code=`const rows=[]; const dc=${candidate ? `require('node:vm').runInNewContext(require('node:fs').readFileSync(${JSON.stringify(source)},'utf8'),{queueMicrotask})` : "require('node:diagnostics_channel')"};
      const reason=Error('subscriber');process.once('uncaughtException',error=>{if(error!==reason)throw error;rows.push('uncaught');});
      queueMicrotask(()=>rows.push('queued'));const c=dc.channel('uncaught-case');c.subscribe(()=>{throw reason;});c.publish({});rows.push('sync');
      setImmediate(()=>console.log(rows.join(',')));`;
    const result=spawnSync(process.execPath,['-e',code],{encoding:'utf8',timeout:5000});
    assert.equal(result.status,0,result.stderr);assert.equal(result.stderr,'');return result.stdout;
  }
  assert.equal(probe(false),'sync,uncaught,queued\n');
  assert.equal(probe(true),'sync,queued,uncaught\n');
});
