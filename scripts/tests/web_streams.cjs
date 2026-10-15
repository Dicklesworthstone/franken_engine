'use strict';
// These tests execute the production JS factory on Node's language primitives.
// They do NOT prove that the Rust parser, lowerer, GC or VM executes it.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const reference = require('node:stream/web');
const source = fs.readFileSync(path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/web_stream_module.js'), 'utf8');
function candidate() { return vm.runInThisContext(source, { filename: 'web_stream_module.js' }); }
function deferred() { let resolve, reject; const promise = new Promise((a,b) => { resolve=a;reject=b; }); return { promise, resolve, reject }; }
async function collect(stream) { const values=[]; for await(const value of stream) values.push(value); return values; }
async function ticks(n=8) { while(n--) await Promise.resolve(); }
async function both(program) { const expected=await program(reference); const actual=await program(candidate()); assert.deepEqual(actual, expected); return actual; }

test('queued data, closed readers, aliases and actual controller identity', async () => {
  assert.deepEqual(await both(async api => {
    let control;
    const stream=new api.ReadableStream({start(c){control=c;c.enqueue('a');c.enqueue('b');c.close();}});
    const reader=new api.ReadableStreamDefaultReader(stream);
    const values=await Promise.all([reader.read(),reader.read(),reader.read()]);
    await reader.closed;
    const locked=stream.locked; reader.releaseLock();
    return [values,locked,stream.locked,control.desiredSize,control instanceof api.ReadableStreamDefaultController,
      api.ReadableStream.prototype[Symbol.asyncIterator]===api.ReadableStream.prototype.values];
  }), [[{value:'a',done:false},{value:'b',done:false},{value:undefined,done:true}],true,false,0,true,true]);
});
test('no pull until asynchronous start finishes; pull promises serialize', async () => {
  assert.deepEqual(await both(async api => {
    const start=deferred(), next=deferred(); let pulls=0,active=0,max=0,control;
    const stream=new api.ReadableStream({start(c){control=c;return start.promise;},
      async pull(c){pulls++;active++;max=Math.max(max,active);await next.promise;c.enqueue(pulls);active--;}} ,{highWaterMark:0});
    const reader=stream.getReader(); const a=reader.read(), b=reader.read();
    await ticks(); const early=pulls; start.resolve(); await ticks(); const pending=pulls;
    next.resolve(); const values=await Promise.all([a,b]); await reader.cancel(); reader.releaseLock();
    return [early,pending,max,values.map(v=>v.value)];
  }),[0,1,1,[1,2]]);
});
test('desiredSize and custom size callbacks are bypassed for pending reads', async () => {
  await both(async api => {
    let c; const sizes=[];
    const stream=new api.ReadableStream({start(x){c=x;}},{highWaterMark:3,size(x){sizes.push(x);return x.length;}});
    const before=c.desiredSize;c.enqueue('ab');const queued=c.desiredSize;
    const reader=stream.getReader();await reader.read();const p=reader.read();c.enqueue('long');await p;
    const after=c.desiredSize; c.close(); await reader.closed;reader.releaseLock();
    return [sizes,before,queued,after];
  });
});
test('source error rejects every pending read and closed with exact falsy identity', async () => {
  for (const reason of [undefined,null,false,0,'',Object.freeze({reason:42})]) {
    for (const api of [reference,candidate()]) {
      let c;const stream=new api.ReadableStream({start(x){c=x;}},{highWaterMark:0}); const r=stream.getReader();
      const requests=[r.read(),r.read(),r.closed].map(p=>p.then(()=>{throw Error('unexpected fulfillment');},e=>{assert.equal(e,reason);}));
      c.error(reason); await Promise.all(requests); assert.equal(c.desiredSize,null);
      await assert.rejects(r.read(),e=>e===reason);r.releaseLock();
    }
  }
});
test('cancel closes reads before its algorithm settles and invokes it once', async () => {
  await both(async api => {
    let calls=0,reason,control; const finish=deferred();
    const stream=new api.ReadableStream({start(c){control=c;},cancel(r){calls++;reason=r;return finish.promise;}},{highWaterMark:0});
    const reader=stream.getReader();const pending=reader.read();const cancellation=reader.cancel('stop');
    const read=await pending; await reader.closed; await reader.cancel('again');
    assert.throws(()=>control.enqueue('late'),TypeError);finish.resolve('ignored');const value=await cancellation;
    reader.releaseLock();return [calls,reason,read,value,stream.locked];
  });
});
test('reader release rejects pending reads without cancelling; new reader receives data', async () => {
  await both(async api => {
    let c,cancels=0;const s=new api.ReadableStream({start(x){c=x;},cancel(){cancels++;}},{highWaterMark:0});
    const a=s.getReader();const oldClosed=a.closed;const read=a.read();a.releaseLock();
    await assert.rejects(oldClosed,TypeError);await assert.rejects(read,TypeError);await assert.rejects(a.read(),TypeError);
    const b=s.getReader();c.enqueue(42);const value=await b.read();c.close();await b.closed;b.releaseLock();
    return [value,cancels,s.locked];
  });
});
test('iterator locks immediately, serializes demand, cancels on early return', async () => {
  await both(async api => {
    const reasons=[];let c;const s=new api.ReadableStream({start(x){c=x;x.enqueue(1);x.enqueue(2);},cancel(x){reasons.push(x);}});
    const iterator=s.values();const locked=s.locked;const values=await Promise.all([iterator.next(),iterator.next()]);
    const end=await iterator.return('finished');const later=await iterator.next();
    return [locked,values,end,later,reasons,s.locked];
  });
});
test('preventCancel and return before first read release iterator ownership', async () => {
  await both(async api => {
    let cancelled=0;const s=new api.ReadableStream({start(c){c.enqueue(7);c.close();},cancel(){cancelled++;}});
    const it=s.values({preventCancel:true});await it.return();const values=await collect(s);
    const unused=new api.ReadableStream({cancel(){cancelled++;}},{highWaterMark:0});await unused.values().return();
    return [values,cancelled,s.locked,unused.locked];
  });
});
test('ReadableStream.from supports sync/async iterators and promised values', async () => {
  await both(async api => {
    const iterator={n:0,next(){return {done:this.n===3,value:++this.n};},[Symbol.iterator](){return this;}};
    const s=api.ReadableStream.from(iterator);
    const a=await collect(s);const b=await collect(api.ReadableStream.from([Promise.resolve(4),5]));
    const c=await collect(api.ReadableStream.from((async function*(){yield 6;yield 7;})()));
    return [a,b,c];
  });
});
test('ReadableStream.from invokes return with cancellation reason and awaits rejection', async () => {
  await both(async api => {
    const reasons=[];const failure={failure:true};
    const iterable={[Symbol.asyncIterator](){return this;},next(){return Promise.resolve({value:1,done:false});},
      return(reason){reasons.push(reason);return Promise.reject(failure);}};
    const s=api.ReadableStream.from(iterable);const it=s.values();await it.next();
    await assert.rejects(it.return('stop'),error=>error===failure);return [reasons,s.locked];
  });
});
test('synchronous start errors escape; rejected start and pull error the stream', async () => {
  for (const api of [reference,candidate()]) {
    const error={original:true};assert.throws(()=>new api.ReadableStream({start(){throw error;}}),e=>e===error);
    for(const source of [{start(){return Promise.reject(error);}},{pull(){throw error;}}]) {
      const r=new api.ReadableStream(source).getReader();await assert.rejects(r.read(),e=>e===error);await assert.rejects(r.closed,e=>e===error);r.releaseLock();
    }
  }
});
test('invalid size errors discard queued values and preserve thrown identity', async () => {
  for(const api of [reference,candidate()]) {
    const error={sizing:true};let c;const s=new api.ReadableStream({start(x){c=x;}},{size(){throw error;}});
    assert.throws(()=>c.enqueue(1),e=>e===error);await assert.rejects(s.getReader().read(),e=>e===error);
    for(const size of [-1,NaN,Infinity]) {
      let c;const s=new api.ReadableStream({start(x){c=x;}},{size(){return size;}});
      assert.throws(()=>c.enqueue(1),RangeError);await assert.rejects(s.getReader().read(),RangeError);
    }
  }
});
test('queue strategies share stable size functions and do not coerce byteLength', async () => {
  await both(async api => {
    const c=new api.CountQueuingStrategy({highWaterMark:'3'}),b=new api.ByteLengthQueuingStrategy({highWaterMark:4});
    return [c.highWaterMark,b.highWaterMark,c.size(null),b.size({byteLength:'2'}),c.size===new api.CountQueuingStrategy({highWaterMark:1}).size];
  });
});
test('invalid receiver, locked stream and invalid options never get read access', async () => {
  for(const api of [reference,candidate()]) {
    assert.throws(()=>new api.ReadableStreamDefaultReader({}),TypeError);
    assert.throws(()=>new api.ReadableStreamDefaultController(),TypeError);
    const s=new api.ReadableStream({}, {highWaterMark:0});const r=s.getReader();
    assert.throws(()=>s.getReader(),TypeError);await assert.rejects(s.cancel(),TypeError);r.releaseLock();
    for(const h of [-1,NaN,Symbol('x'),1n])assert.throws(()=>new api.ReadableStream({}, {highWaterMark:h}));
    for(const source of [4,{pull:3},{cancel:3},{start:3}])assert.throws(()=>new api.ReadableStream(source));
  }
});
test('record Node 22 callback-coercion and mutable-sync-next differences, not parity', async () => {
  const api=candidate();
  for(const source of [{cancel:null},{start:false}]) {
    assert.doesNotThrow(()=>new reference.ReadableStream(source));
    assert.throws(()=>new api.ReadableStream(source),TypeError);
  }
  function mutable(api) {
    const iterator={n:0,next(){return {value:++this.n,done:this.n>1};},[Symbol.iterator](){return this;}};
    const stream=api.ReadableStream.from(iterator);
    iterator.next=()=>{throw Error('replacement');};
    return stream;
  }
  await assert.rejects(collect(mutable(reference)),/replacement/);
  assert.deepEqual(await collect(mutable(api)),[1]);
});
test('candidate refuses byte/BYOB contracts instead of pretending default semantics', () => {
  const api=candidate();assert.throws(()=>new api.ReadableStream({type:'bytes'}),RangeError);
  assert.throws(()=>new api.ReadableStream().getReader({mode:'byob'}),RangeError);
});
test('long pull/read workload retains only live queue entries', async () => {
  await both(async api => {
    let n=0;const s=new api.ReadableStream({pull(c){if(n===4096)c.close();else c.enqueue(n++);}});
    let count=0,sum=0;for await(const value of s){count++;sum+=value;}
    return [count,sum,s.locked];
  });
});
