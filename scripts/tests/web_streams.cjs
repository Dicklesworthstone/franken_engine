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

test('writable queues callbacks in order and includes in-flight size in backpressure', async () => {
  assert.deepEqual(await both(async api => {
    const start=deferred(), first=deferred(), events=[]; let active=0,max=0,controller;
    const s=new api.WritableStream({start(c){controller=c;return start.promise;},
      async write(value){events.push('write:'+value);active++;max=Math.max(max,active);if(value==='ab')await first.promise;active--;},
      close(){events.push('close');}},{highWaterMark:3,size(x){return x.length;}});
    const w=s.getWriter(); const before=w.ready;await before;
    const a=w.write('ab'),b=w.write('cd');const pressure=w.ready;
    const sizes=[w.desiredSize];await ticks();assert.deepEqual(events,[]);
    start.resolve();await ticks();sizes.push(w.desiredSize);assert.deepEqual(events,['write:ab']);
    first.resolve();await Promise.all([a,b,pressure]);sizes.push(w.desiredSize);
    await w.close();await w.closed; sizes.push(w.desiredSize);const signal=controller.signal.aborted;
    w.releaseLock();return [events,sizes,max,before===pressure,signal,s.locked];
  }),[['write:ab','write:cd','close'],[-1,-1,3,0],1,false,false,false]);
});
test('close waits for queued writes and releases ready even at zero high water mark', async () => {
  await both(async api => {
    const gate=deferred(),events=[];const s=new api.WritableStream({write(x){events.push(x);return gate.promise;},close(){events.push('closed');}},{highWaterMark:0});
    const w=s.getWriter();const a=w.write(1),b=w.write(2),closing=w.close();await w.ready;
    await ticks();assert.deepEqual(events,[1]);gate.resolve();await Promise.all([a,b,closing,w.closed]);
    await assert.rejects(w.write(3),TypeError);await assert.rejects(w.close(),TypeError);
    w.releaseLock();return [events,s.locked];
  });
});
test('writable rejection preserves original falsy errors across queued work', async () => {
  for(const reason of [undefined,null,false,0,'',Object.freeze({failure:true})]) {
    for(const api of [reference,candidate()]) {
      const seen=[];const s=new api.WritableStream({write(value){seen.push(value);throw reason;}});const w=s.getWriter();
      const promises=[w.write(1),w.write(2),w.close(),w.closed];
      await Promise.all(promises.map(p=>p.then(()=>{throw Error('unexpected fulfillment');},error=>assert.equal(error,reason))));
      await assert.rejects(w.ready,error=>error===reason);
      assert.deepEqual(seen,[1]);assert.equal(w.desiredSize,null);w.releaseLock();
    }
  }
});
test('writer release does not cancel previously accepted writes or close', async () => {
  await both(async api => {
    const gate=deferred(),events=[];const s=new api.WritableStream({write(x){events.push(x);return gate.promise;},close(){events.push('close');}});
    const a=s.getWriter();const write=a.write(1);const closed=a.closed;a.releaseLock();await assert.rejects(closed,TypeError);
    await assert.rejects(a.write(2),TypeError);assert.throws(()=>a.desiredSize,TypeError);
    const b=s.getWriter();const closing=b.close();gate.resolve();await Promise.all([write,closing,b.closed]);b.releaseLock();
    return [events,s.locked];
  });
});
test('abort signals immediately, waits for active write, and rejects unstarted writes', async () => {
  await both(async api => {
    const gate=deferred(),abortGate=deferred(),events=[];let c;
    const s=new api.WritableStream({start(x){c=x;},write(x){events.push(x);return gate.promise;},abort(reason){events.push(reason);return abortGate.promise;}});
    const w=s.getWriter();const a=w.write(1),b=w.write(2);const later=b.catch(x=>x);await ticks();
    const abort=w.abort('stop');const same=abort===w.abort('ignored');const observed=[c.signal.aborted,c.signal.reason];
    await ticks();assert.deepEqual(events,[1]);gate.resolve();await a;const failure=await later;
    await ticks();assert.deepEqual(events,[1,'stop']);abortGate.resolve();await abort;await assert.rejects(w.closed,e=>e==='stop');w.releaseLock();
    return [events,same,observed,failure,s.locked];
  });
});
test('successful in-flight close wins racing abort and never calls abort algorithm', async () => {
  await both(async api => {
    const gate=deferred(),events=[];const s=new api.WritableStream({close(){events.push('close');return gate.promise;},abort(){events.push('abort');}});
    const w=s.getWriter();const closing=w.close();await ticks();const abort=w.abort('late');gate.resolve();
    await Promise.all([closing,abort,w.closed]);const desired=w.desiredSize;w.releaseLock();return [events,desired,s.locked];
  });
});
test('failing in-flight close rejects both close and concurrent abort', async () => {
  for(const api of [reference,candidate()]) {
    const failure={close:true},gate=deferred();const s=new api.WritableStream({close(){return gate.promise;}});
    const w=s.getWriter();const closing=w.close();await ticks();const abort=w.abort('abort');
    const checks=[assert.rejects(closing,e=>e===failure),assert.rejects(abort,e=>e===failure),assert.rejects(w.closed,e=>e==='abort')];
    gate.reject(failure);await Promise.all(checks);w.releaseLock();
  }
});
test('erroring plus abort keeps the first error and does not invoke the sink abort', async () => {
  await both(async api => {
    let c,aborts=0;const gate=deferred(),s=new api.WritableStream({start(x){c=x;},write(){return gate.promise;},abort(){aborts++;}});
    const w=s.getWriter(),first=w.write(1),second=w.write(2);const rejectedSecond=second.catch(x=>x);await ticks();
    c.error('first');const abort=w.abort('second');const rejectedAbort=abort.catch(x=>x);gate.resolve();await first;
    const values=await Promise.all([rejectedSecond,rejectedAbort,w.closed.catch(x=>x)]);w.releaseLock();return [aborts,values,c.signal.reason];
  });
});
test('abort during unresolved start waits and preserves first failure', async () => {
  await both(async api => {
    const gate=deferred(),seen=[];const s=new api.WritableStream({start(){return gate.promise;},write(){seen.push('write');},abort(x){seen.push(x);}});
    const w=s.getWriter();const p=w.write(1).catch(x=>x);const abort=w.abort('cancel');await ticks();assert.deepEqual(seen,[]);
    gate.reject('start failed');const value=await p;await abort;await assert.rejects(w.closed,x=>x==='cancel');w.releaseLock();return [seen,value];
  });
});
test('a rejecting abort algorithm changes abort result but not the stream stored error', async () => {
  await both(async api => {
    const s=new api.WritableStream({abort(){throw 'cleanup';}});const w=s.getWriter();
    const value=await w.abort('cancel').catch(x=>x);const closed=await w.closed.catch(x=>x);await w.abort('again');w.releaseLock();return [value,closed];
  });
});
test('writable size callbacks cannot publish after reentrant lock release or close', async () => {
  await both(async api => {
    let writer,calls=0;const s=new api.WritableStream({write(){calls++;}},{size(){writer.releaseLock();return 1;}});
    writer=s.getWriter();await assert.rejects(writer.write('x'),TypeError);const next=s.getWriter();await next.close();next.releaseLock();
    let closing,w;const second=new api.WritableStream({write(){calls++;}},{size(){closing=w.close();return 1;}});w=second.getWriter();
    await assert.rejects(w.write('x'),TypeError);await closing;w.releaseLock();return [calls,s.locked,second.locked];
  });
});
test('writable start, strategy and lock failures do not fabricate success', async () => {
  for(const api of [reference,candidate()]) {
    const failure={start:true};assert.throws(()=>new api.WritableStream({start(){throw failure;}}),e=>e===failure);
    const w=new api.WritableStream({start(){return Promise.reject(failure);}}).getWriter();
    await assert.rejects(w.write(1),e=>e===failure);await assert.rejects(w.closed,e=>e===failure);w.releaseLock();
    assert.throws(()=>new api.WritableStreamDefaultWriter({}),TypeError);assert.throws(()=>new api.WritableStreamDefaultController(),TypeError);
    const s=new api.WritableStream(),writer=s.getWriter();assert.throws(()=>s.getWriter(),TypeError);await assert.rejects(s.close(),TypeError);await assert.rejects(s.abort(),TypeError);writer.releaseLock();await s.close();
  }
});
test('thousands of queued writes finish without overlapping sink callbacks', async () => {
  assert.deepEqual(await both(async api => {
    let count=0,sum=0;const s=new api.WritableStream({async write(n){await Promise.resolve();count++;sum+=n;}});
    const w=s.getWriter(),pending=[];for(let n=0;n<2048;n++)pending.push(w.write(n));const close=w.close();
    await Promise.all(pending);await close;w.releaseLock();return [count,sum,s.locked];
  }),[2048,2096128,false]);
});

test('pipeTo drains every queued chunk, awaits sink close, and releases both locks', async () => {
  await both(async api => {
    const values=[],close=deferred();const r=new api.ReadableStream({start(c){c.enqueue(1);c.enqueue(2);c.close();}});
    const w=new api.WritableStream({write(value){values.push(value);},close(){values.push('close');return close.promise;}});
    let done=false;const p=r.pipeTo(w).then(()=>{done=true;});assert.equal(r.locked,true);assert.equal(w.locked,true);
    await ticks(30);assert.deepEqual(values,[1,2,'close']);assert.equal(done,false);close.resolve();await p;
    return [values,done,r.locked,w.locked];
  });
});
test('pipe fills the admitted writable queue without overlapping writes or whole-stream collection', async () => {
  assert.deepEqual(await both(async api => {
    const gate=deferred();let reads=0,active=0,max=0;const values=[];
    const r=new api.ReadableStream({pull(c){if(reads===6)c.close();else c.enqueue(++reads);}},{highWaterMark:0});
    const w=new api.WritableStream({async write(value){active++;max=Math.max(max,active);if(value===1)await gate.promise;values.push(value);active--;}},{highWaterMark:3});
    const p=r.pipeTo(w);await ticks(40);const early=reads;assert.equal(values.length,0);gate.resolve();await p;
    return [early,values,max,r.locked,w.locked];
  }),[3,[1,2,3,4,5,6],1,false,false]);
});
test('pipe source failure aborts destination with the original error', async () => {
  await both(async api => {
    const reason={source:true},events=[];let c;const r=new api.ReadableStream({start(x){c=x;}},{highWaterMark:0});
    const w=new api.WritableStream({abort(e){events.push(e===reason);}});const p=r.pipeTo(w);
    c.error(reason);await assert.rejects(p,e=>e===reason);return [events,r.locked,w.locked];
  });
});
test('pipe destination failure cancels a stalled source without waiting for its next chunk', async () => {
  await both(async api => {
    const reason={sink:true},events=[];let c;
    const r=new api.ReadableStream({pull(){return new Promise(()=>{});},cancel(e){events.push(e===reason);}},{highWaterMark:0});
    const w=new api.WritableStream({start(x){c=x;}});const p=r.pipeTo(w);await ticks();c.error(reason);
    await assert.rejects(p,e=>e===reason);return [events,r.locked,w.locked];
  });
});
test('pipe preventClose permits an unlocked destination to receive later writes', async () => {
  await both(async api => {
    const out=[];let closed=0;const r=api.ReadableStream.from([1,2]);const w=new api.WritableStream({write(x){out.push(x);},close(){closed++;}});
    await r.pipeTo(w,{preventClose:true});const a=w.getWriter();await a.write(3);await a.close();a.releaseLock();return [out,closed,r.locked,w.locked];
  });
});
test('pipe preventAbort and preventCancel preserve the opposite endpoint', async () => {
  await both(async api => {
    let source;const r=new api.ReadableStream({start(c){source=c;}}),out=[];const w=new api.WritableStream({write(x){out.push(x);},abort(){out.push('abort');}});
    const p=r.pipeTo(w,{preventAbort:true});source.error('bad source');await assert.rejects(p,e=>e==='bad source');
    const writer=w.getWriter();await writer.write(1);await writer.close();writer.releaseLock();
    let cancelled=0,control;const r2=new api.ReadableStream({start(c){control=c;},cancel(){cancelled++;}},{highWaterMark:0});
    const w2=new api.WritableStream({write(){throw 'bad sink';}});const p2=r2.pipeTo(w2,{preventCancel:true});control.enqueue(2);
    await assert.rejects(p2,e=>e==='bad sink');control.enqueue(3);control.close();const values=await collect(r2);return [out,cancelled,values,r2.locked,w2.locked];
  });
});
test('already-aborted and mid-read signals stop both pipe endpoints and preserve causes', async () => {
  for(const pre of [true,false])await both(async api => {
    const signal=new AbortController(),reason={abort:true},seen=[];let pulls=0;
    const r=new api.ReadableStream({pull(){pulls++;return new Promise(()=>{});},cancel(e){seen.push(['cancel',e===reason]);}},{highWaterMark:0});
    const w=new api.WritableStream({abort(e){seen.push(['abort',e===reason]);}});if(pre)signal.abort(reason);
    const p=r.pipeTo(w,{signal:signal.signal});if(!pre){await ticks();signal.abort(reason);}
    await assert.rejects(p,e=>e===reason);return [seen,pulls,r.locked,w.locked];
  });
});
test('pipe cancellation survives public stopImmediatePropagation', async () => {
  for(const api of [reference,candidate()]) {
    const a=new AbortController();a.signal.addEventListener('abort',e=>e.stopImmediatePropagation());
    let cancelled=0;const r=new api.ReadableStream({cancel(){cancelled++;}},{highWaterMark:0});const w=new api.WritableStream();
    const p=r.pipeTo(w,{signal:a.signal});await ticks();assert.equal(cancelled,0);
    a.abort('real');await assert.rejects(p,e=>e==='real');assert.equal(cancelled,1);assert.equal(r.locked,false);assert.equal(w.locked,false);
  }
});
test('record Node 22 synthetic-event cancellation difference, not parity', async () => {
  for(const api of [reference,candidate()]) {
    const a=new AbortController();let cancelled=0;
    const r=new api.ReadableStream({cancel(){cancelled++;}},{highWaterMark:0}),w=new api.WritableStream();
    const p=r.pipeTo(w,{signal:a.signal}).then(()=>({fulfilled:true}),error=>({error}));
    a.signal.dispatchEvent(new Event('abort'));await ticks(20);
    if(api===reference) { assert.equal(cancelled,1);assert.deepEqual(await p,{error:undefined}); }
    else { assert.equal(cancelled,0);a.abort('real');assert.deepEqual(await p,{error:'real'});assert.equal(cancelled,1); }
    assert.equal(r.locked,false);assert.equal(w.locked,false);
  }
});
test('pipe abort prevent flags suppress only their corresponding cleanup', async () => {
  for(const preventAbort of [false,true])for(const preventCancel of [false,true])await both(async api => {
    const a=new AbortController(),events=[];const r=new api.ReadableStream({cancel(){events.push('cancel');}},{highWaterMark:0});const w=new api.WritableStream({abort(){events.push('abort');}});
    const p=r.pipeTo(w,{signal:a.signal,preventAbort,preventCancel});a.abort('stop');await assert.rejects(p,e=>e==='stop');return [events,r.locked,w.locked];
  });
});
test('pipe cleanup failure replaces the original pipe error and still releases locks', async () => {
  await both(async api => {
    const r=new api.ReadableStream({start(c){c.error('original');}});const w=new api.WritableStream({abort(){throw 'cleanup';}});
    const failure=await r.pipeTo(w).catch(e=>e);return [failure,r.locked,w.locked];
  });
});
test('pipe does not call replaceable public reader and writer operations', async () => {
  for(const api of [reference,candidate()]) {
    const out=[];const r=api.ReadableStream.from([1,2]);const w=new api.WritableStream({write(x){out.push(x);}});
    const oldRead=api.ReadableStreamDefaultReader.prototype.read,oldWrite=api.WritableStreamDefaultWriter.prototype.write;
    try {
      api.ReadableStreamDefaultReader.prototype.read=()=>{throw Error('public read');};
      api.WritableStreamDefaultWriter.prototype.write=()=>{throw Error('public write');};
      r.getReader=()=>{throw Error('public getReader');};w.getWriter=()=>{throw Error('public getWriter');};
      await r.pipeTo(w);assert.deepEqual(out,[1,2]);
    }finally{api.ReadableStreamDefaultReader.prototype.read=oldRead;api.WritableStreamDefaultWriter.prototype.write=oldWrite;}
  }
});
test('pipe invalid endpoints and options reject without stealing a lock', async () => {
  for(const api of [reference,candidate()]) {
    const r=new api.ReadableStream({}, {highWaterMark:0}),w=new api.WritableStream();
    await assert.rejects(r.pipeTo({}),TypeError);await assert.rejects(r.pipeTo(w,{signal:{}}),TypeError);
    const lock=w.getWriter();await assert.rejects(r.pipeTo(w),TypeError);assert.equal(r.locked,false);lock.releaseLock();
    assert.throws(()=>r.pipeThrough({readable:{},writable:w}),TypeError);assert.equal(w.locked,false);
    await w.close();await assert.rejects(r.pipeTo(w),TypeError);assert.equal(r.locked,false);
  }
});
test('empty closed source finishes even with a zero-capacity writable', async () => {
  await both(async api => {
    let closed=0;const r=new api.ReadableStream({start(c){c.close();}}),w=new api.WritableStream({close(){closed++;}},{highWaterMark:0});
    await r.pipeTo(w);return [closed,r.locked,w.locked];
  });
});
test('transform pipelines serialize callbacks, preserve order and await asynchronous flush', async () => {
  assert.deepEqual(await both(async api => {
    let active=0,max=0;const out=[];const t=new api.TransformStream({async transform(x,c){active++;max=Math.max(max,active);await Promise.resolve();c.enqueue(x*2);active--;},async flush(c){await Promise.resolve();c.enqueue('end');}});
    const readable=api.ReadableStream.from([1,2,3]).pipeThrough(t);
    await readable.pipeTo(new api.WritableStream({write(x){out.push(x);}}));return [out,max,t.readable.locked,t.writable.locked];
  }),[[2,4,6,'end'],1,false,false]);
});
test('default transform backpressure blocks writes until the readable is consumed', async () => {
  await both(async api => {
    let calls=0;const t=new api.TransformStream({transform(x,c){calls++;c.enqueue(x);}});const w=t.writable.getWriter();let finished=false;
    const p=w.write(42).then(()=>{finished=true;});await ticks(30);assert.equal(calls,0);assert.equal(finished,false);
    const r=t.readable.getReader();const value=await r.read();await p;await w.close();await r.read();r.releaseLock();w.releaseLock();return [value,calls,t.readable.locked,t.writable.locked];
  });
});
test('identity transforms and custom readable high water marks support prefill', async () => {
  await both(async api => {
    const t=new api.TransformStream(undefined,{highWaterMark:4},{highWaterMark:2});const w=t.writable.getWriter();
    await w.write('a');await w.write('b');let third=false;const p=w.write('c').then(()=>{third=true;});await ticks();assert.equal(third,false);
    const reads=collect(t.readable);await p;await w.close();const values=await reads;w.releaseLock();return values;
  });
});
test('transform cancellation unblocks a backpressured writer and calls cancel once', async () => {
  await both(async api => {
    const events=[];const t=new api.TransformStream({cancel(reason){events.push(reason);}});const w=t.writable.getWriter();const write=w.write(1).catch(e=>e);
    await ticks();await t.readable.cancel('stop');const reason=await write;await assert.rejects(w.closed,e=>e==='stop');w.releaseLock();return [events,reason,t.readable.locked,t.writable.locked];
  });
});
test('transform errors propagate to both directions without calling cancel as cleanup', async () => {
  for(const api of [reference,candidate()])for(const reason of [undefined,false,{transform:true}]) {
    let cancels=0;const t=new api.TransformStream({transform(){throw reason;},cancel(){cancels++;}});
    const r=t.readable.getReader(),w=t.writable.getWriter();const read=r.read(),write=w.write(1);
    await Promise.all([read,write,r.closed,w.closed].map(p=>p.then(()=>{throw Error('unexpected success');},e=>assert.equal(e,reason))));
    assert.equal(cancels,0);r.releaseLock();w.releaseLock();
  }
});
test('transform controller error and terminate preserve the correct readable completion', async () => {
  await both(async api => {
    let c;const t=new api.TransformStream({start(x){c=x;}});const w=t.writable.getWriter(),r=t.readable.getReader();
    c.enqueue('last');c.terminate();const a=await r.read(),b=await r.read();await r.closed;await assert.rejects(w.closed,TypeError);r.releaseLock();w.releaseLock();
    return [a,b,t.readable.locked,t.writable.locked];
  });
});
test('transform async start rejection and flush rejection reach both endpoints', async () => {
  for(const api of [reference,candidate()]) {
    const reason={failure:true};const bad=new api.TransformStream({start(){return Promise.reject(reason);}});
    const a=bad.readable.getReader(),b=bad.writable.getWriter();await assert.rejects(a.read(),e=>e===reason);await assert.rejects(b.write(1),e=>e===reason);a.releaseLock();b.releaseLock();
    const flush=new api.TransformStream({flush(){throw reason;}});const r=flush.readable.getReader(),w=flush.writable.getWriter();
    const read=r.read(),close=w.close();await Promise.all([assert.rejects(read,e=>e===reason),assert.rejects(close,e=>e===reason)]);r.releaseLock();w.releaseLock();
  }
});
test('transform cancellation rejection owns both failure results', async () => {
  await both(async api => {
    const t=new api.TransformStream({cancel(){throw 'cancel failed';}});const w=t.writable.getWriter();const write=w.write(1).catch(e=>e);await ticks();
    const cancel=await t.readable.cancel('stop').catch(e=>e);const closed=await w.closed.catch(e=>e);const value=await write;w.releaseLock();return [cancel,closed,value];
  });
});

test('pipe shutdown flushes a synchronously read chunk before source error cleanup', async () => {
  assert.deepEqual(await both(async api => {
    const out=[];const r=new api.ReadableStream({pull(c){c.enqueue(42);c.error('after read');}},{highWaterMark:0});
    const w=new api.WritableStream({write(x){out.push(x);},abort(x){out.push(x);}});
    const error=await r.pipeTo(w).catch(x=>x);return [out,error,r.locked,w.locked];
  }),[[42,'after read'],'after read',false,false]);
});
test('pipe initial failure precedence and two already-closed endpoints follow state', async () => {
  await both(async api => {
    const r=new api.ReadableStream({start(c){c.error('source first');}}),w=new api.WritableStream();await w.close();
    const first=await r.pipeTo(w).catch(e=>e);
    const r2=new api.ReadableStream({start(c){c.close();}}),w2=new api.WritableStream();await w2.close();
    const second=await r2.pipeTo(w2);return [first,second,r.locked,w.locked,r2.locked,w2.locked];
  });
});

test('controller error releases sizing algorithms before the in-flight write finishes', async () => {
  await both(async api => {
    let c,sizes=0;const gate=deferred();const s=new api.WritableStream({start(x){c=x;},write(){return gate.promise;}},{size(){sizes++;return 1;}});
    const w=s.getWriter(),p=w.write(1);await ticks();c.error('closed to new work');
    await assert.rejects(w.write(2),e=>e==='closed to new work');gate.resolve();await p;await assert.rejects(w.closed,e=>e==='closed to new work');
    w.releaseLock();return sizes;
  });
});
