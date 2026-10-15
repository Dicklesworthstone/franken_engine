'use strict';
// Execute the exact filesystem factory; Node supplies only the language,
// Buffer/stream primitives and the host-I/O effects. This is NOT native Rust,
// sandbox/IFC, event-loop phase or storage-device crash-durability evidence.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const source = fs.readFileSync(process.env.FRANKEN_FS_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/fs_module.js'), 'utf8');
function fixture(hook = () => undefined) {
  // Retain roots for diagnosis; never remove workspace/user files.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-write-contents-'));
  const file = path.join(root, 'data');
  const calls = [];
  const open = new Set();
  function effect(authority, tag, ...args) {
    const op = tag.slice(6);
    const call = { authority, op, args };
    calls.push(call);
    const response = hook(call, calls);
    if (response && response.throw) throw response.value;
    if (response && response.return) return response.value;
    switch (op) {
      case 'open': {
        const fd = fs.openSync(args[0], args[1], args[2]); open.add(fd); return fd;
      }
      case 'close_fd': { open.delete(args[0]); return fs.closeSync(args[0]); }
      case 'fsync': return fs.fsyncSync(args[0]);
      case 'write_fd': {
        const length = response && response.limit !== undefined ? Math.min(args[3], response.limit) : args[3];
        return fs.writeSync(args[0], args[1], args[2], length, args[4]);
      }
      case 'read_fd': return fs.readSync(...args);
      case 'read': {
        if (typeof args[2] === 'function') {
          fs.readFile(args[0], args[1], args[2]); return;
        }
        return fs.readFileSync(...args);
      }
      case 'write': case 'append': {
        // The old route is deliberately present, not a missing-method trap.
        // Its use is visible separately from descriptor writes/fsync/close.
        let failed = false, error;
        try { fs[op === 'write' ? 'writeFileSync' : 'appendFileSync'](args[0], args[1], args[2]); }
        catch (e) { failed = true; error = e; }
        if (typeof args[3] === 'function') {
          queueMicrotask(() => args[3](failed ? error : null)); return;
        }
        if (failed) throw error;
        return;
      }
      default: throw Error('Unexpected host operation: ' + op);
    }
  }
  const context = vm.createContext({ Buffer, Promise, WeakMap, Reflect, ArrayBuffer,
    Array, Object, Symbol, AggregateError, Error, TypeError, RangeError, Uint8Array, DataView,
    require(name) { assert.equal(name, 'stream'); return require('node:stream'); },
    __franken_fs_read: effect.bind(null, 'fs:read'),
    __franken_fs_write: effect.bind(null, 'fs:write') });
  return { root, file, calls, open, api: vm.runInContext(source, context) };
}
function order(f) { return f.calls.map(c => c.op); }
function sameFailure(expected) { return actual => actual === expected; }
function checkClosed(f) {
  assert.equal(f.open.size, 0, 'no live descriptor after completion');
  const opens = f.calls.filter(c => c.op === 'open');
  const closes = f.calls.filter(c => c.op === 'close_fd');
  assert.equal(closes.length, opens.length, 'every acquired descriptor closes once');
  assert(f.calls.every(c => c.authority === 'fs:write'), 'no added read authority');
}
for (const method of ['writeFile', 'appendFile']) {
  test(method + ' scalar and iterable inputs share one explicit flush lifecycle', async () => {
    for (const data of ['hé', Buffer.from('hé'), new Uint8Array(Buffer.from('hé')), ['hé']]) {
      const f = fixture();
      const result = await f.api.promises[method](f.file, data, {flush:true});
      assert.equal(result, undefined);
      assert.deepEqual(order(f), ['open','write_fd','fsync','close_fd']);
      assert.equal(fs.readFileSync(f.file,'utf8'), 'hé'); checkClosed(f);
    }
  });
  test(method + ' completes short writes within the unchanged 16 KiB request bound', async () => {
    const f = fixture(c => c.op === 'write_fd' ? {limit:997} : undefined);
    const bytes = Buffer.alloc(65539, 90);
    await f.api.promises[method](f.file, bytes, {flush:true});
    assert.deepEqual(fs.readFileSync(f.file), bytes);
    const writes = f.calls.filter(c => c.op === 'write_fd');
    assert(writes.length > 4); assert(writes.every(c => c.args[3] <= 16384));
    assert.deepEqual(order(f).slice(-2), ['fsync','close_fd']); checkClosed(f);
  });
  test(method + ' flush failure rejects and still closes the same descriptor', async () => {
    const error = new Error('device sync refused');
    const f = fixture(c => c.op === 'fsync' ? {throw:true,value:error} : undefined);
    await assert.rejects(f.api.promises[method](f.file,'accepted',{flush:true}),sameFailure(error));
    assert.equal(fs.readFileSync(f.file,'utf8'),'accepted'); checkClosed(f);
    const write = f.calls.find(c => c.op === 'write_fd');
    assert(f.calls.filter(c => ['write_fd','fsync','close_fd'].includes(c.op)).every(c => c.args[0] === write.args[0]));
  });
  test(method + ' empty input still opens, optionally flushes and closes', async () => {
    for (const data of ['',Buffer.alloc(0),[]]) {
      const f=fixture(); fs.writeFileSync(f.file,'old');
      await f.api.promises[method](f.file,data,{flush:true});
      assert.deepEqual(order(f),['open','fsync','close_fd']);
      assert.equal(fs.readFileSync(f.file,'utf8'),method==='writeFile'?'':'old');checkClosed(f);
    }
  });
}
test('write and append preserve flags, encodings and exclusive-open refusal', async () => {
  const f=fixture();fs.writeFileSync(f.file,'prefix');
  await f.api.promises.writeFile(f.file,'c3a9',{flag:'a',encoding:'hex',flush:true});
  await f.api.promises.appendFile(f.file,'!',{flush:false});
  assert.equal(fs.readFileSync(f.file,'utf8'),'prefixé!');
  const prior=fs.readFileSync(f.file);
  await assert.rejects(f.api.promises.writeFile(f.file,'no',{flag:'wx',flush:true}),{code:'EEXIST'});
  assert.deepEqual(fs.readFileSync(f.file),prior);assert.equal(f.open.size,0);
});
test('ordinary options and scalar formats match the live Node reference', async () => {
  for(const method of ['writeFile','appendFile'])for(const [data,opts] of [
    ['abc',undefined],['6162','hex'],['c3a9',{encoding:'hex'}],
    [Buffer.from('xyz'),{flag:'a',flush:true}],['',null],['A',{mode:0o600}],
    [new DataView(Uint8Array.from([95,65,66,95]).buffer,1,2),{flush:true}],
  ]) {
    const f=fixture(), reference=path.join(f.root,'reference');
    fs.writeFileSync(f.file,'old');fs.writeFileSync(reference,'old');
    await fs.promises[method](reference,data,opts);await f.api.promises[method](f.file,data,opts);
    assert.deepEqual(fs.readFileSync(f.file),fs.readFileSync(reference));checkClosed(f);
  }
});
test('invalid and pre-aborted scalar writes never open or truncate a destination', async () => {
  for(const opts of [{flush:null},{flush:1},{encoding:'not-an-encoding'},17]) {
    const f=fixture();fs.writeFileSync(f.file,'preserved');
    await assert.rejects(f.api.promises.writeFile(f.file,'no',opts));
    assert.deepEqual(order(f),[]);assert.equal(fs.readFileSync(f.file,'utf8'),'preserved');
  }
  const f=fixture(),abort=new AbortController();abort.abort(false);
  fs.writeFileSync(f.file,'preserved');
  await assert.rejects(f.api.promises.writeFile(f.file,'no',{signal:abort.signal,flush:true}),
    e=>e.name==='AbortError'&&e.code==='ABORT_ERR'&&e.cause===false);
  assert.deepEqual(order(f),[]);assert.equal(fs.readFileSync(f.file,'utf8'),'preserved');
});
test('cancellation between partial writes preserves only the accepted prefix and closes', async () => {
  const abort=new AbortController();let attempts=0;
  const f=fixture(c=>{if(c.op==='write_fd'){if(++attempts===1)abort.abort('stop');return {limit:2};}});
  await assert.rejects(f.api.promises.writeFile(f.file,'abcdef',{signal:abort.signal,flush:true}),
    e=>e.code==='ABORT_ERR'&&e.cause==='stop');
  assert.equal(fs.readFileSync(f.file,'utf8'),'ab');
  assert.deepEqual(order(f),['open','write_fd','close_fd']);checkClosed(f);
});
test('invalid progress counts never become success or an infinite retry', async () => {
  for(const count of [0,-1,0.5,100,NaN,undefined]) {
    const f=fixture(c=>c.op==='write_fd'?{return:true,value:count}:undefined);
    await assert.rejects(f.api.promises.writeFile(f.file,'abc',{flush:true}),{code:'EIO'});
    assert.deepEqual(order(f),['open','write_fd','close_fd']);checkClosed(f);
  }
});
test('both a write failure and a close failure survive, including falsy values', async () => {
  for(const first of [undefined,null,false,new Error('write failed')]) {
    const closeError=new Error('close failed');
    const f=fixture(c=>c.op==='write_fd'?{throw:true,value:first}:c.op==='close_fd'?{throw:true,value:closeError}:undefined);
    await assert.rejects(f.api.promises.writeFile(f.file,'abc',{flush:true}),e=>
      e.name==='AggregateError'&&e.errors.length===2&&e.errors[0]===first&&e.errors[1]===closeError);
    assert.deepEqual(order(f),['open','write_fd','close_fd']);
    // Simulated close failed before the OS effect; release the test-owned fd.
    for(const fd of f.open)fs.closeSync(fd);
  }
});
test('an open failure has no write, sync or spurious close', async () => {
  const error=new Error('open denied'),f=fixture(c=>c.op==='open'?{throw:true,value:error}:undefined);
  await assert.rejects(f.api.promises.writeFile(f.file,'abc',{flush:true}),sameFailure(error));
  assert.deepEqual(order(f),['open']);assert.equal(f.open.size,0);assert(!fs.existsSync(f.file));
});
test('iterable failure still awaits IteratorClose before descriptor release', async () => {
  const error=new Error('write failed');let finish;
  const f=fixture(c=>c.op==='write_fd'?{throw:true,value:error}:undefined);
  const input={ [Symbol.asyncIterator](){return {next:async()=>({value:'x',done:false}),
    return(){return new Promise(resolve=>{finish=()=>resolve({done:true});});}};}};
  const operation=f.api.promises.writeFile(f.file,input,{flush:true});
  const observed=assert.rejects(operation,sameFailure(error));
  for(let i=0;i<10&&!finish;i++)await Promise.resolve();
  assert.equal(typeof finish,'function');assert.equal(f.open.size,1);assert(!order(f).includes('close_fd'));
  finish();await observed;checkClosed(f);assert(!order(f).includes('fsync'));
});
test('FileHandle arguments retain their existing cursor and ownership', async () => {
  const f=fixture();fs.writeFileSync(f.file,'abcdef');
  const handle=await f.api.promises.open(f.file,'r+');
  await handle.read(Buffer.alloc(2));f.calls.length=0;
  handle.writeFile=()=>{throw Error('public replacement');};
  await f.api.promises.writeFile(handle,'XY');await f.api.promises.appendFile(handle,'!');
  assert.equal(fs.readFileSync(f.file,'utf8'),'abXY!f');
  assert.deepEqual(order(f),['write_fd','write_fd']);assert.equal(f.open.size,1);await handle.close();
});
