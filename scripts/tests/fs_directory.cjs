'use strict';
// The real shipped JS factory hosted on Node filesystem primitives. This is
// NOT execution of the Rust interpreter or its native host-I/O provider.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const source = fs.readFileSync(process.env.DIRECTORY_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/fs_directory.js'), 'utf8');
const install = vm.runInThisContext(source, { filename: 'fs_directory.js' });
function factory(overrides = {}) {
  const calls = [];
  const base = { promises: {} };
  for (const name of ['readdirSync','lstatSync','realpathSync']) {
    base[name] = (...args) => { calls.push([name,...args]); return (overrides[name] || fs[name])(...args); };
  }
  return { io: install(base), calls };
}
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-dir-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'tree/sub/deep'), { recursive: true });
  fs.writeFileSync(path.join(root,'tree/a.txt'), 'a');
  fs.writeFileSync(path.join(root,'tree/sub/b.txt'), 'b');
  fs.writeFileSync(path.join(root,'tree/sub/deep/c.txt'), 'c');
  fs.mkdirSync(path.join(root,'empty'));
  return root;
}
function describe(entry, root) {
  return [path.relative(root, path.join(entry.parentPath, entry.name)), entry.isDirectory(),entry.isFile(),entry.isSymbolicLink()];
}
async function collect(dir, root) { const result=[]; for await (const entry of dir) result.push(describe(entry,root)); return result.sort(); }
function collectSync(dir, root) { const result=[]; for(let entry;(entry=dir.readSync())!==null;)result.push(describe(entry,root));return result.sort(); }
for (const lane of ['candidate','node']) {
  const make = () => lane === 'node' ? fs : factory().io;
  test(`${lane}: shallow sync scan and explicit ownership`, async t => {
    const root=fixture(t), io=make(), target=path.join(root,'tree'), dir=io.opendirSync(target);
    assert.equal(dir.path,target); assert(dir instanceof io.Dir);
    assert.deepEqual(collectSync(dir,target),[['a.txt',false,true,false],['sub',true,false,false]]);
    assert.equal(dir.readSync(),null); await dir.close();
    assert.throws(()=>dir.readSync(),{code:'ERR_DIR_CLOSED'});
    assert.throws(()=>dir.read(),{code:'ERR_DIR_CLOSED'});
    await assert.rejects(dir.close(),{code:'ERR_DIR_CLOSED'});
  });
  test(`${lane}: recursive promise scan includes parent paths and closes at EOF`, async t => {
    const root=fixture(t), io=make(), target=path.join(root,'tree'), dir=await io.promises.opendir(target,{recursive:true});
    assert.deepEqual(await collect(dir,target),[['a.txt',false,true,false],['sub',true,false,false],['sub/b.txt',false,true,false],['sub/deep',true,false,false],['sub/deep/c.txt',false,true,false]]);
    assert.throws(()=>dir.readSync(),{code:'ERR_DIR_CLOSED'});
  });
  test(`${lane}: early iterator break closes without consuming remainder`, async t => {
    const root=fixture(t), io=make(), dir=await io.promises.opendir(path.join(root,'tree'));
    let n=0;for await(const entry of dir){assert(entry.name);n++;break;}
    assert.equal(n,1);assert.throws(()=>dir.readSync(),{code:'ERR_DIR_CLOSED'});
  });
  test(`${lane}: consumer throw preserves exact error and closes`, async t => {
    const root=fixture(t),io=make(),dir=await io.promises.opendir(path.join(root,'tree'));
    const reason={private:'reason'};await assert.rejects((async()=>{for await(const entry of dir){throw reason;}})(),e=>e===reason);
    assert.throws(()=>dir.readSync(),{code:'ERR_DIR_CLOSED'});
  });
  test(`${lane}: multiple queued reads drain before close and reject synchronous interleaving`, async t => {
    const root=fixture(t),io=make(),dir=io.opendirSync(path.join(root,'tree'));
    const reads=[dir.read(),dir.read(),dir.read()];const closing=dir.close();
    assert.throws(()=>dir.readSync(),{code:'ERR_DIR_CONCURRENT_OPERATION'});
    assert.throws(()=>dir.closeSync(),{code:'ERR_DIR_CONCURRENT_OPERATION'});
    const values=await Promise.all(reads);assert.equal(values.filter(Boolean).length,2);assert.equal(values[2],null);await closing;
    assert.throws(()=>dir.read(),{code:'ERR_DIR_CLOSED'});
  });
  test(`${lane}: empty async iteration closes and manual EOF alone does not`, async t => {
    const root=fixture(t),io=make();let dir=io.opendirSync(path.join(root,'empty'));
    assert.equal(dir.readSync(),null);assert.equal(await dir.read(),null);dir.closeSync();
    dir=await io.promises.opendir(path.join(root,'empty'));assert.deepEqual(await collect(dir,root),[]);
    assert.throws(()=>dir.closeSync(),{code:'ERR_DIR_CLOSED'});
  });
  test(`${lane}: missing and non-directory errors`, async t => {
    const root=fixture(t),io=make();
    assert.throws(()=>io.opendirSync(path.join(root,'absent')),{code:'ENOENT'});
    await assert.rejects(io.promises.opendir(path.join(root,'tree/a.txt')),{code:'ENOTDIR'});
  });
  test(`${lane}: symbolic links are returned without descending into them`, async t => {
    const root=fixture(t),io=make(),target=path.join(root,'tree');fs.symlinkSync('sub',path.join(target,'alias'));
    const rows=await collect(await io.promises.opendir(target,{recursive:true}),target);
    assert(rows.some(row=>row[0]==='alias'&&row[3]));assert(!rows.some(row=>row[0].startsWith('alias/')));
  });
}
test('candidate: opening loads only one directory and early break never acquires descendants', async t => {
  const root=fixture(t),{io,calls}=factory(),dir=await io.promises.opendir(path.join(root,'tree'),{recursive:true});
  assert.equal(calls.filter(c=>c[0]==='readdirSync').length,1);
  for await(const entry of dir)break;
  assert.equal(calls.filter(c=>c[0]==='readdirSync').length,1);
});
test('candidate: returned entry mutation cannot redirect traversal', async t => {
  const root=fixture(t),{io}=factory(),dir=io.opendirSync(path.join(root,'tree'),{recursive:true});
  let entry;while((entry=dir.readSync())!==null){if(entry.name==='sub'){entry.name='../empty';entry.isDirectory=()=>false;break;}}
  assert(entry);const remainder=collectSync(dir,path.join(root,'tree'));dir.closeSync();
  assert(remainder.some(row=>row[0]==='sub/deep/c.txt'));
});
test('candidate: directory-to-link replacement is terminal and never reads the target', async t => {
  const root=fixture(t),{io,calls}=factory(),target=path.join(root,'tree'),dir=io.opendirSync(target,{recursive:true});
  let entry;while((entry=dir.readSync())!==null)if(entry.name==='sub')break;
  fs.renameSync(path.join(target,'sub'),path.join(root,'retained'));fs.symlinkSync('../empty',path.join(target,'sub'));
  assert.throws(()=>dir.readSync(),{code:'ERR_FS_DIR_CHANGED'});assert.throws(()=>dir.readSync(),{code:'ERR_FS_DIR_CHANGED'});
  assert.equal(calls.filter(c=>c[0]==='readdirSync').length,1);dir.closeSync();
});
test('candidate: invalid callbacks/non-UTF8/buffering refuse before host effects', t => {
  const root=fixture(t),{io,calls}=factory();
  for(const options of [{encoding:'buffer'},{bufferSize:1},{recursive:'true'},42])assert.throws(()=>io.opendirSync(root,options));
  for(const input of [Buffer.from(root),{},root+'\0x',root+'\\other'])assert.throws(()=>io.opendirSync(input));
  assert.equal(calls.length,0);
  const dir=io.opendirSync(root);assert.throws(()=>dir.read(null),{code:'ERR_INVALID_ARG_TYPE'});assert.throws(()=>dir.close(null),{code:'ERR_INVALID_ARG_TYPE'});dir.closeSync();
});
test('candidate: one malformed snapshot cannot publish or traverse a non-child entry', t => {
  for(const name of ['..','.','x/y','x\\y','x\0y']){
    const {io,calls}=factory({realpathSync:()=>'/safe',readdirSync:()=>[{name,isDirectory:()=>true,isSymbolicLink:()=>false}]});
    assert.throws(()=>io.opendirSync('/safe',{recursive:true}));assert.equal(calls.length,2);
  }
});
test('candidate: never-started iterator return and forged receiver cleanup', async t => {
  const root=fixture(t),{io}=factory(),dir=io.opendirSync(root);const it=dir[Symbol.asyncIterator]();await it.return();
  assert.throws(()=>dir.readSync(),{code:'ERR_DIR_CLOSED'});assert.throws(()=>new io.Dir(),{code:'ERR_ILLEGAL_CONSTRUCTOR'});
  for(const method of ['readSync','read','closeSync','close'])assert.throws(()=>io.Dir.prototype[method].call({}),{code:'ERR_INVALID_ARG_TYPE'});
});
test('candidate: private operations survive public method replacement', async t => {
  const root=fixture(t),{io}=factory(),target=path.join(root,'tree'),dir=await io.promises.opendir(target);
  io.readdirSync=()=>{throw Error('public readdir');};dir.read=()=>{throw Error('public read');};dir.close=()=>{throw Error('public close');};
  assert.equal((await collect(dir,target)).length,2);assert.throws(()=>dir.readSync(),{code:'ERR_DIR_CLOSED'});
});
test('candidate: pending read bound still admits cleanup', async t => {
  const root=fixture(t),{io}=factory(),dir=io.opendirSync(root),reads=[];
  for(let i=0;i<1024;i++)reads.push(dir.read());assert.throws(()=>dir.read(),{code:'ERR_FS_DIR_LIMIT'});
  const closing=dir.close();await Promise.all(reads);await closing;assert.throws(()=>dir.readSync(),{code:'ERR_DIR_CLOSED'});
});
test('candidate: depth and entry caps refuse rather than publish partial success', async () => {
  const {io}=factory({realpathSync:p=>p,lstatSync:()=>({isDirectory:()=>true,isSymbolicLink:()=>false}),
    readdirSync:()=>[{name:'d',isDirectory:()=>true,isFile:()=>false,isSymbolicLink:()=>false}]});
  const dir=io.opendirSync('/safe',{recursive:true});let seen=0;await assert.rejects((async()=>{for await(const entry of dir)seen++;})(),{code:'ERR_FS_DIR_LIMIT'});
  assert(seen<=65);assert.throws(()=>dir.readSync(),{code:'ERR_DIR_CLOSED'});
  const tooWide=factory({realpathSync:p=>p,readdirSync:()=>new Array(100001)}).io;
  assert.throws(()=>tooWide.opendirSync('/safe'),{code:'ERR_FS_DIR_LIMIT'});
});

// Callback/Promise interop uses the same cursor, not a second enumeration.
const { promisify } = require('node:util');
const { spawnSync } = require('node:child_process');
function callbackCall(receiver, method, ...args) {
  return new Promise((resolve, reject) => {
    const result = method.call(receiver, ...args, (error, value) => error ? reject(error) : resolve(value));
    assert.equal(result, undefined, 'callback APIs return undefined');
  });
}
for (const lane of ['candidate', 'node']) {
  const make = () => lane === 'node' ? fs : factory().io;
  test(`${lane}: callback directory scan returns real entries and explicit EOF`, async t => {
    const root = fixture(t), io = make(), target = path.join(root, 'tree');
    let synchronous = true;
    const opening = new Promise((resolve, reject) => {
      assert.equal(io.opendir(target, function (error, dir) {
        assert.equal(synchronous, false); assert.equal(this, undefined);
        assert.equal(arguments.length, 2); if (error) reject(error); else resolve(dir);
      }), undefined);
    });
    synchronous = false;
    const dir = await opening, entries = [];
    assert(dir instanceof io.Dir); assert.equal(dir.path, target);
    let entry;
    while ((entry = await callbackCall(dir, dir.read)) !== null) entries.push(describe(entry, target));
    assert.deepEqual(entries.sort(), [['a.txt', false, true, false], ['sub', true, false, false]]);
    assert.equal(await dir.read(), null, 'manual EOF does not close the owner');
    await callbackCall(dir, dir.close);
    assert.throws(() => dir.read(() => {}), { code: 'ERR_DIR_CLOSED' });
    await assert.rejects(callbackCall(dir, dir.close), { code: 'ERR_DIR_CLOSED' });
  });
  test(`${lane}: callback recursive scan and Promise iteration share ownership`, async t => {
    const root = fixture(t), io = make(), target = path.join(root, 'tree');
    const dir = await callbackCall(io, io.opendir, target, { recursive: true });
    const first = await callbackCall(dir, dir.read), second = await dir.read();
    const rest = await collect(dir, target);
    const entries = [describe(first, target), describe(second, target), ...rest].sort();
    assert.deepEqual(entries, [['a.txt',false,true,false],['sub',true,false,false],
      ['sub/b.txt',false,true,false],['sub/deep',true,false,false],['sub/deep/c.txt',false,true,false]]);
    assert.throws(() => dir.read(), { code: 'ERR_DIR_CLOSED' });
  });
  test(`${lane}: promisified opening reading and closing preserve errors`, async t => {
    const root = fixture(t), io = make();
    const dir = await promisify(io.opendir)(path.join(root, 'empty'));
    assert.equal(await promisify(dir.read).call(dir), null);
    assert.equal(await promisify(dir.close).call(dir), undefined);
    await assert.rejects(promisify(dir.close).call(dir), { code: 'ERR_DIR_CLOSED' });
    await assert.rejects(promisify(io.opendir)(path.join(root, 'absent')), { code: 'ENOENT' });
    await assert.rejects(promisify(io.opendir)(path.join(root, 'tree/a.txt')), { code: 'ENOTDIR' });
  });
  test(`${lane}: invalid callback never consumes an entry or closes a directory`, async t => {
    const root = fixture(t), io = make(), target = path.join(root, 'tree');
    for (const value of [null, 1, false, {}]) {
      assert.throws(() => io.opendir(target, {}, value), { code: 'ERR_INVALID_ARG_TYPE' });
    }
    const dir = io.opendirSync(target);
    for (const value of [null, 1, false, {}]) {
      assert.throws(() => dir.read(value), { code: 'ERR_INVALID_ARG_TYPE' });
      assert.throws(() => dir.close(value), { code: 'ERR_INVALID_ARG_TYPE' });
    }
    assert.equal((await collect(dir, target)).length, 2);
    assert.throws(() => dir.read(null), { code: 'ERR_DIR_CLOSED' });
    assert.throws(() => dir.close(null), { code: 'ERR_INVALID_ARG_TYPE' });
  });
}

test('candidate: callback open captures options once before any host effect', async t => {
  const root = fixture(t), { io, calls } = factory();
  let reads = 0, recursive = false;
  const options = { get recursive() { reads++; return recursive; } };
  const opening = callbackCall(io, io.opendir, path.join(root, 'tree'), options);
  assert.equal(reads, 1); assert.equal(calls.length, 0);
  recursive = true;
  io.opendirSync = io.readdirSync = () => { throw new Error('public method replacement'); };
  const dir = await opening;
  assert.equal((await collect(dir, path.join(root, 'tree'))).length, 2);
  assert.equal(reads, 1);
});

test('candidate: mixed queued reads drain FIFO before one accepted callback close', async t => {
  const root = fixture(t), { io } = factory(), dir = io.opendirSync(path.join(root, 'tree'));
  const trace = [];
  const a = callbackCall(dir, dir.read).then(entry => { trace.push('callback'); return entry.name; });
  const b = dir.read().then(entry => { trace.push('promise'); return entry.name; });
  const c = callbackCall(dir, dir.read).then(entry => { trace.push('eof'); return entry; });
  const closing = callbackCall(dir, dir.close).then(() => trace.push('close'));
  assert.throws(() => dir.read(), { code: 'ERR_DIR_CLOSED' });
  assert.throws(() => dir.closeSync(), { code: 'ERR_DIR_CONCURRENT_OPERATION' });
  const values = await Promise.all([a, b, c]); await closing;
  assert.deepEqual(values.slice(0, 2).sort(), ['a.txt', 'sub']); assert.equal(values[2], null);
  assert.deepEqual(trace, ['callback', 'promise', 'eof', 'close']);
});

test('candidate: reentrant callbacks can enqueue but cannot run synchronous cursor operations', async t => {
  const root = fixture(t), { io } = factory(), dir = io.opendirSync(path.join(root, 'tree'));
  const seen = [];
  await new Promise((resolve, reject) => {
    function next(error, entry) {
      if (error) { reject(error); return; }
      assert.throws(() => dir.readSync(), { code: 'ERR_DIR_CONCURRENT_OPERATION' });
      assert.throws(() => dir.closeSync(), { code: 'ERR_DIR_CONCURRENT_OPERATION' });
      if (entry === null) { dir.close(error => error ? reject(error) : resolve()); return; }
      seen.push(entry.name); dir.read(next);
    }
    dir.read(next);
  });
  assert.deepEqual(seen.sort(), ['a.txt', 'sub']);
  assert.throws(() => dir.readSync(), { code: 'ERR_DIR_CLOSED' });
});

test('candidate: pending callback reads share the existing limit and still permit cleanup', async t => {
  const root = fixture(t), { io } = factory(), dir = io.opendirSync(path.join(root, 'empty'));
  let count = 0;
  for (let i = 0; i < 1024; i++) dir.read((error, entry) => { assert.ifError(error); assert.equal(entry, null); count++; });
  assert.throws(() => dir.read(() => {}), { code: 'ERR_FS_DIR_LIMIT' });
  assert.throws(() => dir.read(), { code: 'ERR_FS_DIR_LIMIT' });
  await callbackCall(dir, dir.close); assert.equal(count, 1024);
});

test('candidate: callback close and iterator return join the same close ownership', async t => {
  const root = fixture(t), { io } = factory(), dir = io.opendirSync(path.join(root, 'tree'));
  const iterator = dir[Symbol.asyncIterator]();
  const reading = callbackCall(dir, dir.read);
  const closing = callbackCall(dir, dir.close);
  const returning = iterator.return();
  assert((await reading).name); await closing;
  assert.deepEqual(await returning, { value: undefined, done: true });
  await assert.rejects(dir.close(), { code: 'ERR_DIR_CLOSED' });
});

for (const reason of [undefined, null, false, 0, '', new Error('read failed')]) {
  test('candidate: callback traversal error cannot become EOF, reason=' + String(reason), async t => {
    const root = fixture(t), target = path.join(root, 'tree');
    const { io } = factory({ lstatSync() { throw reason; } });
    const dir = await callbackCall(io, io.opendir, target, { recursive: true });
    let entry;
    do { entry = await callbackCall(dir, dir.read); } while (entry.name !== 'sub');
    await assert.rejects(callbackCall(dir, dir.read), failure => reason ? failure === reason :
      failure.code === 'EIO' && Object.is(failure.cause, reason));
    await assert.rejects(dir.read(), failure => Object.is(failure, reason));
    await callbackCall(dir, dir.close);
  });
}

test('candidate: callback exceptions escape once and do not strand accepted close', () => {
  // A real child uncaughtException observer distinguishes exceptions from
  // rejected discarded Promises. Its use is confined to this failure test.
  const program = `
    'use strict'; const vm=require('node:vm'); const source=${JSON.stringify(source)};
    const install=vm.runInThisContext(source); let calls=0; let escaped=0; let closed=false;
    process.on('uncaughtException',error=>{if(error.message!=='callback throw')process.exit(8);escaped++;});
    process.on('unhandledRejection',()=>process.exit(9));
    const io=install({promises:{},realpathSync:p=>p,lstatSync:()=>({isDirectory:()=>true,isSymbolicLink:()=>false}),
      readdirSync:()=>[{name:'a',isDirectory:()=>false,isSymbolicLink:()=>false}]});
    io.opendir('/safe',(error,dir)=>{
      if(error)throw error;
      dir.read(()=>{calls++;throw Error('callback throw');});
      dir.close(error=>{if(error)throw error;closed=true;});
    });
    process.on('beforeExit',()=>{console.log(calls,escaped,closed);if(calls!==1||escaped!==1||!closed)process.exitCode=7;});
  `;
  const result = spawnSync(process.execPath, ['-e', program], { encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
  assert.equal(result.stdout, '1 1 true\n');
});

test('candidate: 4096 callback entries allocate no per-read Promise and request one snapshot', async () => {
  let allocations = 0, jobs = 0, snapshots = 0;
  const CountingPromise = new Proxy(Promise, { construct(target, args) { allocations++; return Reflect.construct(target, args); } });
  const installCounted = vm.runInNewContext(source, { Promise: CountingPromise,
    queueMicrotask(job) { jobs++; queueMicrotask(job); } });
  const io = installCounted({ promises: {}, realpathSync: p => p,
    lstatSync: () => ({ isDirectory: () => true, isSymbolicLink: () => false }),
    readdirSync() { snapshots++; return Array.from({ length: 4096 }, (_, i) => ({
      name: String(i), isDirectory: () => false, isSymbolicLink: () => false })); } });
  let count = 0;
  await new Promise((resolve, reject) => io.opendir('/safe', (error, dir) => {
    if (error) { reject(error); return; }
    function next(error, entry) {
      if (error) { reject(error); return; }
      if (entry === null) {
        assert.equal(allocations, 0, 'opening and callback reads need no Promises');
        dir.close(error => error ? reject(error) : resolve()); return;
      }
      assert.equal(entry.name, String(count++)); dir.read(next);
    }
    dir.read(next);
  }));
  assert.equal(count, 4096); assert.equal(snapshots, 1);
  assert.equal(allocations, 1, 'only the joinable close needs a Promise');
  assert.equal(jobs, 4099, 'one open, 4097 reads including EOF, one close');
});
