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
test('candidate: callback/non-UTF8/buffering contracts refuse before host effects', t => {
  const root=fixture(t),{io,calls}=factory();
  for(const options of [{encoding:'buffer'},{bufferSize:1},{recursive:'true'},42])assert.throws(()=>io.opendirSync(root,options));
  for(const input of [Buffer.from(root),{},root+'\0x',root+'\\other'])assert.throws(()=>io.opendirSync(input));
  assert.equal(calls.length,0);
  const dir=io.opendirSync(root);assert.throws(()=>dir.read(()=>{}),{code:'ERR_FS_DIR_UNSUPPORTED'});assert.throws(()=>dir.close(()=>{}),{code:'ERR_FS_DIR_UNSUPPORTED'});dir.closeSync();
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
