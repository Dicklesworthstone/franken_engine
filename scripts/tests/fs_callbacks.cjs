'use strict';
// Exact callback installer on Node primitives/synchronous I/O. This does not
// execute the Rust lowerer, interpreter, sandbox provider, or fs module factory.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { promisify } = require('node:util');
const { spawnSync } = require('node:child_process');
const sourcePath = process.env.FRANKEN_FS_CALLBACK_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/fs_callbacks.js');
const source = fs.readFileSync(sourcePath, 'utf8');
const names = ['stat','lstat','readdir','mkdir','mkdtemp','realpath','readlink','access','rmdir','rm',
  'truncate','unlink','rename','chmod','utimes','copyFile','symlink','exists','open','close','fsync',
  'read','write','readv','writev','cp'];
function candidate(overrides = {}, globals = {}) {
  const base = Object.create(null);
  for (const name of names) base[name+'Sync'] = fs[name+'Sync'];
  base.promises = { cp: fs.promises.cp };
  Object.assign(base, overrides);
  for (const name of names) assert.equal(base[name], undefined, 'no callback fallback');
  const context = vm.createContext({ Buffer, Uint8Array, DataView, ArrayBuffer, Promise,
    Reflect, Object, TypeError, RangeError, Error, Array, Symbol, queueMicrotask, URL, Date, ...globals });
  return { api: vm.runInContext(source, context)(base), base, context };
}
function invoke(api, name, ...args) {
  return new Promise((resolve, reject) => {
    let returned = false;
    const result = api[name](...args, function (error, ...values) {
      try {
        assert.equal(returned, true, 'callback must not be synchronous');
        if (error) reject(error); else resolve(values);
      } catch (failure) { reject(failure); }
    });
    assert.equal(result, undefined); returned = true;
  });
}
function fixture() {
  // Test roots are deliberately retained, never deleting user/workspace files.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-fs-callback-'));
  const file = path.join(root, 'input'); fs.writeFileSync(file, 'abé\nCDEF\n');
  return { root, file };
}
async function both(program) {
  const expected = await program(fs, fixture());
  const actual = await program(candidate().api, fixture());
  assert.deepEqual(actual, expected); return actual;
}
test('all callback operations are actually installed', () => {
  const {api} = candidate();
  for (const name of names) assert.equal(typeof api[name], 'function', name);
});
test('metadata discovery, aliases, views and BigInt stats', async () => {
  await both(async (api, {root, file}) => {
    const [s] = await invoke(api, 'stat', file), [l] = await invoke(api, 'lstat', file);
    const [b] = await invoke(api, 'stat', file, {bigint:true});
    const [list] = await invoke(api, 'readdir', root, {withFileTypes:true});
    const [real] = await invoke(api, 'realpath', file);
    await invoke(api, 'access', file);
    return [s.size,l.isFile(),typeof b.size,list.map(x=>[x.name,x.isFile()]),path.basename(real)];
  });
});
test('mkdir returns first created directory and undefined once it exists', async () => {
  await both(async (api, {root}) => {
    const nested = path.join(root,'a/b');
    const first = await invoke(api,'mkdir',nested,{recursive:true});
    const second = await invoke(api,'mkdir',nested,{recursive:true});
    const [tmp] = await invoke(api,'mkdtemp',path.join(root,'temp-'));
    return [first.map(x=>path.relative(root,x)),second,fs.statSync(tmp).isDirectory()];
  });
});
test('copy rename permissions timestamps truncate and unlink have exact results', async () => {
  await both(async (api,{root,file}) => {
    const a=path.join(root,'a'),b=path.join(root,'b');
    const results=[];
    results.push(await invoke(api,'copyFile',file,a));
    results.push(await invoke(api,'rename',a,b));
    results.push(await invoke(api,'chmod',b,0o600));
    results.push(await invoke(api,'utimes',b,1000,1001));
    const time=fs.statSync(b).mtimeMs;
    results.push(await invoke(api,'truncate',b,2));
    const value=fs.readFileSync(b,'utf8');
    results.push(await invoke(api,'unlink',b));
    return [results,time,value,fs.existsSync(a),fs.existsSync(b)];
  });
});
test('symlink target and lstat do not get replaced by followed stat', async () => {
  await both(async (api,{root,file}) => {
    const link=path.join(root,'link');await invoke(api,'symlink',path.basename(file),link);
    const [target]=await invoke(api,'readlink',link);
    const [s]=await invoke(api,'lstat',link);return [target,s.isSymbolicLink()];
  });
});
test('open read write fsync close share a raw descriptor and original buffer', async () => {
  await both(async (api,{root}) => {
    const file=path.join(root,'result');const [fd]=await invoke(api,'open',file,'w+');
    const bytes=Buffer.from('_hello_');
    const [written, same]=await invoke(api,'write',fd,bytes,1,5,0);
    const target=new Uint8Array(7);target.fill(95);
    const [read, original]=await invoke(api,'read',fd,target,1,5,0);
    const sync=await invoke(api,'fsync',fd), close=await invoke(api,'close',fd);
    return [written,same===bytes,read,original===target,Buffer.from(target).toString(),sync,close];
  });
});
test('read default allocation, options and buffer-options overloads', async () => {
  await both(async (api,{file}) => {
    const [fd]=await invoke(api,'open',file);
    try {
      const a=await invoke(api,'read',fd);
      const b=Buffer.alloc(4,95);const result=await invoke(api,'read',fd,{buffer:b,offset:1,length:2,position:0});
      const c=Buffer.alloc(4,95);const third=await invoke(api,'read',fd,c,{offset:1,length:2,position:0});
      return [a[0],a[1].length,a[1].subarray(0,a[0]).toString(),result[0],result[1]===b,b.toString(),third[0],third[1]===c,c.toString()];
    } finally { await invoke(api,'close',fd); }
  });
});
test('string writes preserve original string and count encoded bytes', async () => {
  await both(async (api,{root}) => {
    const file=path.join(root,'result');const [fd]=await invoke(api,'open',file,'w+');
    const a=await invoke(api,'write',fd,'é');
    const b=await invoke(api,'write',fd,'ab',null);
    const c=await invoke(api,'write',fd,'4142',0,'hex');
    await invoke(api,'close',fd);return [a,b,c,fs.readFileSync(file).toString('hex')];
  });
});
test('DataView and wide typed arrays use viewed bytes and preserve public identity', async () => {
  await both(async (api,{root}) => {
    const file=path.join(root,'result');const [fd]=await invoke(api,'open',file,'w+');
    const backing=new Uint8Array([0,1,2,3,4,5,6,7]);const view=new DataView(backing.buffer,2,4);
    const written=await invoke(api,'write',fd,view,0,4,0);
    const output=new Uint16Array(2);const read=await invoke(api,'read',fd,output,{position:0});
    await invoke(api,'close',fd);
    return [written[0],written[1]===view,read[0],read[1]===output,Array.from(new Uint8Array(output.buffer))];
  });
});
test('vectored I/O reports partial counts and original list identity', async () => {
  await both(async (api,{root}) => {
    const file=path.join(root,'result');const [fd]=await invoke(api,'open',file,'w+');
    const list=[Buffer.from('ab'),new Uint8Array([99,100]),new DataView(new Uint8Array([101]).buffer)];
    const w=await invoke(api,'writev',fd,list,0);
    const output=[Buffer.alloc(2),Buffer.alloc(6,95)];
    const r=await invoke(api,'readv',fd,output,0);
    await invoke(api,'close',fd);return [w[0],w[1]===list,r[0],r[1]===output,Buffer.concat(output).toString()];
  });
});
test('native filesystem errors are delivered once without a successful result', async () => {
  await both(async (api,{root}) => {
    const errors=[];
    for (const name of ['stat','lstat','readdir','access','readlink','unlink']) {
      try { await invoke(api,name,path.join(root,'missing')); assert.fail(name); }
      catch (error) { errors.push([name,error.code]); }
    }
    return errors;
  });
});
test('legacy exists preserves its boolean-only and synchronous-invalid-path contract', async () => {
  await both(async (api,{file,root}) => {
    const values=[];
    for (const input of [file,path.join(root,'missing'),null,12]) {
      let returned=false;
      const value=await new Promise(resolve=>{api.exists(input,function(...args){assert.equal(returned,typeof input==='string');resolve(args);});returned=true;});
      values.push(value);
    }
    return values;
  });
});
test('callback validation refuses before scheduling any filesystem effects', () => {
  let calls=0;const {api}=candidate(Object.fromEntries(names.map(name=>[name+'Sync',()=>{calls++;}])));
  for(const name of names.filter(name=>name!=='close')) {
    assert.throws(()=>api[name]('bad',null),error=>error.code==='ERR_INVALID_ARG_TYPE');
  }
  assert.equal(calls,0);
});
test('queued operations capture methods instead of rereading replaceable exports', async () => {
  const {file}=fixture();const {api,context}=candidate();
  const complete=invoke(api,'stat',file);
  api.statSync=()=>{throw Error('replacement');};context.queueMicrotask=()=>{throw Error('replacement scheduler');};
  const [s]=await complete;assert.equal(s.isFile(),true);
});
test('callback exceptions escape once, and callback return thenables are not consumed', () => {
  const jobs=[];const {api}=candidate({statSync:()=>42},{queueMicrotask:fn=>jobs.push(fn)});
  const failure={callback:true};let calls=0;
  api.stat('x',()=>{calls++;throw failure;});
  assert.throws(()=>jobs.shift()(),error=>error===failure);assert.equal(calls,1);
  api.stat('x',()=>({then(){throw Error('must not consume callback return');}}));
  jobs.shift()();assert.equal(jobs.length,0);
});
test('provider failures including falsy values cannot become successful callbacks', async () => {
  for(const reason of [undefined,null,false,0,'',new Error('denied')]) {
    const {api}=candidate({statSync(){throw reason;}});
    await assert.rejects(invoke(api,'stat','x'),error=>reason ? error===reason : error.code==='EIO' && error.cause===reason);
  }
});
test('short writes report progress without performing a hidden whole-buffer retry', async () => {
  let calls=0;const bytes=Buffer.from('abcdef');const {api}=candidate({writeSync(){calls++;return 2;}});
  const [n,original]=await invoke(api,'write',3,bytes);assert.equal(n,2);assert.equal(original,bytes);assert.equal(calls,1);
});
test('invalid provider counts reject rather than corrupting the caller progress counter', async () => {
  for(const n of [-1,1.5,NaN,4]) {
    const {api}=candidate({readSync(){return n;}});
    await assert.rejects(invoke(api,'read',3,Buffer.alloc(3)),error=>error.code==='EIO');
  }
});
test('new multi-result callbacks work with util.promisify', async () => {
  await both(async (api,{root})=>{
    const file=path.join(root,'result');const fd=await promisify(api.open)(file,'w+');
    const buffer=Buffer.from('abc');const written=await promisify(api.write)(fd,buffer);
    const output=Buffer.alloc(3);const read=await promisify(api.read)(fd,output,0,3,0);
    const buffers=[Buffer.from('x')];const vector=await promisify(api.writev)(fd,buffers,0);
    await promisify(api.close)(fd);
    return [written.bytesWritten,written.buffer===buffer,read.bytesRead,read.buffer===output,output.toString(),vector.bytesWritten,vector.buffer===buffers];
  });
});

test('cp awaits async filters and copies only selected files before completion', async () => {
  await both(async (api,{root,file})=>{
    const input=path.join(root,'src'),output=path.join(root,'dst');fs.mkdirSync(input);
    fs.copyFileSync(file,path.join(input,'keep'));fs.writeFileSync(path.join(input,'skip'),'unchanged');
    const seen=[];
    const result=await invoke(api,'cp',input,output,{recursive:true,async filter(source){await Promise.resolve();seen.push(path.basename(source));return !source.endsWith('skip');}});
    return [result,seen.sort(),fs.readdirSync(output),fs.readFileSync(path.join(output,'keep'),'utf8')];
  });
});
test('metadata options, Buffer paths, URL paths and times are fixed at call time', async () => {
  await both(async (api,{root,file})=>{
    const buffer=Buffer.from(file), url=require('node:url').pathToFileURL(file);
    const settings={bigint:true};const a=invoke(api,'stat',buffer,settings),b=invoke(api,'stat',url);
    settings.bigint=false;buffer.fill(0);url.pathname='/no/such/file';
    const [s]=await a, [t]=await b;
    const atime=new Date(1000000),mtime=new Date(1001000);
    const done=invoke(api,'utimes',file,atime,mtime);atime.setTime(0);mtime.setTime(0);await done;
    return [typeof s.size,t.size,fs.statSync(file).mtimeMs];
  });
});
test('later option mutation cannot upgrade a queued removal to recursive deletion', async () => {
  const jobs=[],received=[];const {api}=candidate({rmSync(path,settings){received.push([path,settings.recursive,settings.force]);}},
    {queueMicrotask:fn=>jobs.push(fn)});
  const options={recursive:false,force:false};api.rm('target',options,error=>assert.equal(error,null));
  options.recursive=true;options.force=true;jobs.shift()();assert.deepEqual(received,[['target',false,false]]);
});
test('throwing option getters do not schedule partial filesystem work', () => {
  let jobs=0,calls=0;const failure={option:true};const {api}=candidate({statSync(){calls++;}},
    {queueMicrotask(){jobs++;}});
  assert.throws(()=>api.stat('file',{get bigint(){throw failure;}},()=>{}),error=>error===failure);
  assert.equal(jobs,0);assert.equal(calls,0);
});
test('buffer view accessors cannot redirect descriptor I/O', async () => {
  const original=new Uint8Array([1,2,3,4]);const view=new Uint16Array(original.buffer,0,2);
  const other=new Uint8Array([9,9,9,9]);
  for(const [key,value] of [['buffer',other.buffer],['byteOffset',0],['byteLength',4]])Object.defineProperty(view,key,{value});
  let payload;const {api}=candidate({writeSync(fd,buffer,offset,length){payload=Array.from(buffer.subarray(offset,offset+length));return length;}});
  const [count,returned]=await invoke(api,'write',7,view);
  assert.equal(count,4);assert.equal(returned,view);assert.deepEqual(payload,[1,2,3,4]);
});
test('record Node double-get versus admitted vector snapshot; aliasing bytes still agree', async () => {
  async function exercise(api,{file}) {
    const [fd]=await invoke(api,'open',file);
    const base=Buffer.alloc(6,95);let reads=0;
    const buffers=[base.subarray(0,3)];Object.defineProperty(buffers,'1',{get(){reads++;return base.subarray(1,4);}});
    const answer=await invoke(api,'readv',fd,buffers,0);await invoke(api,'close',fd);
    return [answer[0],answer[1]===buffers,reads,base.toString('hex')];
  }
  const reference=await exercise(fs,fixture()), actual=await exercise(candidate().api,fixture());
  assert.equal(reference[2],2);assert.equal(actual[2],1);
  assert.deepEqual([actual[0],actual[1],actual[3]],[reference[0],reference[1],reference[3]]);
});
test('EOF and zero-length read preserve original buffer and zero byte count', async () => {
  await both(async (api,{file})=>{
    const [fd]=await invoke(api,'open',file);const bytes=Buffer.alloc(3,95);
    const eof=await invoke(api,'read',fd,bytes,0,3,1000);
    const zero=await invoke(api,'read',fd,bytes,1,0,0);
    await invoke(api,'close',fd);return [eof[0],eof[1]===bytes,zero[0],zero[1]===bytes,bytes.toString()];
  });
});
test('actual queued callback throws are uncaught exceptions, not unhandled rejections', () => {
  const code=`const fs=require('fs'),vm=require('vm');const input=Object.create(null);input.promises={cp:async()=>{}};input.statSync=()=>42;
  const api=vm.runInThisContext(fs.readFileSync(process.argv[1],'utf8'))(input);
  let calls=0;process.once('uncaughtException',e=>{if(e.message!=='callback-failure'||calls!==1)process.exitCode=1;else console.log('UNCAUGHT_ONCE');});
  process.once('unhandledRejection',()=>{process.exitCode=2;});api.stat('x',()=>{calls++;throw Error('callback-failure');});`;
  const result=spawnSync(process.execPath,['-e',code,sourcePath],{encoding:'utf8',timeout:10000});
  assert.equal(result.status,0,result.stderr);assert.equal(result.stdout,'UNCAUGHT_ONCE\n');assert.equal(result.stderr,'');
});
test('long callback chain does not recurse synchronously or leak pending jobs', async () => {
  const jobs=[];let effects=0,completed=0;const {api}=candidate({statSync(){effects++;return 1;}},{queueMicrotask:fn=>jobs.push(fn)});
  function next(error,value){assert.equal(error,null);assert.equal(value,1);if(++completed<4096)api.stat('x',next);}
  api.stat('x',next);assert.equal(effects,0);
  for(let i=0;i<4096;i++){assert.equal(jobs.length,1);jobs.shift()();}
  assert.equal(effects,4096);assert.equal(completed,4096);assert.equal(jobs.length,0);
});
test('promisified readv has plural buffers and writev uses Node singular buffer', async () => {
  await both(async (api,{root})=>{
    const file=path.join(root,'vector');const fd=await promisify(api.open)(file,'w+');
    const original=[Buffer.from('ab')];const written=await promisify(api.writev)(fd,original,0);
    const output=[Buffer.alloc(4,95)];const read=await promisify(api.readv)(fd,output,0);
    await promisify(api.close)(fd);return [Object.keys(written),written.bytesWritten,written.buffer===original,
      Object.keys(read),read.bytesRead,read.buffers===output,output[0].toString()];
  });
});
test('synchronous argument validation protects callback scheduling for paths and descriptors', () => {
  const jobs=[];const {api}=candidate({},{queueMicrotask:fn=>jobs.push(fn)});
  for(const name of ['stat','lstat','open','readdir','access','mkdir','unlink']) {
    assert.throws(()=>api[name](null,()=>{}),error=>error.code==='ERR_INVALID_ARG_TYPE');
  }
  for(const value of [null,'3',-1,1.1,NaN,Infinity,2147483648]) {
    assert.throws(()=>api.read(value,Buffer.alloc(1),()=>{}));
  }
  assert.equal(jobs.length,0);
});

test('null close callbacks and embedded-NUL paths fail before scheduling', () => {
  const jobs = [], calls = [];
  const {api} = candidate({ closeSync(fd) { calls.push(fd); } }, {queueMicrotask: fn => jobs.push(fn)});
  for (const io of [fs, api]) {
    assert.throws(() => io.close(999999, null), { code: 'ERR_INVALID_ARG_TYPE' });
    for (const name of ['a\0b', Buffer.from([0])]) {
      assert.throws(() => io.stat(name, () => {}), { code: 'ERR_INVALID_ARG_VALUE' });
    }
  }
  assert.deepEqual(calls, []); assert.deepEqual(jobs, []);
});
