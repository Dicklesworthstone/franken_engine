'use strict';
// Execute the production factory, not a transcription. Only its pre-existing
// native path effects are supplied by Node in this HOST test. Rust execution
// and the native path algorithms require the adjacent orchestrator tests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const file = process.env.PATH_MODULE_SOURCE || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/path_module.js');
const text = fs.readFileSync(file, 'utf8');
const source = file.endsWith('.rs') ? text.match(/const PATH_SOURCE: &str = r#"([\s\S]*?)"#;/)[1] : text;
const globals = {};
for (const name of ['normalize', 'resolve', 'relative', 'basename', 'dirname', 'extname', 'parse', 'format']) {
  globals['__franken_path_' + name] = (...args) => path.posix[name](...args);
}
globals.__franken_path_is_absolute = path.posix.isAbsolute;
globals.__franken_path_win32_join = path.win32.join;
globals.__franken_path_win32_basename = path.win32.basename;
globals.__franken_path_win32_is_absolute = path.win32.isAbsolute;
const candidate = vm.runInNewContext(source, globals);
assert(candidate.win32, 'canonical path module must export win32');
const w = candidate.win32, ref = path.win32;
let checks = 0;
function outcome(fn, args) {
  try { return {value: JSON.stringify(Reflect.apply(fn, null, args))}; }
  catch (e) { return {error: e.code, type: e.name}; }
}
function compare(method, args, namespace = 'win32') {
  const actual = outcome(candidate[namespace][method], args);
  const expected = outcome(path[namespace][method], args);
  assert.deepEqual(actual, expected, `${namespace}.${method}(${JSON.stringify(args)})`);
  checks++;
}
assert.equal(w.win32, w);
assert.equal(w.posix, candidate);
assert.equal(candidate.posix, candidate);
assert.equal(w.posix.win32, w);
const edges = ['', '.', '..', '...', '/', '//', '///', '\\', '\\\\', 'a', 'a/', 'a//b',
  'a\\b\\', '.x', '..x', 'x.', '.x.', 'C:', 'c:.', 'C:..', 'C:foo', 'C:/', 'C:\\',
  'C:\\a\\..\\b\\', 'C:/a/./b//', 'D:\\target', '//server', '//server/share',
  '//server//share//a///b', '\\\\server\\share\\..\\a', '\\\\?\\C:\\x',
  '\\\\?\\UNC\\server\\share\\x', 'é/😀.txt', 'C:\\a\ud800.b', '\0/a'];
for (const value of edges) {
  for (const method of ['normalize','isAbsolute','basename','dirname','extname','parse','resolve','toNamespacedPath']) compare(method, [value]);
  for (const suffix of ['', '.txt', 'x', value]) compare('basename', [value,suffix]);
  for (const other of edges) {
    compare('join', [value, other]); compare('resolve', [value, other]); compare('relative', [value, other]);
  }
}
for (const bad of [null, undefined, 1, false, {}, [], new String('x')]) {
  for (const method of ['normalize','isAbsolute','basename','dirname','extname','parse','resolve','join']) compare(method, [bad]);
  compare('relative', [bad,'a']); compare('relative', ['a',bad]);
  compare('toNamespacedPath', [bad]);
}
for (const record of [{}, {root:'C:\\', name:'a', ext:'txt'}, {dir:'C:/a',base:'x'},
  {dir:42,base:'x'}, {root:'x',ext:'js',name:'n'}, {dir:'x',base:42}, {dir:'x',name:42,ext:5},
  {base:1},{root:3,base:4},[],null]) compare('format',[record]);
let seed = 0x52a531;
function random(n) { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return (seed >>> 0) % n; }
const pieces = ['', 'a', 'B', '.', '..', '...', 'C:', 'd:', '/', '\\', 'é', '😀', '\ud800', 'x.txt', '?', 'UNC'];
function randomPath() {
  let p = '';
  for (let i=0,n=random(9); i<n; i++) p += pieces[random(pieces.length)] + ['', '/', '\\'][random(3)];
  return p;
}
for (let i=0;i<10000;i++) {
  const a=randomPath(), b=randomPath(), c=randomPath();
  for (const method of ['normalize','basename','dirname','extname','parse','toNamespacedPath']) compare(method, [a]);
  compare('join',[a,b,c]); compare('resolve',[a,b,c]); compare('relative',[a,b]);
}
for (const a of edges) for (const method of ['normalize','basename','dirname','extname','parse','resolve','toNamespacedPath']) compare(method,[a],'posix');
console.log(`PASS ${checks} exact factory/reference outcomes on ${process.version}`);
// Admission must preserve observable getters/coercions, not merely strings.
function formatOrder(api) {
  const seen=[];
  const value=name=>({[Symbol.toPrimitive](hint){seen.push(name+':'+hint);return name;}});
  const object=new Proxy({dir:value('dir'),root:value('root'),name:value('name'),ext:value('ext')},
    {get(target,key){seen.push('get:'+key);return target[key];}});
  return [api.format(object), seen];
}
assert.deepEqual(formatOrder(w),formatOrder(ref));
for (const field of ['dir','root','base','name','ext']) {
  for (const value of [undefined,null,'',false,0,1,Symbol('field'),['a'],{toString(){return 'field';}}]) {
    compare('format',[{dir:'dir',name:'name',ext:'txt',[field]:value}]);
  }
}
const argumentsList = Array.from({length:4096}, (_, i) => i%4 === 3 ? '..' : `part${i}`);
compare('join', argumentsList); compare('resolve', ['C:\\', ...argumentsList]);
for (const args of [[null,'C:/safe','file'],['C:/base',null,'/root'],[{},'//server/share'],
  [null,'relative'], [null, ...Array(20).fill(''), 'C:/safe'],[null, ...Array(20).fill('')]]) {
  compare('resolve',args);
}
// Separate guest globals named Array must not become free-name dependencies
// in the lowered factory; the native lowerer test verifies its globalThis path.
const expectedExports=['resolve','normalize','isAbsolute','join','relative','toNamespacedPath',
  'dirname','basename','extname','format','parse','sep','delimiter','posix','win32'];
assert.deepEqual(Object.keys(w).sort(),expectedExports.sort());
console.log(`PASS ${checks} final outcomes, coercion ordering, identities and 4096-argument calls`);
