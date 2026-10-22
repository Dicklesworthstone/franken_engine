'use strict';
// Execute the complete production module. Node supplies the language and brand
// predicates, not the candidate comparison algorithm. These are not VM tests.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const util = require('node:util');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(process.env.FRANKEN_UTIL_SOURCE || path.join(root,
  'crates/franken-engine/src/lowering_pipeline/util_module.js'), 'utf8');
const checks = [['isProxy','Proxy'], ['isMap','Map'], ['isSet','Set'],
  ['isWeakMap','WeakMap'], ['isWeakSet','WeakSet'], ['isDate','Date'],
  ['isRegExp','RegExp'], ['isNativeError','Error'], ['isArrayBuffer','ArrayBuffer'],
  ['isDataView','DataView']].map(([name, tag]) => [util.types[name], tag]);
function typeTag(value) {
  for (const [check, tag] of checks) if (check(value)) return tag;
  return Object.prototype.toString.call(value).slice(8, -1);
}
function candidate() {
  const maps = [];
  const size = Object.getOwnPropertyDescriptor(Map.prototype, 'size').get;
  class ObservedMap extends Map {
    constructor() { super(); maps.push(this); }
    get size() { return Reflect.apply(size, this, []); }
  }
  const api = new Function('__franken_util_type_tag', 'Map', 'return ' + source)(typeTag, ObservedMap);
  return { eq: api.isDeepStrictEqual, maps };
}
function wrap(value, depth) { for (let i=0;i<depth;i++) value={next:value}; return value; }
function collection(keys, map) { return map ? new Map(keys.map(key => [key, key.rank])) : new Set(keys); }

test('empty and object-only snapshots allocate no primitive-key Map', () => {
  for (const map of [false,true]) for (const count of [0,1,16,1024]) {
    const c=candidate(), left=Array.from({length:count},(_,rank)=>({rank}));
    const right=Array.from({length:count},(_,rank)=>({rank}));
    assert.equal(c.eq(collection(left,map),collection(right,map)),true);
    assert.equal(c.maps.length,0, `${map ? 'Map' : 'Set'} entries=${count}`);
  }
});
test('nested object-only collections allocate only the active-pair index', () => {
  for (const map of [false,true]) for (const count of [128,1024]) {
    const c=candidate(); let left={leaf:1},right={leaf:1};
    for(let i=0;i<count;i++) {
      left=map?new Map([[left,i]]):new Set([left]);
      right=map?new Map([[right,i]]):new Set([right]);
    }
    assert.equal(c.eq(left,right),true);
    assert.equal(c.maps.length,1,'no unused index per collection level');
    assert.equal(c.maps[0].size,0,'active-pair cleanup');
  }
});
test('primitive keys still get one index and retain SameValueZero and strict values', () => {
  const symbol=Symbol('same'),fn=function(){};
  const keys=[undefined,null,false,0,NaN,1,1n,'1',symbol,fn];
  for(const map of [false,true]) for(const deep of [0,80]) {
    const c=candidate();
    const make=reverse=>map?new Map((reverse?keys.slice().reverse():keys).map(key=>[key,{value:1}]))
      :new Set(reverse?keys.slice().reverse():keys);
    assert.equal(c.eq(wrap(make(false),deep),wrap(make(true),deep)),true);
    assert.equal(c.maps.length,deep?2:1);
    for(const index of c.maps)assert.equal(index.size,0);
    assert.equal(c.eq(new Map([[NaN,-0]]),new Map([[NaN,0]])),false);
  }
});
test('absent primitive index is a mismatch rather than an invalid Map receiver', () => {
  for(const deep of [0,80]) for(const map of [false,true]) {
    const c=candidate();
    const left=map?new Map([[1,0]]):new Set([1]);
    const right=map?new Map([[{rank:1},0]]):new Set([{rank:1}]);
    assert.equal(c.eq(wrap(left,deep),wrap(right,deep)),false);
    assert.equal(c.eq(wrap(right,deep),wrap(left,deep)),false);
    assert.equal(util.isDeepStrictEqual(left,right),false);
  }
});
test('mixed snapshots preserve distinct multiplicities, ordering and late value mutations', () => {
  for(const deep of [0,80]) for(const map of [false,true]) {
    const c=candidate(), symbol=Symbol('shared');
    const left=[null,{rank:0},symbol,{rank:1},NaN,'last'];
    const right=['last',NaN,{rank:1},symbol,{rank:0},null];
    const make=keys=>map?new Map(keys.map(key=>[key,{value:1}])):new Set(keys);
    assert.equal(c.eq(wrap(make(left),deep),wrap(make(right),deep)),true);
    const wrong=right.slice();wrong[2]={rank:0};
    assert.equal(c.eq(wrap(make(left),deep),wrap(make(wrong),deep)),false);
    assert.equal(util.isDeepStrictEqual(make(left),make(wrong)),false);
  }
  for(const deep of [0,80]) {
    const c=candidate(),a=new Map(),b=new Map();
    a.set('first',{get value(){ b.set('later',99);return 1; }});a.set('later',2);
    b.set('first',{value:1});b.set('later',2);
    assert.equal(c.eq(wrap(a,deep),wrap(b,deep)),true,'snapshot captures the old later value');
    assert.equal(b.get('later'),99);
  }
});
// Observe actual private candidate arrays through their existing push calls.
// Nothing is injected into the comparison algorithm or its decision branches.
function retention(map,deep,failValue) {
  const snapshots=[], observed=[];
  const rightKeys=[{rank:0},{rank:1},{rank:2}];
  const realm=vm.createContext({TextEncoder,TextDecoder,__franken_util_type_tag:typeTag,
    inspectAppend(array,value){
      const key=map?value&&value[0]:value;
      if(rightKeys.includes(key)&&!snapshots.includes(array))snapshots.push(array);
    }});
  vm.runInContext(`const savedPush=Array.prototype.push;
    Array.prototype.push=function(value){inspectAppend(this,value);return Reflect.apply(savedPush,this,arguments);};`,realm);
  const api=vm.runInContext(source,realm);
  const leftKeys=rightKeys.map((_,rank)=>({get rank(){
    assert.equal(snapshots.length,1);
    const slots=snapshots[0];
    for(let i=0;i<rank;i++)assert.equal(slots[i],undefined,'consumed object released before next comparison');
    assert.notEqual(slots[rank],undefined,'current candidate remains until comparison succeeds');
    observed.push(rank);return rank;
  }}));
  const left=map?new Map(leftKeys.map((key,i)=>[key,{get value(){
    assert.notEqual(snapshots[0][i],undefined,'Map key match alone does not consume its entry');
    return failValue&&i===1?9:i;
  }}])):new Set(leftKeys);
  const right=map?new Map(rightKeys.map((key,i)=>[key,{value:i}])):new Set(rightKeys);
  const result=api.isDeepStrictEqual(wrap(left,deep),wrap(right,deep));
  if(!failValue){assert.equal(result,true);assert.deepEqual(observed,[0,1,2]);
    assert.equal(snapshots[0].every(value=>value===undefined),true);}
  else assert.equal(result,false);
}
test('both walkers release each consumed object snapshot before the next left entry',()=>{
  for(const map of [false,true])for(const deep of [0,80])retention(map,deep,false);
});
test('a successful Map key does not release the candidate before its value matches',()=>{
  for(const deep of [0,80])retention(true,deep,true);
});
test('iterator cardinality is retained even when repeated primitive keys collapse in its index',()=>{
  for(const deep of [0,80]) {
    const realm=vm.createContext({TextEncoder,TextDecoder,__franken_util_type_tag:typeTag});
    vm.runInContext(`var a=new Map([['x',1],['y',2]]),b=new Map([['x',1],['y',2]]);
      var native=Map.prototype.entries;
      Map.prototype.entries=function(){
        if(this===a)return [['x',1]][Symbol.iterator]();
        if(this===b)return [['x',1],['x',1]][Symbol.iterator]();
        return Reflect.apply(native,this,[]);
      };`,realm);
    vm.runInContext('var api='+source+';',realm);
    realm.depth=deep;
    assert.equal(vm.runInContext(`(function(){var x=a,y=b;
      for(var i=0;i<depth;i++){x={next:x};y={next:y};}return api.isDeepStrictEqual(x,y);})()`,realm),false);
  }
});
test('falsy and function primitive keys never collide with an absent-index sentinel',()=>{
  const keys=[undefined,null,false,0,NaN,'',1n,Symbol('x'),function(){}];
  for(const key of keys)for(const deep of [0,80]) {
    const c=candidate(),a=new Map([[key,undefined],[{rank:1},false]]);
    const b=new Map([[{rank:1},false],[key,undefined]]);
    assert.equal(c.eq(wrap(a,deep),wrap(b,deep)),true);
  }
});

test('snapshot storage is allocated only for the key classes actually present',()=>{
  const anchor='    snapshot.candidateCount = count;';
  assert.equal(source.split(anchor).length,2,'one shared production snapshot builder');
  const instrumented=source.replace(anchor,anchor+'\n    observeSnapshot(snapshot);');
  for(const deep of [0,80]) for(const kind of ['empty','primitive','object','mixed']) {
    const snapshots=[];
    const compare=new Function('__franken_util_type_tag','observeSnapshot','return '+instrumented)(
      typeTag,snapshot=>snapshots.push(snapshot)).isDeepStrictEqual;
    const keys=kind==='empty'?[]:kind==='primitive'?['x']:kind==='object'?[{rank:1}]:['x',{rank:1}];
    const other=keys.map(key=>typeof key==='object'?{rank:1}:key);
    assert.equal(compare(wrap(new Set(keys),deep),wrap(new Set(other),deep)),true);
    assert.equal(snapshots.length,1);
    assert.equal(snapshots[0].primitive===undefined,kind==='empty'||kind==='object');
    assert.equal(snapshots[0].candidates===undefined,kind==='empty'||kind==='primitive');
    assert.equal(snapshots[0].candidateCount,keys.length);
  }
});
