'use strict';
// Execute the shipped installer, not Node's MIME parser. Node supplies the
// language and collection intrinsics; native lowering/accounting is separate.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const reference = require('node:util');
const sourcePath = process.env.MIME_SOURCE || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/util_mime.js');
const source = fs.readFileSync(sourcePath, 'utf8');
function load() {
  const context = vm.createContext({});
  vm.runInContext('globalThis.api = (' + source + ')({});', context);
  return { api: context.api, context };
}
const candidate = load().api;
const plain = value => JSON.parse(JSON.stringify(value));
function outcome(action) {
  try { return ['ok', plain(action())]; }
  catch (error) { return ['error', error.name, error.code || null]; }
}
function record(api, input) {
  const mime = new api.MIMEType(input);
  return { type: mime.type, subtype: mime.subtype, essence: mime.essence,
    text: String(mime), json: JSON.stringify(mime), params: [...mime.params] };
}
function compare(input) {
  assert.deepEqual(outcome(() => record(candidate, input)),
    outcome(() => record(reference, input)), typeof input === 'string' ? JSON.stringify(input) : typeof input);
}

test('exports, constructor ownership and standard method aliases', () => {
  for (const api of [candidate, reference]) {
    const mime = new api.MIMEType('Text/PLAIN');
    assert(mime instanceof api.MIMEType);
    assert(mime.params instanceof api.MIMEParams);
    assert.equal(mime.params, mime.params);
    assert.equal(api.MIMEParams.prototype[Symbol.iterator], api.MIMEParams.prototype.entries);
    assert.equal(api.MIMEType.prototype.toJSON, api.MIMEType.prototype.toString);
    assert.equal(api.MIMEParams.prototype.toJSON, api.MIMEParams.prototype.toString);
    assert.equal(api.MIMEType.length, 1); assert.equal(api.MIMEParams.length, 0);
    assert.throws(() => api.MIMEType('x/y'), {name:'TypeError'});
    assert.throws(() => api.MIMEParams(), {name:'TypeError'});
  }
});
test('essences, HTTP whitespace and legal token punctuation', () => {
  for (const input of ['text/plain', ' Application/Vnd.test+JSON ; charset=UTF-8 ',
    '\t\r\nTEXT/HTML\n\t', '!#$%&\'*+-.^_`|~/x', '*/*', 'x/y;',
    '', '/', 'x', 'x/', '/x', 'x/y/z', 'x /y', '\fx/y', 'x/é', 'x/y\0']) compare(input);
});
test('first duplicate wins, parsed names lowercase, case-sensitive mutation', () => {
  for (const input of ['text/html;CHARSET=utf-8;charset=latin1',
    'x/y;a=;a=second', 'x/y;a="";a=second', 'x/y;bad name=z;ok=x',
    'x/y;__proto__=x;constructor=y;toString=z']) compare(input);
  function run(api) {
    const m = new api.MIMEType('x/y;a=one');
    m.params.set('A', 'two');m.params.set('a','three');
    const result = [String(m),m.params.get('a'),m.params.get('A'),m.params.has('missing')];
    m.params.delete('A');m.params.delete('missing');result.push(String(m));return result;
  }
  assert.deepEqual(plain(run(candidate)),plain(run(reference)));
});
test('quoted strings, escapes and unterminated values', () => {
  for (const input of ['x/y;a="a;b";q="a\\\"b";path="a\\\\b"',
    'x/y;a="unterminated', 'x/y;a="tail\\', 'x/y;a=""',
    'x/y;a=" v "', 'x/y;a="a\tb"', 'x/y;a="a\rb";ok=yes']) compare(input);
});
test('Node-specific missing-separator and trailing-quote recovery is explicit', () => {
  // Node 22.16 differs from the WHATWG discard-until-semicolon step and
  // retains trailing whitespace inside unterminated quoted values.
  for (const input of ['x/y;a="v" z=q','x/y;a="v"z=q','x/y;a="v"\\z=q',
    'x/y;a="tail ', 'x/y;a="tail\t', 'x/y;a="tail\r']) compare(input);
});
test('all Latin-1 units across type, subtype, names and quoted values', () => {
  for(let code=0;code<256;code++) {
    const ch=String.fromCharCode(code);
    for(const input of [ch+'/x','x/'+ch,'x/y;'+ch+'=v','x/y;a="'+ch+'"']) compare(input);
  }
});
test('non-Latin-1 and surrogate characters cannot enter serialized parameter values', () => {
  for(const value of ['é','ÿ','Ā','😀','\ud800','\udfff']) {
    compare('x/y;a="'+value+'";ok=yes');
    assert.deepEqual(outcome(()=>{const p=new candidate.MIMEParams();p.set('a',value);return String(p);}),
      outcome(()=>{const p=new reference.MIMEParams();p.set('a',value);return String(p);}));
  }
});
test('valid string coercions and Symbol refusal', () => {
  for(const value of [undefined,null,true,1,1n,Symbol('x'),['x/y'],{toString(){return 'TEXT/HTML';}}]) compare(value);
  for(const api of [candidate,reference]) {
    const calls=[];
    const input={[Symbol.toPrimitive](hint){calls.push(hint);return 'x/y';}};
    assert.equal(String(new api.MIMEType(input)),'x/y');assert.deepEqual(calls,['string']);
    const error={};assert.throws(()=>new api.MIMEType({toString(){throw error;}}),e=>e===error);
  }
});
test('type and subtype mutations canonicalize or leave the old state untouched', () => {
  for(const field of ['type','subtype']) for(const value of ['IMAGE','x/y',' x','x ',true,undefined,'','é',Symbol('x')]) {
    function run(api){const m=new api.MIMEType('text/plain;a=b');const changed=outcome(()=>{m[field]=value;return m[field];});return [changed,String(m)];}
    assert.deepEqual(plain(run(candidate)),plain(run(reference)));
  }
});
test('parameter set validates both converted arguments before mutation', () => {
  for(const api of [candidate,reference]) {
    const m=new api.MIMEType('x/y;a=old'),calls=[];
    assert.throws(()=>m.params.set({toString(){calls.push('name');return 'bad name';}},
      {toString(){calls.push('value');return 'ok';}}),e=>e.code==='ERR_INVALID_MIME_SYNTAX');
    assert.deepEqual(calls,['name','value']);assert.equal(String(m),'x/y;a=old');
    for(const value of ['\r\nInjected: yes','\0','\x7f','\u0100']) {
      assert.throws(()=>m.params.set('a',value),e=>e.code==='ERR_INVALID_MIME_SYNTAX');
      assert.equal(String(m),'x/y;a=old');
    }
  }
});
test('parameter lookup keeps raw keys while set coerces exactly once', () => {
  function run(api) {
    const p=new api.MIMEParams('ignored');let calls=0;
    const key={toString(){calls++;return 'x';}};
    const rows=[p.get(key),p.has(key),p.set(key,'v'),p.get(key),p.delete(key),p.has(key)];
    return {rows,calls,text:String(p)};
  }
  assert.deepEqual(plain(run(candidate)),plain(run(reference)));
});
test('parameter iterators are live and retain Map insertion order', () => {
  function run(api) {
    const p=new api.MIMEParams();p.set('a','1');p.set('b','2');
    const i=p.entries(),first=i.next();p.delete('b');p.set('c','3');p.set('a','4');
    const rest=[i.next(),i.next()];p.set('d','5');rest.push(i.next());
    return [first,rest,[...p.keys()],[...p.values()],String(p)];
  }
  assert.deepEqual(plain(run(candidate)),plain(run(reference)));
});
test('all values serialize with reversible quoting and backslash escaping', () => {
  for(const value of ['','a b','a;b','a=b','a"b','a\\b','a\\"b','\t','é','!#$%&\'*+-.^_`|~']) {
    function run(api){const m=new api.MIMEType('x/y');m.params.set('p',value);const text=String(m);return [text,new api.MIMEType(text).params.get('p')];}
    assert.deepEqual(plain(run(candidate)),plain(run(reference)));
  }
});
test('prototype-named parameters are real ordered entries', () => {
  function run(api){const m=new api.MIMEType('x/y;__proto__=first');m.params.set('constructor','second');m.params.set('toString','third');return [String(m),[...m.params]];}
  assert.deepEqual(plain(run(candidate)),plain(run(reference)));
});
test('JSON serialization aliases the internal serializer and readonly accessors stay readonly', () => {
  for(const api of [candidate,reference]) {
    const m=new api.MIMEType('x/y;a=b');
    assert.equal(JSON.stringify([m,m.params]),'["x/y;a=b","a=b"]');
    assert.throws(()=>{m.essence='bad';},{name:'TypeError'});
    assert.throws(()=>{m.params=new api.MIMEParams();},{name:'TypeError'});
    assert.equal(String(m),'x/y;a=b');
  }
});
test('branded methods reject forged receivers without invoking argument conversion', () => {
  for(const api of [candidate,reference]) for(const method of ['get','has','delete','set','entries','keys','values','toString']) {
    let converted=0;const value={toString(){converted++;return 'x';}};
    const action = () => api.MIMEParams.prototype[method].call({},value,value);
    if (['entries','keys','values'].includes(method)) {
      const iterator=action();assert.throws(()=>iterator.next(),{name:'TypeError'});
    } else assert.throws(action,{name:'TypeError'});
    assert.equal(converted,0);
  }
});
test('subclasses retain private identity without exposing implementation records', () => {
  for(const api of [candidate,reference]) {
    class Child extends api.MIMEType {}
    const m=new Child('x/y;a=b');assert.equal(String(m),'x/y;a=b');
    assert.deepEqual(Reflect.ownKeys(m),[]);assert.deepEqual(Reflect.ownKeys(m.params),[]);
    assert.throws(()=>Object.getOwnPropertyDescriptor(api.MIMEType.prototype,'type').get.call({}),{name:'TypeError'});
  }
});
test('thirty thousand deterministic complete input comparisons', () => {
  const chars=['x','X',' ','\t','\r','\n','/',';','=','"','\\','a','0','é','\x7f','\0','😀'];let state=1234567;
  const random=n=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state%n;};
  for(let i=0;i<30000;i++) {let input=i%3?'text/plain;':'';for(let j=0,end=random(70);j<end;j++)input+=chars[random(chars.length)];compare(input);}
});
test('seeded mutation sequences compare every published state', () => {
  let state=9981;const random=n=>{state=(Math.imul(state,1103515245)+12345)>>>0;return state%n;};
  const names=['a','A','__proto__','constructor','foo-bar','bad name',''],values=['','a b','a"b','a\\b','é','yes','\r'];
  for(let trial=0;trial<128;trial++) {
    const a=new candidate.MIMEType('Text/Plain'),b=new reference.MIMEType('Text/Plain');
    for(let step=0;step<32;step++) {
      const name=names[random(names.length)],value=values[random(values.length)],op=random(3);
      const action=m=>op===0?m.params.delete(name):op===1?m.params.set(name,value):m.params.get(name);
      const aResult=outcome(()=>[action(a)]),bResult=outcome(()=>[action(b)]);
      assert.deepEqual(aResult,bResult);assert.equal(String(a),String(b));
    }
  }
});
test('large escaped parameters roundtrip without regex, recursion or whole-prefix rescanning', () => {
  const value='a\\"b '.repeat(16384);const a=new candidate.MIMEType('x/y'),b=new reference.MIMEType('x/y');
  a.params.set('payload',value);b.params.set('payload',value);
  assert.equal(String(a),String(b));assert.equal(new candidate.MIMEType(String(a)).params.get('payload'),value);
});
test('many parameters retain order and duplicate admission is first-wins', () => {
  let input='application/json';for(let i=0;i<4096;i++)input+=';k'+i+'=v'+i;
  input+=';k0=ignored';compare(input);
});
test('caller replacements cannot alter internal MIME serialization', () => {
  const m=new candidate.MIMEType('x/y;a="v v"');
  m.params.toString=()=>{throw new Error('not canonical');};
  m.params[Symbol.iterator]=()=>{throw new Error('not canonical');};
  assert.equal(String(m),'x/y;a="v v"');
});
test('captured collection and string methods survive later public replacements', () => {
  const {context}=load();
  const result=vm.runInContext(`
    const mime=new api.MIMEType('TEXT/HTML;a="b b"');
    const stop=()=>{throw new Error('replaced public method');};
    Map.prototype.get=stop;Map.prototype.set=stop;Map.prototype.has=stop;
    Map.prototype.delete=stop;Map.prototype.entries=stop;
    WeakMap.prototype.get=stop;WeakMap.prototype.set=stop;
    String.prototype.slice=stop;String.prototype.toLowerCase=stop;
    Array.prototype.join=stop;
    mime.params.set('c','d');mime.params.delete('a');mime.type='APPLICATION';
    mime.toString();`,context);
  assert.equal(result,'application/html;c=d');
});
test('private serialization fragments cannot be intercepted by inherited index setters', () => {
  const {context}=load();
  const result=vm.runInContext(`
    let intercepted=0;Object.defineProperty(Array.prototype,'0',{
      configurable:true,set(){intercepted++;throw new Error('inherited setter');}});
    const mime=new api.MIMEType('x/y;a="b\\\\c"');
    mime.params.set('quote','a"b');
    const text=mime.toString();delete Array.prototype[0];
    [text,intercepted];`,context);
  assert.deepEqual(plain(result),['x/y;a=bc;quote="a\\"b"',0]);
});
test('reentrant parameter coercions preserve live map ordering', () => {
  function run(api) {
    const p=new api.MIMEParams();p.set('old','value');const calls=[];
    p.set({toString(){calls.push('name');p.set('side','one');return 'key';}},
      {toString(){calls.push('value');p.delete('old');return 'two';}});
    return [calls,[...p],String(p)];
  }
  assert.deepEqual(plain(run(candidate)),plain(run(reference)));
});
test('iterator return is terminal and conversion failures preserve original identity', () => {
  for(const api of [candidate,reference]) {
    const p=new api.MIMEParams();p.set('a','b');const iterator=p.entries();
    iterator.next();assert.equal(iterator.return('closed').value,'closed');p.set('c','d');
    assert.equal(iterator.next().done,true);
    const reason={};assert.throws(()=>p.set('x',{toString(){throw reason;}}),e=>e===reason);
    assert.equal(p.get('x'),null);
  }
});
test('omitted and non-string lookup keys are not implicitly stringified', () => {
  for(const api of [candidate,reference]) {
    const p=new api.MIMEParams();p.set('undefined','u');p.set('null','n');p.set('5','v');
    for(const key of [undefined,null,5,Symbol('x'),{toString(){throw new Error('unexpected conversion');}}]) {
      assert.equal(p.get(key),null);assert.equal(p.has(key),false);assert.equal(p.delete(key),undefined);
    }
    assert.equal(String(p),'undefined=u;null=n;5=v');
  }
});
