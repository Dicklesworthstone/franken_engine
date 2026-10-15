'use strict';
// Run the exact engine-owned factory against the selected live Node oracle.
// This checks JavaScript semantics on a host, not native engine execution.
// Run: node scripts/tests/util_parse_env.cjs [baseline-util-source.js]
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const util = require('node:util');
const sourcePath = process.argv[2] || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/util_module.js');
const source = fs.readFileSync(sourcePath, 'utf8');
const implementation = Function('__franken_util_inspect', '__franken_util_format',
  '__franken_util_type_tag', 'return ' + source)(
  (value, depth) => util.inspect(value, { depth }),
  args => util.format(...args),
  () => { throw new Error('parseEnv must not call the type-tag intrinsic'); }
);
assert.equal(typeof implementation.parseEnv, 'function', 'util.parseEnv must be exported');
assert.equal(implementation.parseEnv.length, 1);
let checks = 0;
function outcome(parse, value) {
  try { return { value: parse(value) }; }
  catch (error) { return { error: { name: error.name, code: error.code, message: error.message } }; }
}
function compare(content, label = JSON.stringify(content)) {
  const actual = outcome(implementation.parseEnv, content);
  const expected = outcome(util.parseEnv, content);
  assert.deepStrictEqual(actual, expected, label);
  if (actual.value) {
    assert.equal(Object.getPrototypeOf(actual.value), Object.prototype, label + ' prototype');
    assert.deepStrictEqual(Object.keys(actual.value), Object.keys(expected.value), label + ' key order');
    assert.ok(Object.values(actual.value).every(value => typeof value === 'string'));
  }
  checks++;
  return actual.value;
}
const examples = [
  '', ' ', '\t\r\n', '# comment', '# comment\n', 'PORT=3000', 'ZERO=0\nBOOL=true\nJSON={"a":1}',
  'HELLO=world\nHELLO=oh my\n', 'Z=z\nA=a\nM=m', '10=ten\n2=two\nB=b\nA=a',
  'export HOST=localhost\nexport  PORT = 8080\nexport\tLITERAL=x',
  'A=one # tail\nB="two # not a comment"\nC=\'three # literal\'\nD=`four # literal`',
  'A="first\nsecond"\nB=\'first\nsecond\'\nC=`first\nsecond`',
  'A="line\\nnext\\r\\t"\nB=\'line\\nnext\'\nC=`line\\nnext`',
  'A="embedded\\"quote"\nB=y', 'A="x" trailing=y\nB=z',
  'A="unclosed\nB=next', 'A=\'unclosed # literal\t\nB=next', 'A=`unclosed # literal\t\nB=next',
  'A=\nB=x', 'A= \nB=x', 'A= \t', 'A=', 'bad\nother\nA=ok', '=x=y', '=\nA=x',
  'A=x\rB=y', 'A="x\ry"', 'A=one\r\nB=two\r\n', 'A=\u00a0x\u00a0', '\uFEFFA=1',
  'A=\v x\f', '\vA=x\f', 'A=${HOME}\nB=$(echo never)\nC=`not a command`',
  '__proto__=string\nconstructor=string\ntoString=string\n__proto__=another',
  '\uE000=bmp\n\u{10000}=astral\n\uD800=\uDFFF', 'A=a\u0000b\n\u0000B=c',
  '# first\n  # accepted-by-node22=x\nB=y', 'A="x"\n  # accepted-by-node22=y',
  'A=\n  # accepted-by-node22=y', '# first\n\t\n# ignored=x\nB=y',
  'A=x\n  # ignored=y\nB=z'
];
for (const text of examples) compare(text);
for (const value of [undefined, null, true, false, 0, -0, 3.5, NaN, Infinity, 1n,
  Symbol('env'), {}, [], Buffer.from('A=x'), new String('A=x'), function parser() {}]) {
  compare(value, 'invalid content: ' + typeof value);
}
// Independent expectations cover useful application behavior, not just equality
// with an incumbent that might also be wrong.
assert.deepStrictEqual(implementation.parseEnv('export APP = "hello # world"\nAPP=override\nPORT=3000'),
  { APP: 'override', PORT: '3000' });
const untrusted = implementation.parseEnv('__proto__=not-an-object\nconstructor=ordinary-value');
assert.equal(Object.getPrototypeOf(untrusted), Object.prototype);
assert.equal(Object.hasOwn(untrusted, '__proto__'), false);
assert.equal(untrusted.constructor, 'ordinary-value');
assert.deepStrictEqual(implementation.parseEnv('LITERAL=${HOME}\nSHELL=$(exit 1)'),
  { LITERAL: '${HOME}', SHELL: '$(exit 1)' });
checks += 3;
let seed = 572993;
function random(n) { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return (seed >>> 0) % n; }
const lines = ['A=x', 'B=y', 'export C=z', 'BAD', '# comment', 'A="x"', "B='x'", 'C=`x`',
  'A="x\\ny"', 'A="unclosed', "B='unclosed", 'C=`unclosed', 'A=', 'B= \t', 'A= # comment',
  'A="x" trailing', '__proto__=safe', 'constructor=ok', 'export  D = two words', '\t E \t = \t y #tail'];
for (let i = 0; i < 10000; i++) {
  const content = Array.from({ length: 1 + random(16) }, () => lines[random(lines.length)])
    .join(random(2) ? '\n' : '\r\n');
  compare(content, 'generated lines ' + i);
}
// A separate fixed-seed character corpus covers malformed separators, quote
// recovery, comment/blank-line transitions and CR normalization together.
seed = 63222;
const alphabet = 'AB= #\n\r\t\'"`xyz\\';
for (let i = 0; i < 30000; i++) {
  const content = Array.from({ length: random(80) }, () => alphabet[random(alphabet.length)]).join('');
  compare(content, 'generated characters ' + i);
}
// Fresh state per call and no ambient environment mutation or interpolation.
const savedEnvironment = { ...process.env };
const first = implementation.parseEnv('ONLY=first');
first.ONLY = 'changed';
assert.deepStrictEqual(implementation.parseEnv('ONLY=second'), { ONLY: 'second' });
assert.deepStrictEqual(implementation.parseEnv('OTHER=next'), { OTHER: 'next' });
assert.deepStrictEqual({ ...process.env }, savedEnvironment);
let coerced = false;
const nonString = { toString() { coerced = true; throw new Error('coercion must not run'); } };
compare(nonString, 'non-string is not coerced');
assert.equal(coerced, false);
checks += 3;
// Node publishes into an ordinary object using Set, so inherited setters are
// observable; do not silently claim a null-prototype/DefineOwnProperty result.
function inheritedSetter(parse) {
  const values = [];
  const old = Object.getOwnPropertyDescriptor(Object.prototype, 'FRANKEN_ENV_SETTER');
  Object.defineProperty(Object.prototype, 'FRANKEN_ENV_SETTER', {
    configurable: true, set(value) { values.push(value); }
  });
  try {
    const result = parse('FRANKEN_ENV_SETTER=one\nFRANKEN_ENV_SETTER=two\nZ=z');
    return { values, result, own: Object.hasOwn(result, 'FRANKEN_ENV_SETTER') };
  } finally {
    if (old) Object.defineProperty(Object.prototype, 'FRANKEN_ENV_SETTER', old);
    else delete Object.prototype.FRANKEN_ENV_SETTER;
  }
}
assert.deepStrictEqual(inheritedSetter(implementation.parseEnv), inheritedSetter(util.parseEnv));
checks++;
compare(Array.from({ length: 20000 }, (_, i) => 'PACKAGE_' + i + '=version-' + i).reverse().join('\n'),
  'large package environment');
// Count logical '=' search spans, not wall-clock time or native instructions.
// The search must stay bounded to each physical line even when most lines are
// malformed and only the final row contains a separator.
const malformed = 'not-an-assignment\n'.repeat(50000) + 'VALID=last';
const indexOf = String.prototype.indexOf;
let separatorSpan = 0;
String.prototype.indexOf = function (search, from = 0) {
  if (search === '=') separatorSpan += Math.max(0, this.length - from);
  return Reflect.apply(indexOf, this, [search, from]);
};
try { assert.deepStrictEqual(implementation.parseEnv(malformed), { VALID: 'last' }); }
finally { String.prototype.indexOf = indexOf; }
assert.ok(separatorSpan <= malformed.length, 'malformed lines must not rescan the remaining file');
compare(malformed, 'large malformed environment');
checks++;
console.log(JSON.stringify({ suite: 'engine util.parseEnv host differential', node: process.version,
  checks, separator_search_span: separatorSpan, native_engine_verified: false, bun_verified: false }));
