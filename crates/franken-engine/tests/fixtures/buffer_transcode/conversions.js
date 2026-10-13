// Executed through the engine's real script-goal require rewrite and by the
// source-level differential runner. Expected bytes/errors: Node v22.16.0.
var bufferModule = require('node:buffer');
var transcode = bufferModule.transcode;
var checked = 0;
function same(name, actual, expected) {
  if (actual !== expected) throw new Error(name + ': expected ' + expected + ', got ' + actual);
  checked++;
}
function convert(hex, from, to) {
  try { return transcode(Buffer.from(hex, 'hex'), from, to).toString('hex'); }
  catch (error) { return error.name + ':' + error.code + ':' + error.errno; }
}
var cases = [
  ['utf8 astral ascii', '41f09f9880c3a9e282ac', 'utf8', 'ascii', '413f3f3f'],
  ['utf8 astral latin1', '41f09f9880c3a9e282ac', 'utf8', 'latin1', '413fe93f'],
  ['utf16 astral ascii', '41003dd800dee900ac20', 'ucs2', 'ascii', '413f3f3f'],
  ['utf16 astral latin1', '41003dd800dee900ac20', 'utf16le', 'latin1', '413fe93f'],
  ['unicode roundtrip', '41f09f9880c3a9', 'UTF-8', 'UTF-16LE', '41003dd800dee900'],
  ['utf16 roundtrip', '41003dd800dee900', 'UCS-2', 'utf8', '41f09f9880c3a9'],
  ['ascii does not mask', '4180ff', 'ascii', 'utf8', '41efbfbdefbfbd'],
  ['ascii substitutions', '4180ff', 'ascii', 'ascii', '413f3f'],
  ['ascii latin1 substitutions', '4180ff', 'ascii', 'binary', '413f3f'],
  ['ascii widening', '4180ff', 'ascii', 'ucs2', '41008000ff00'],
  ['latin1 widening', '4180ff', 'binary', 'ucs2', '41008000ff00'],
  ['latin1 utf8', '4180ff', 'latin1', 'utf8', '41c280c3bf'],
  ['latin1 copy', '0080adff', 'binary', 'LATIN1', '0080adff'],
  ['invalid utf8 repaired', '80ffe282', 'utf8', 'utf8', 'efbfbdefbfbdefbfbd'],
  ['invalid utf8 substitution', '80ffe282', 'utf8', 'ascii', '3f3f3f'],
  ['invalid utf8 refused', '80ff', 'utf8', 'ucs2', 'Error:U_INVALID_CHAR_FOUND:10'],
  ['truncated utf8 refused', 'e282', 'utf8', 'utf16le', 'Error:U_INVALID_CHAR_FOUND:10'],
  ['high surrogate refused', '00d8', 'utf16le', 'utf8', 'Error:U_INVALID_CHAR_FOUND:10'],
  ['low surrogate refused', '00dc', 'utf16le', 'utf8', 'Error:U_INVALID_CHAR_FOUND:10'],
  ['byte-only utf16 refused', '41', 'utf16le', 'utf8', 'Error:U_INVALID_CHAR_FOUND:10'],
  ['utf16 complete units', '4100ff', 'utf16le', 'utf8', '41'],
  ['utf16 identity repairs', '00d84100ff', 'utf16le', 'utf16le', 'fdff4100fdff'],
  ['utf16 byte-only repairs', '41', 'utf16le', 'ucs2', 'fdff'],
  ['utf16 trailing byte to ascii', '4100ff', 'utf16le', 'ascii', '41'],
  ['utf8 BOM is data', 'efbbbf41', 'utf8', 'utf16le', 'fffe4100'],
  ['utf16 BOM is data', 'fffe4100', 'utf16le', 'utf8', 'efbbbf41'],
  ['utf16 BOM identity', 'fffe4100', 'utf16le', 'utf16le', 'fffe4100'],
  ['ignorables ascii', '41c2adcdaff3a0808062', 'utf8', 'ascii', '413f62'],
  ['soft hyphen ascii', '41ad42', 'latin1', 'ascii', '4142'],
  ['soft hyphen latin1', '41c2ad42', 'utf8', 'latin1', '41ad42'],
  ['variation selector', '41efb88f42', 'utf8', 'latin1', '4142'],
  ['invalid encoding', '41', 'base64', 'utf8', 'Error:U_ILLEGAL_ARGUMENT_ERROR:1'],
  ['nonstring encoding', '41', false, 'utf8', 'Error:U_ILLEGAL_ARGUMENT_ERROR:1'],
  ['default encoding', '41', undefined, null, '41']
];
for (var i = 0; i < cases.length; i++) {
  var item = cases[i];
  same(item[0], convert(item[1], item[2], item[3]), item[4]);
}
var conversions = 0;
var badEncoding = { toString: function () { conversions++; throw new Error('encoding coerced'); } };
same('empty short circuit', transcode(new Uint8Array(0), badEncoding, badEncoding).length, 0);
same('empty has no coercion', conversions, 0);
same('object encoding', convert('41', badEncoding, 'utf8'), 'Error:U_ILLEGAL_ARGUMENT_ERROR:1');
same('nonempty has no coercion', conversions, 0);
var backing = new Uint8Array([0xff, 0x41, 0xc3, 0xa9, 0xff]);
var view = new Uint8Array(backing.buffer, 1, 3);
Object.defineProperty(view, 'buffer', { get: function () { throw new Error('own buffer read'); } });
Object.defineProperty(view, 'byteOffset', { value: 0 });
Object.defineProperty(view, 'byteLength', { value: 5 });
same('intrinsic view bounds', transcode(view, 'utf8', 'latin1').toString('hex'), '41e9');
var original = Buffer.from([0, 0x80, 0xff]);
var copied = transcode(original, 'latin1', 'binary');
copied[1] = 0;
same('copy isolation', original.toString('hex'), '0080ff');
same('result is Buffer', Buffer.isBuffer(copied), true);
var originalToString = Buffer.prototype.toString;
var directCopy;
try {
  Buffer.prototype.toString = function () { throw new Error('identity conversion decoded'); };
  directCopy = transcode(original, 'latin1', 'latin1');
} finally {
  Buffer.prototype.toString = originalToString;
}
same('identity avoids decode', directCopy.toString('hex'), '0080ff');
console.log('buffer transcode: ' + checked + ' checks');
