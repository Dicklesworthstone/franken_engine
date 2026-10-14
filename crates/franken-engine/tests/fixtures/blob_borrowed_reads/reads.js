// Run by HybridRouter and directly under Node v22.16.0 as the reference.
async function checkBlobReads() {
  var checked = 0;
  function same(name, actual, expected) {
    if (actual !== expected) throw new Error(name + ': ' + JSON.stringify(actual) + ' !== ' + JSON.stringify(expected));
    checked++;
  }
  function bytes(hex) {
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  async function hex(blob) {
    var input = new Uint8Array(await blob.arrayBuffer());
    var out = '';
    for (var i = 0; i < input.length; i++) out += input[i].toString(16).padStart(2, '0');
    return out;
  }
  var cases = [
    ['', ''],
    ['efbbbf41', 'A'],
    ['efbbbfefbbbf41', '\ufeffA'],
    ['41efbbbf', 'A\ufeff'],
    ['fffe4100', '\ufffd\ufffdA\0'],
    ['e282', '\ufffd'],
    ['efbb', '\ufffd'],
    ['ff00f09f9880', '\ufffd\0😀'],
    ['eda080', '\ufffd\ufffd\ufffd'],
    ['f4908080', '\ufffd\ufffd\ufffd\ufffd']
  ];
  for (var i = 0; i < cases.length; i++) {
    var blob = new Blob([bytes(cases[i][0])], { type: 'text/plain;charset=utf-16le' });
    same('decoded text ' + i, await blob.text(), cases[i][1]);
    same('unchanged raw bytes ' + i, await hex(blob), cases[i][0]);
  }
  var parts = ['\ud83d', '\ude00', '\ud83d' + '\ude00', '\0aé€'];
  var fromStrings = new Blob(parts, { type: 'TEXT/PLAIN' });
  same('part normalization', await hex(fromStrings), 'efbfbdefbfbdf09f98800061c3a9e282ac');
  same('type normalization', fromStrings.type, 'text/plain');
  var sourceBytes = bytes('ff4142434445ff');
  var view = new Uint8Array(sourceBytes.buffer, 1, 5);
  var fromView = new Blob([view]);
  sourceBytes.fill(0);
  same('input view snapshot', await fromView.text(), 'ABCDE');
  var slices = [[0, 1, 'A'], [1, 4, 'BCD'], [-2, 99, 'DE'], [4, 1, ''], [-99, -1, 'ABCD']];
  for (var i = 0; i < slices.length; i++) {
    var slice = fromView.slice(slices[i][0], slices[i][1], 'TEXT/CUSTOM');
    same('slice content ' + i, await slice.text(), slices[i][2]);
    same('slice type ' + i, slice.type, 'text/custom');
  }
  var exported = new Uint8Array(await fromView.arrayBuffer());
  exported.fill(0);
  same('output buffer independence', await fromView.text(), 'ABCDE');
  var converting = new Blob(['ABCDE']);
  var order = '';
  var converted = converting.slice({ valueOf: function () {
    order += 'start;';
    converting = null;
    for (var i = 0; i < 16; i++) new Blob(['temporary']);
    return 1;
  } }, { valueOf: function () { order += 'end;'; return 4; } });
  same('conversion order', order, 'start;end;');
  same('receiver survives conversion', await converted.text(), 'BCD');
  var large = new Blob(['x'.repeat(262144)]);
  var total = 0;
  for (var i = 0; i < 64; i++) total += large.slice(i * 4096, i * 4096 + 1).size;
  same('tiny slices from large blob', total, 64);
  same('source still intact', large.size, 262144);
  var rejected = false;
  try { await Blob.prototype.text.call({}); } catch (error) { rejected = error instanceof TypeError; }
  same('text receiver brand', rejected, true);
  rejected = false;
  try { Blob.prototype.slice.call({}, 0, 0); } catch (error) { rejected = error instanceof TypeError; }
  same('slice receiver brand', rejected, true);
  console.log('blob borrowed reads: ' + checked + ' checks');
}
checkBlobReads().catch(function (error) { console.log('FAIL: ' + error.message); });
