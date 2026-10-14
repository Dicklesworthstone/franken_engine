// __case is supplied by the native test or reference runner, not guest I/O.
// The same program checks the public constructor, input views and streaming API.
(function () {
  const entry = __case;
  function check(ok, detail) { if (!ok) throw new Error(entry.name + ': ' + detail); }
  function expected(byte) { return byte < 128 ? byte : entry.high[byte - 128] === null ? 65533 : entry.high[byte - 128]; }
  function checkText(text, bytes) {
    check(text.length === bytes.length, 'decoded length');
    for (let i = 0; i < bytes.length; i++) {
      check(text.charCodeAt(i) === expected(bytes[i]), 'byte ' + bytes[i] + ': ' + text.charCodeAt(i));
    }
  }
  for (const label of entry.labels) {
    const decoder = new TextDecoder('\t ' + label.toUpperCase() + '\r\n');
    check(decoder.encoding === entry.name, 'canonical label ' + label);
    check(decoder.fatal === false && decoder.ignoreBOM === false, 'default options');
  }
  const storage = new Uint8Array(260);
  for (let i = 0; i < 256; i++) storage[i + 2] = i;
  const bytes = storage.subarray(2, 258);
  const view = new DataView(storage.buffer, 2, 256);
  checkText(new TextDecoder(entry.name).decode(view), bytes);
  checkText(new TextDecoder(entry.name).decode(bytes), bytes);
  checkText(new TextDecoder(entry.name).decode(bytes.slice().buffer), bytes);
  for (const ignoreBOM of [false, true]) {
    const decoder = new TextDecoder(entry.name, { ignoreBOM });
    let joined = '';
    for (let i = 0; i < bytes.length; i++) {
      const single = decoder.decode(bytes.subarray(i, i + 1), { stream: true });
      check(single.length === 1 && single.charCodeAt(0) === expected(bytes[i]), 'stream byte ' + i);
      joined += single;
    }
    check(decoder.decode() === '', 'flush must be empty');
    checkText(joined, bytes);
  }
  const fatal = new TextDecoder(entry.name, { fatal: true });
  let undefinedCount = 0;
  for (let i = 0; i < 256; i++) {
    const missing = i >= 128 && entry.high[i - 128] === null;
    let threw = false;
    try {
      const text = fatal.decode(bytes.subarray(i, i + 1), { stream: true });
      check(!missing, 'undefined byte accepted ' + i);
      checkText(text, [i]);
    } catch (error) {
      if (!missing || !(error instanceof TypeError)) throw error;
      threw = true;
    }
    check(threw === missing, 'fatal status ' + i);
    if (missing) undefinedCount++;
    check(fatal.decode(new Uint8Array([65])) === 'A', 'fatal decoder reuse');
  }
  check(fatal.decode() === '', 'fatal flush');
  const bom = new Uint8Array([239, 187, 191]);
  checkText(new TextDecoder(entry.name).decode(bom), bom);
  checkText(new TextDecoder(entry.name, { ignoreBOM: true }).decode(bom), bom);
  for (const label of ['\u00a0' + entry.name, entry.name + '\u000b', entry.name + '\uFEFF']) {
    let threw = false;
    try { new TextDecoder(label); } catch (error) { threw = error instanceof RangeError; }
    check(threw, 'non-ASCII whitespace must not be trimmed');
  }
  console.log('LEGACY_SINGLE_BYTE_OK ' + entry.name + ' ' + undefinedCount);
})();
