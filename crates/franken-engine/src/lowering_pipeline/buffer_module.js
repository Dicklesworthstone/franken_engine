(function () {
  'use strict';
  // Node's buffer module over the realm's Buffer, atob, btoa and Blob
  // (bd-305gi.3). It reads only standard globals and needs no authority.
  var MAX_LENGTH = 9007199254740991;
  var MAX_STRING_LENGTH = 536870888;
  function invalidArgument(name, value) {
    var error = new TypeError('The "' + name + '" argument must be an instance of ' +
      'Buffer, TypedArray, or ArrayBuffer. Received ' + (value === null ? 'null' : typeof value));
    error.code = 'ERR_INVALID_ARG_TYPE';
    return error;
  }
  function bytesOf(name, input) {
    if (input instanceof ArrayBuffer) {
      return new Uint8Array(input);
    }
    if (ArrayBuffer.isView(input)) {
      return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    }
    throw invalidArgument(name, input);
  }
  function SlowBuffer(size) {
    return Buffer.alloc(size);
  }
  function encodingName(encoding) {
    switch (String(encoding).toLowerCase()) {
      case 'utf8':
      case 'utf-8':
        return 'utf8';
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return 'utf16le';
      case 'latin1':
      case 'binary':
        return 'latin1';
      case 'ascii':
        return 'ascii';
      default:
        return null;
    }
  }
  function transcode(source, fromEncoding, toEncoding) {
    if (!(source instanceof Uint8Array)) {
      throw invalidArgument('source', source);
    }
    var from = encodingName(fromEncoding);
    var to = encodingName(toEncoding);
    if (from === null || to === null) {
      throw new Error('Unable to transcode Buffer [U_ILLEGAL_ARGUMENT_ERROR]');
    }
    var text = Buffer.from(source.buffer, source.byteOffset, source.byteLength).toString(from);
    if (to === 'ascii') {
      text = text.replace(/[^\x00-\x7f]/g, '?');
    } else if (to === 'latin1') {
      text = text.replace(/[^\x00-\xff]/g, '?');
    }
    return Buffer.from(text, to);
  }
  function isUtf8(input) {
    var bytes = bytesOf('input', input);
    try {
      new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      return true;
    } catch (error) {
      return false;
    }
  }
  function isAscii(input) {
    var bytes = bytesOf('input', input);
    for (var index = 0; index < bytes.length; index++) {
      if (bytes[index] > 0x7f) {
        return false;
      }
    }
    return true;
  }
  function resolveObjectURL() {
    return undefined;
  }
  var constants = {};
  Object.defineProperty(constants, 'MAX_LENGTH', { value: MAX_LENGTH, enumerable: true });
  Object.defineProperty(constants, 'MAX_STRING_LENGTH', { value: MAX_STRING_LENGTH, enumerable: true });
  var module = {
    Buffer: Buffer,
    SlowBuffer: SlowBuffer,
    transcode: transcode,
    isUtf8: isUtf8,
    isAscii: isAscii,
    kMaxLength: MAX_LENGTH,
    kStringMaxLength: MAX_STRING_LENGTH,
    btoa: btoa,
    atob: atob,
    constants: constants,
    INSPECT_MAX_BYTES: 50,
    Blob: Blob,
    resolveObjectURL: resolveObjectURL
  };
  if (typeof File === 'function') {
    module.File = File;
  }
  return module;
})()
