(function () {
  'use strict';
  // Node's buffer module over the realm's Buffer, atob, btoa and Blob
  // (bd-305gi.3). It reads only standard globals and needs no authority.
  var MAX_LENGTH = 9007199254740991;
  var MAX_STRING_LENGTH = 536870888;
  var typedPrototype = Object.getPrototypeOf(Uint8Array.prototype);
  var typedBuffer = Object.getOwnPropertyDescriptor(typedPrototype, 'buffer').get;
  var typedOffset = Object.getOwnPropertyDescriptor(typedPrototype, 'byteOffset').get;
  var typedLength = Object.getOwnPropertyDescriptor(typedPrototype, 'byteLength').get;
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
    if (encoding === undefined || encoding === null || encoding === '') return 'utf8';
    if (typeof encoding !== 'string') return null;
    switch (encoding.toLowerCase()) {
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
  function transcodeError(code, errno) {
    var error = new Error('Unable to transcode Buffer [' + code + ']');
    error.code = code;
    error.errno = errno;
    return error;
  }
  function transcode(source, fromEncoding, toEncoding) {
    if (!ArrayBuffer.isView(source) || !(source instanceof Uint8Array)) {
      throw invalidArgument('source', source);
    }
    // The source is a byte view, not an array-like. Own buffer/offset/length
    // properties must not redirect conversion to a different allocation.
    var bytes = Buffer.from(typedBuffer.call(source), typedOffset.call(source), typedLength.call(source));
    // Node returns a fresh empty Buffer before examining either encoding.
    if (bytes.length === 0) return Buffer.alloc(0);
    var from = encodingName(fromEncoding);
    var to = encodingName(toEncoding);
    if (from === null || to === null) {
      throw transcodeError('U_ILLEGAL_ARGUMENT_ERROR', 1);
    }
    // This identity conversion is a byte copy, not a decode/re-encode. It
    // retains snapshot semantics without a source-sized intermediate string.
    if (from === 'latin1' && to === 'latin1') return Buffer.from(bytes);
    var text;
    if ((from === 'utf8' && to === 'utf16le') || (from === 'utf16le' && to === 'utf8')) {
      // Node's Unicode-to-Unicode fast paths reject malformed input rather
      // than inserting substitution characters. The UTF-16 -> UTF-8 path
      // consumes complete code units only, but refuses a nonempty byte-only
      // input. A BOM is data here, unlike TextDecoder's default behavior.
      var input = from === 'utf16le' ? bytes.subarray(0, bytes.length - bytes.length % 2) : bytes;
      if (input.length === 0) throw transcodeError('U_INVALID_CHAR_FOUND', 10);
      try {
        text = new TextDecoder(from === 'utf16le' ? 'utf-16le' : 'utf-8', { fatal: true, ignoreBOM: true }).decode(input);
      } catch (error) {
        throw transcodeError('U_INVALID_CHAR_FOUND', 10);
      }
    } else if (from === 'utf16le' && to === 'utf16le') {
      // The identity UTF-16 conversion still repairs lone surrogates and
      // truncated code units; a byte copy would silently preserve them.
      text = new TextDecoder('utf-16le', { ignoreBOM: true }).decode(bytes);
    } else if (from === 'ascii') {
      // Buffer.toString('ascii') masks the high bit. ICU transcoding instead
      // substitutes invalid ASCII, except the byte-widening UTF-16 path.
      text = bytes.toString('latin1');
      if (to !== 'utf16le') text = text.replace(/[\x80-\xff]/g, '\ufffd');
    } else {
      text = bytes.toString(from);
    }
    // ICU omits unrepresentable Default_Ignorable_Code_Point characters.
    // Soft hyphen is the only such character representable in Latin-1, so
    // retain it for that target. Keep this a native regexp operation, not a
    // guest callback per character in a potentially large input.
    if (to === 'ascii' || to === 'latin1') {
      text = text.replace(/[\u034f\u061c\u115f-\u1160\u17b4-\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}\u{e0000}-\u{e0fff}]/gu, '');
      if (to === 'ascii') text = text.replace(/\u00ad/g, '');
    }
    // One substitution per Unicode scalar, not one per surrogate. The `u`
    // flag also treats an unpaired surrogate as one unrepresentable value.
    if (to === 'ascii') {
      text = text.replace(/[^\x00-\x7f]/gu, '?');
    } else if (to === 'latin1') {
      text = text.replace(/[^\x00-\xff]/gu, '?');
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
