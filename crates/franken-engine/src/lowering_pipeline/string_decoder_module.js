(function () {
  'use strict';
  // Keep only a four-byte carry buffer per decoder. Complete input is decoded
  // directly by the native Buffer codec: never retain an incoming chunk or
  // concatenate it with all preceding input. State is weakly owned by its
  // decoder and cannot be forged by changing the public encoding property.
  var states = new WeakMap();
  var apply = Reflect.apply;
  var getState = WeakMap.prototype.get;
  var setState = WeakMap.prototype.set;
  var from = Buffer.from;
  var alloc = Buffer.alloc;
  var decode = Buffer.prototype.toString;
  var slice = Buffer.prototype.subarray;
  var isView = ArrayBuffer.isView;
  var lower = String.prototype.toLowerCase;
  var typedPrototype = Object.getPrototypeOf(Uint8Array.prototype);
  var typedBuffer = Object.getOwnPropertyDescriptor(typedPrototype, 'buffer').get;
  var typedOffset = Object.getOwnPropertyDescriptor(typedPrototype, 'byteOffset').get;
  var typedLength = Object.getOwnPropertyDescriptor(typedPrototype, 'byteLength').get;
  var dataBuffer = Object.getOwnPropertyDescriptor(DataView.prototype, 'buffer').get;
  var dataOffset = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteOffset').get;
  var dataLength = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteLength').get;

  function error(code, message) {
    var result = new TypeError(message);
    result.code = code;
    return result;
  }
  function normalize(encoding) {
    if (encoding === undefined || encoding === null || encoding === '') { return 'utf8'; }
    if (typeof encoding !== 'string') { throw error('ERR_UNKNOWN_ENCODING', 'Unknown encoding'); }
    var name = apply(lower, encoding, []);
    if (name === 'utf8' || name === 'utf-8') { return 'utf8'; }
    if (name === 'utf16le' || name === 'utf-16le' || name === 'ucs2' || name === 'ucs-2') {
      return 'utf16le';
    }
    if (name === 'latin1' || name === 'binary') { return 'latin1'; }
    if (name === 'ascii' || name === 'hex' || name === 'base64' || name === 'base64url') { return name; }
    throw error('ERR_UNKNOWN_ENCODING', 'Unknown encoding: ' + encoding);
  }
  function state(receiver) {
    var result = apply(getState, states, [receiver]);
    if (result === undefined) { throw error('ERR_INVALID_THIS', 'Expected a StringDecoder receiver'); }
    return result;
  }
  function bytes(input) {
    if (!isView(input)) {
      throw error('ERR_INVALID_ARG_TYPE', 'Expected a string, Buffer, TypedArray or DataView');
    }
    // A view exposes its raw bytes, not its element values. Use authenticated
    // native getters so own buffer/offset/length properties cannot redirect it.
    var backing;
    var offset;
    var length;
    try {
      backing = apply(typedBuffer, input, []);
      offset = apply(typedOffset, input, []);
      length = apply(typedLength, input, []);
    } catch (failure) {
      backing = apply(dataBuffer, input, []);
      offset = apply(dataOffset, input, []);
      length = apply(dataLength, input, []);
    }
    return from(backing, offset, length);
  }
  function text(buffer, encoding, start, end) {
    return apply(decode, buffer, [encoding, start, end]);
  }
  function continuation(byte) { return (byte & 192) === 128; }
  function width(byte) {
    if (byte >= 192 && byte < 224) { return 2; }
    if (byte >= 224 && byte < 240) { return 3; }
    if (byte >= 240 && byte < 248) { return 4; }
    return 0;
  }
  function writeBytes(s, buffer) {
    var offset = 0;
    var length = buffer.length;
    var output = '';
    if (length === 0) { return output; }
    if (s.have > 0) {
      while (s.have < s.total && offset < length) {
        // A non-continuation ends an incomplete UTF-8 sequence. Decode that
        // prefix as malformed, then reconsider this byte as new input.
        if (s.encoding === 'utf8' && !continuation(buffer[offset])) { break; }
        s.carry[s.have++] = buffer[offset++];
      }
      if (s.have < s.total && offset === length) { return output; }
      output = text(s.carry, s.encoding, 0, s.have);
      s.have = 0;
      s.total = 0;
    }
    if (offset === length) { return output; }
    var end = length;
    var total = 0;
    if (s.encoding === 'utf8') {
      var start = length - 1;
      var count = 0;
      while (start >= offset && continuation(buffer[start]) && count < 3) {
        start--;
        count++;
      }
      if (start >= offset) {
        var expected = width(buffer[start]);
        if (expected > length - start) { end = start; total = expected; }
      }
    } else if (s.encoding === 'utf16le') {
      if ((length - offset) % 2 !== 0) {
        end = length - 1;
        total = 2;
      } else if (buffer[length - 1] >= 216 && buffer[length - 1] <= 219) {
        // At an even boundary retain the trailing high surrogate. At an odd
        // boundary the already-complete code units are returned as in Node.
        end = length - 2;
        total = 4;
      }
    } else if (s.encoding === 'base64' || s.encoding === 'base64url') {
      var remainder = (length - offset) % 3;
      if (remainder !== 0) { end = length - remainder; total = 3; }
    }
    output += text(buffer, s.encoding, offset, end);
    if (end !== length) {
      s.have = length - end;
      s.total = total;
      for (var i = 0; i < s.have; i++) { s.carry[i] = buffer[end + i]; }
    }
    return output;
  }
  function StringDecoder(encoding) {
    var normalized = normalize(encoding);
    this.encoding = normalized;
    apply(setState, states, [this, {
      encoding: normalized, carry: alloc(4), have: 0, total: 0
    }]);
  }
  StringDecoder.prototype.write = function write(input) {
    // Strings are already decoded; they do not consume a pending byte prefix.
    if (typeof input === 'string') { return input; }
    return writeBytes(state(this), bytes(input));
  };
  StringDecoder.prototype.end = function end(input) {
    var output = input === undefined ? '' : this.write(input);
    var s = state(this);
    if (s.have > 0) { output += text(s.carry, s.encoding, 0, s.have); }
    s.have = 0;
    s.total = 0;
    return output;
  };
  // Node also exposes text() and read-only carry-state accessors. text starts
  // a fresh byte sequence; it does not append to a prefix from a previous write.
  StringDecoder.prototype.text = function text(input, offset) {
    var s = state(this);
    s.have = 0;
    s.total = 0;
    return this.write(input.slice(offset));
  };
  Object.defineProperty(StringDecoder.prototype, 'lastChar', {
    enumerable: true, configurable: true, get: function get() { return apply(slice, state(this).carry, [0, 4]); }
  });
  Object.defineProperty(StringDecoder.prototype, 'lastNeed', {
    enumerable: true, configurable: true, get: function get() { var s = state(this); return s.total - s.have; }
  });
  Object.defineProperty(StringDecoder.prototype, 'lastTotal', {
    enumerable: true, configurable: true, get: function get() { return state(this).total; }
  });
  return { StringDecoder: StringDecoder };
})()
