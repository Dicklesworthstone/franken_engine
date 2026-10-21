(function () {
  'use strict';
  // First-class exports over the existing bounded native codecs. Keep codec
  // work, deferred callback delivery, provenance and limits in their current
  // owners. These functions introduce no host I/O or alternate compression.
  function gzipSync(input, options) { return __franken_zlib_gzip_sync(input, options); }
  function gunzipSync(input, options) { return __franken_zlib_gunzip_sync(input, options); }
  function deflateSync(input, options) { return __franken_zlib_deflate_sync(input, options); }
  function inflateSync(input, options) { return __franken_zlib_inflate_sync(input, options); }
  function deflateRawSync(input, options) { return __franken_zlib_deflate_raw_sync(input, options); }
  function inflateRawSync(input, options) { return __franken_zlib_inflate_raw_sync(input, options); }
  function unzipSync(input, options) { return __franken_zlib_unzip_sync(input, options); }
  function brotliCompressSync(input, options) { return __franken_zlib_brotli_compress_sync(input, options); }
  function brotliDecompressSync(input, options) { return __franken_zlib_brotli_decompress_sync(input, options); }
  // Preserve the exact native two/three argument overload. In particular,
  // passing an extra undefined must not displace the callback in native code.
  // Do not wrap/catch the callback: the native I/O completion lane owns its
  // label, exactly-once delivery and exceptions from user code.
  function gzip(input, options, callback) {
    if (typeof options === 'function') return __franken_zlib_gzip(input, options);
    return __franken_zlib_gzip(input, options, callback);
  }
  function gunzip(input, options, callback) {
    if (typeof options === 'function') return __franken_zlib_gunzip(input, options);
    return __franken_zlib_gunzip(input, options, callback);
  }
  function deflate(input, options, callback) {
    if (typeof options === 'function') return __franken_zlib_deflate(input, options);
    return __franken_zlib_deflate(input, options, callback);
  }
  function inflate(input, options, callback) {
    if (typeof options === 'function') return __franken_zlib_inflate(input, options);
    return __franken_zlib_inflate(input, options, callback);
  }
  // CRC32 is a data-integrity checksum, not cryptographic authentication.
  // Keep its table private and lazy: importing compression or checksumming
  // an empty chunk does not allocate the table. The ordinary interpreter
  // charges these byte operations and the 1 KiB typed-array allocation.
  const apply = Reflect.apply;
  const charCodeAt = String.prototype.charCodeAt;
  const isView = ArrayBuffer.isView;
  const ByteView = Uint8Array;
  const Words = Uint32Array;
  const Type = TypeError;
  const Range = RangeError;
  const viewPrototype = Object.getPrototypeOf(ByteView.prototype);
  const getOwnDescriptor = Object.getOwnPropertyDescriptor;
  const typedBuffer = getOwnDescriptor(viewPrototype, 'buffer').get;
  const typedOffset = getOwnDescriptor(viewPrototype, 'byteOffset').get;
  const typedLength = getOwnDescriptor(viewPrototype, 'byteLength').get;
  const dataBuffer = getOwnDescriptor(DataView.prototype, 'buffer').get;
  const dataOffset = getOwnDescriptor(DataView.prototype, 'byteOffset').get;
  const dataLength = getOwnDescriptor(DataView.prototype, 'byteLength').get;
  let crcTable;
  function invalidCrcArgument(name) {
    const error = new Type('Invalid CRC32 ' + name + ' argument');
    error.code = 'ERR_INVALID_ARG_TYPE';
    return error;
  }
  function crc32(data, value) {
    // Use actual backing windows, never replaceable .buffer/.byteOffset/
    // .byteLength properties. Subclasses, Buffers and foreign-realm views
    // must checksum their own bytes rather than arbitrary decoy storage.
    const text = typeof data === 'string';
    if (!text && !isView(data)) throw invalidCrcArgument('data');
    if (value === undefined) value = 0;
    if (typeof value !== 'number') throw invalidCrcArgument('value');
    if (value < 0 || value > 4294967295 || value % 1 !== 0) {
      const error = new Range('CRC32 value must be an unsigned 32-bit integer');
      error.code = 'ERR_OUT_OF_RANGE';
      throw error;
    }
    let bytes, length;
    if (text) length = data.length;
    else {
      let buffer, typed = true;
      try { buffer = apply(typedBuffer, data, []); }
      catch (error) {
        typed = false;
        buffer = apply(dataBuffer, data, []);
      }
      const offset = apply(typed ? typedOffset : dataOffset, data, []);
      length = apply(typed ? typedLength : dataLength, data, []);
      // Construct even an empty window so detached storage fails explicitly.
      // A detached input must not silently reset an archive's rolling checksum.
      bytes = new ByteView(buffer, offset, length);
    }
    if (length === 0) return value >>> 0;
    if (crcTable === undefined) {
      const table = new Words(256);
      for (let i = 0; i < 256; i++) {
        let entry = i;
        for (let bit = 0; bit < 8; bit++) {
          entry = (entry >>> 1) ^ ((entry & 1) === 0 ? 0 : 0xedb88320);
        }
        table[i] = entry >>> 0;
      }
      crcTable = table;
    }
    let crc = value ^ 0xffffffff;
    if (text) {
      // Feed UTF-8 directly from UTF-16 without a whole-string Buffer. A lone
      // surrogate encodes U+FFFD, and separate calls never share surrogate
      // carry. Reuse the private own-index argument list, not one per unit.
      const index = [0];
      for (let i = 0; i < length; i++) {
        index[0] = i;
        let code = apply(charCodeAt, data, index);
        if (code >= 0xd800 && code <= 0xdfff) {
          if (code <= 0xdbff && i + 1 < length) {
            index[0] = i + 1;
            const low = apply(charCodeAt, data, index);
            if (low >= 0xdc00 && low <= 0xdfff) {
              code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
              i++;
            } else code = 0xfffd;
          } else code = 0xfffd;
        }
        if (code < 0x80) {
          crc = (crc >>> 8) ^ crcTable[(crc ^ code) & 255];
        } else if (code < 0x800) {
          crc = (crc >>> 8) ^ crcTable[(crc ^ (0xc0 | (code >>> 6))) & 255];
          crc = (crc >>> 8) ^ crcTable[(crc ^ (0x80 | (code & 63))) & 255];
        } else {
          if (code >= 0x10000) {
            crc = (crc >>> 8) ^ crcTable[(crc ^ (0xf0 | (code >>> 18))) & 255];
            crc = (crc >>> 8) ^ crcTable[(crc ^ (0x80 | ((code >>> 12) & 63))) & 255];
          } else {
            crc = (crc >>> 8) ^ crcTable[(crc ^ (0xe0 | (code >>> 12))) & 255];
          }
          crc = (crc >>> 8) ^ crcTable[(crc ^ (0x80 | ((code >>> 6) & 63))) & 255];
          crc = (crc >>> 8) ^ crcTable[(crc ^ (0x80 | (code & 63))) & 255];
        }
      }
    } else {
      for (let i = 0; i < length; i++) {
        crc = (crc >>> 8) ^ crcTable[(crc ^ bytes[i]) & 255];
      }
    }
    return (crc ^ 0xffffffff) >>> 0;
  }
  const exports = {
    crc32: crc32,
    gzipSync: gzipSync, gunzipSync: gunzipSync,
    deflateSync: deflateSync, inflateSync: inflateSync,
    deflateRawSync: deflateRawSync, inflateRawSync: inflateRawSync,
    unzipSync: unzipSync,
    brotliCompressSync: brotliCompressSync, brotliDecompressSync: brotliDecompressSync,
    gzip: gzip, gunzip: gunzip, deflate: deflate, inflate: inflate
  };
  const descriptor = Object.create(null);
  // Reuse the native immutable constants bundle. No platform/version numbers
  // or unsupported codec constants are synthesized in this adapter.
  descriptor.value = __franken_zlib_constants();
  descriptor.enumerable = true;
  descriptor.writable = false;
  descriptor.configurable = false;
  Object.defineProperty(exports, 'constants', descriptor);
  return exports;
})()
