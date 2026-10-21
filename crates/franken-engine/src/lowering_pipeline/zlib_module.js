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
  const exports = {
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
