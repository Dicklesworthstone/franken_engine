(function installBinaryFiles(module) {
  'use strict';
  // File metadata is interpreter-owned state; payload storage and copying stay
  // in the realm's native Blob. No filesystem access, second byte store, or
  // external implementation is introduced by constructing a File.
  const BlobClass = module.Blob;
  const apply = Reflect.apply;
  const define = Object.defineProperty;
  const descriptor = Object.getOwnPropertyDescriptor;
  const own = Object.prototype.hasOwnProperty;
  const create = Object.create;
  const WeakMapClass = WeakMap;
  const weakGet = WeakMap.prototype.get;
  const weakSet = WeakMap.prototype.set;
  const iterator = Symbol.iterator;
  const tag = Symbol.toStringTag;
  const StringClass = String;
  const wellFormed = String.prototype.toWellFormed;
  const replace = String.prototype.replace;
  const now = Date.now;
  const nativeEol = process.platform === 'win32' ? '\r\n' : '\n';
  const isView = ArrayBuffer.isView;
  const bufferLength = descriptor(ArrayBuffer.prototype, 'byteLength').get;
  const blobSize = descriptor(BlobClass.prototype, 'size').get;
  const blobSlice = BlobClass.prototype.slice;
  const blobArrayBuffer = BlobClass.prototype.arrayBuffer;
  const Bytes = Uint8Array;
  const byteSet = Bytes.prototype.set;
  const typedLength = descriptor(Object.getPrototypeOf(Bytes.prototype), 'byteLength').get;
  let metadata;

  function error(code, message) {
    const value = new TypeError(message);
    value.code = code;
    return value;
  }
  function object(value) {
    return value !== null && (typeof value === 'object' || typeof value === 'function');
  }
  function string(value) {
    // String(symbol) accepts a Symbol, whereas Web IDL's ToString does not.
    if (typeof value === 'symbol') throw new TypeError('Cannot convert a Symbol value to a string');
    return StringClass(value);
  }
  function binary(value) {
    if (!object(value)) return false;
    if (isView(value)) return true;
    try { apply(bufferLength, value, []); return true; } catch (ignored) {}
    try { apply(blobSize, value, []); return true; } catch (ignored) {}
    return false;
  }
  function* normalizedParts(parts, native) {
    if (parts === undefined) return;
    // Yield one converted part at a time. The native Blob copies its bytes
    // before resuming this generator, so a producer may safely reuse a view.
    // String conversion failures also perform IteratorClose on that producer.
    for (const part of parts) {
      if (binary(part)) yield part;
      else {
        const text = string(part);
        // Node's native-ending conversion rewrites LF and CRLF, not bare CR.
        // Keep binary parts and boundaries between separate strings intact.
        yield native ? apply(replace, text, [/\r?\n/g, nativeEol]) : text;
      }
    }
  }
  function state(value) {
    const result = metadata === undefined ? undefined : apply(weakGet, metadata, [value]);
    if (result === undefined) throw new TypeError('Illegal invocation');
    return result;
  }
  function property(target, name, value) {
    const attributes = create(null);
    attributes.value = value;
    attributes.writable = true;
    attributes.configurable = true;
    attributes.enumerable = true;
    define(target, name, attributes);
  }

  if (!apply(own, module, ['File'])) {
    const RuntimeFile = class File extends BlobClass {
      constructor(fileBits, fileName, options = undefined) {
        if (arguments.length < 2) {
          throw error('ERR_MISSING_ARGS', 'The "fileBits" and "fileName" arguments must be specified');
        }
        // Node's File/Blob sequence validation precedes option getters. The
        // iterable is acquired again on consumption, matching the reference.
        if (fileBits !== undefined && (!object(fileBits) || typeof fileBits[iterator] !== 'function')) {
          throw error('ERR_INVALID_ARG_TYPE', 'The "sources" argument must be a sequence');
        }
        if (options == null) options = {};
        if (!object(options)) throw error('ERR_INVALID_ARG_TYPE', 'The "options" argument must be a dictionary');
        const type = options.type;
        const endingOption = options.endings;
        const endings = endingOption === undefined ? 'transparent' : string(endingOption);
        if (endings !== 'transparent' && endings !== 'native') {
          throw error('ERR_INVALID_ARG_VALUE', 'The property "options.endings" must be "transparent" or "native"');
        }
        let copied = false;
        function* sources() {
          yield* normalizedParts(fileBits, endings === 'native');
          copied = true;
        }
        // The engine's Blob reads type after copying parts, then accepts a
        // primitive string. Other native Blob implementations may capture the
        // value first and coerce it afterwards. Perform guest conversion only
        // on the former path; either way it happens once, after the last part.
        super(sources(), {
          get type() { return copied ? (type === undefined ? '' : string(type)) : type; },
          endings: 'transparent'
        });
        const modified = options.lastModified;
        // Unary + is ToNumber (unlike Number it rejects BigInt). Node retains
        // fractional and infinite timestamps, and maps NaN to zero.
        let timestamp = modified === undefined ? now() : +modified;
        if (timestamp !== timestamp) timestamp = 0;
        const name = apply(wellFormed, string(fileName), []);
        if (metadata === undefined) metadata = new WeakMapClass();
        apply(weakSet, metadata, [this, { name: name, lastModified: timestamp }]);
      }
      get name() { return state(this).name; }
      get lastModified() { return state(this).lastModified; }
    };
    function enumerable(name) {
      const attributes = descriptor(RuntimeFile.prototype, name);
      attributes.enumerable = true;
      define(RuntimeFile.prototype, name, attributes);
    }
    enumerable('name');
    enumerable('lastModified');
    const attributes = create(null);
    attributes.value = 'File'; attributes.configurable = true;
    define(RuntimeFile.prototype, tag, attributes);
    property(module, 'File', RuntimeFile);
  }
  // The byte-stream machinery is the same private module as stream/web. Its
  // constructor/protocols are acquired on first stream(), not on a Buffer
  // import or File construction. Loading that dependency confers no I/O.
  let protocols;
  function streamProtocols() {
    if (protocols === undefined) {
      const web = __franken_buffer_web_streams;
      const controller = web.ReadableByteStreamController.prototype;
      const request = web.ReadableStreamBYOBRequest.prototype;
      protocols = {
        Stream: web.ReadableStream,
        request: descriptor(request, 'view').get,
        controllerRequest: descriptor(controller, 'byobRequest').get,
        respond: request.respond,
        enqueue: controller.enqueue,
        close: controller.close
      };
    }
    return protocols;
  }
  function byteStream(payload, size) {
    const operations = streamProtocols();
    let offset = 0;
    let cancelled = false;
    function finish(controller) {
      payload = undefined;
      apply(operations.close, controller, []);
      // At EOF a BYOB read (including one with min > bytes available) still
      // owns its destination. Commit its final partial/empty result explicitly.
      const request = apply(operations.controllerRequest, controller, []);
      if (request !== null) apply(operations.respond, request, [0]);
    }
    return new operations.Stream({
      type: 'bytes',
      async pull(controller) {
        if (cancelled) return;
        if (offset === size) { finish(controller); return; }
        try {
          const request = apply(operations.controllerRequest, controller, []);
          const view = request === null ? undefined : apply(operations.request, request, []);
          let count = size - offset;
          if (count > 65536) count = 65536;
          if (view !== undefined) {
            const available = apply(typedLength, view, []);
            if (count > available) count = available;
          }
          // Only the demanded range is copied. A large immutable Blob is not
          // first converted to one whole ArrayBuffer, nor prefetched at load.
          const part = apply(blobSlice, payload, [offset, offset + count]);
          const bytes = new Bytes(await apply(blobArrayBuffer, part, []));
          if (cancelled) return;
          if (apply(typedLength, bytes, []) !== count) {
            throw new TypeError('Blob binary read returned an unexpected byte count');
          }
          offset += count;
          if (request === null) apply(operations.enqueue, controller, [bytes]);
          else {
            apply(byteSet, view, [bytes]);
            apply(operations.respond, request, [count]);
          }
          if (offset === size) finish(controller);
        } catch (failure) { payload = undefined; throw failure; }
      },
      cancel() { cancelled = true; payload = undefined; }
    }, { highWaterMark: 0 });
  }
  if (typeof BlobClass.prototype.stream !== 'function') {
    property(BlobClass.prototype, 'stream', function stream() {
      // Authenticate before acquiring the stream dependency. Own size/slice/
      // arrayBuffer properties cannot substitute bytes or redirect the reader.
      return byteStream(this, apply(blobSize, this, []));
    });
  }
  return module;
})
