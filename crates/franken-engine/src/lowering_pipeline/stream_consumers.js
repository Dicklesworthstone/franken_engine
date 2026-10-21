(function () {
  'use strict';
  // Consume through the language's iterator protocol, not a host stream shim.
  // Binary collection shares the realm's immutable Blob implementation and
  // text uses its incremental UTF-8 decoder, including the final flush.
  const BlobClass = Blob;
  const blobArrayBuffer = BlobClass.prototype.arrayBuffer;
  const BufferClass = Buffer;
  const bufferFrom = BufferClass.from;
  const Decoder = TextDecoder;
  const decode = Decoder.prototype.decode;
  const parse = JSON.parse;
  const apply = Reflect.apply;
  const push = Array.prototype.push;
  const join = Array.prototype.join;
  const iterator = Symbol.iterator;
  const defineProperty = Object.defineProperty;
  const create = Object.create;
  const setPrototype = Object.setPrototypeOf;

  function privateList() {
    // push/join are captured, but their indexed access still observes the
    // receiver's prototype. Never expose private chunks to inherited setters
    // or getters, including ones installed while a producer is suspended.
    return setPrototype([], null);
  }

  async function blob(stream) {
    const parts = privateList();
    // Own the complete cursor protocol, not just Symbol.iterator. Capturing
    // Array.prototype.values alone still lets a replaced iterator-prototype
    // next/return intercept this private list when Blob copies it. Caller
    // chunk coercion and the source iterator remain observable and unchanged.
    const descriptor = create(null);
    descriptor.value = function () {
      const cursor = create(null);
      let index = 0;
      cursor.next = function () {
        return index < parts.length
          ? { value: parts[index++], done: false }
          : { value: undefined, done: true };
      };
      return cursor;
    };
    defineProperty(parts, iterator, descriptor);
    for await (const chunk of stream) apply(push, parts, [chunk]);
    return new BlobClass(parts);
  }

  async function arrayBuffer(stream) {
    return apply(blobArrayBuffer, await blob(stream), []);
  }

  async function buffer(stream) {
    // The returned ArrayBuffer is fresh and private; expose its bytes through
    // a Buffer view rather than copying the collected payload a second time.
    return apply(bufferFrom, BufferClass, [await arrayBuffer(stream)]);
  }

  async function text(stream) {
    const decoder = new Decoder();
    const parts = privateList();
    const fragments = privateList();
    let fragmentUnits = 0;
    // Retained metadata must follow output, not the number of reads. In
    // particular, empty input and incomplete UTF-8 prefixes produce no entry.
    // Bound both fragment count and code units before joining a small batch.
    // Large decoded chunks pass through without an intermediate string copy;
    // small strings participate in at most one batch join and the final join.
    function flush() {
      if (fragments.length !== 0) {
        const part = fragments.length === 1 ? fragments[0] : apply(join, fragments, ['']);
        apply(push, parts, [part]);
        fragments.length = 0;
        fragmentUnits = 0;
      }
    }
    function append(part) {
      // A replaced codec may return a non-string. Preserve the previous
      // deferred Array.join coercion (and its order), rather than inspecting
      // an arbitrary .length or invoking a conversion while pulling input.
      if (typeof part !== 'string') {
        flush();
        apply(push, parts, [part]);
      } else if (part.length !== 0) {
        if (part.length >= 16384) {
          flush();
          apply(push, parts, [part]);
        } else {
          apply(push, fragments, [part]);
          fragmentUnits += part.length;
          if (fragments.length >= 64 || fragmentUnits >= 16384) flush();
        }
      }
    }
    for await (const chunk of stream) {
      // String chunks are already decoded. Do not flush pending byte state
      // between them: a later byte chunk can complete the previous codepoint.
      const part = typeof chunk === 'string' ? chunk : apply(decode, decoder, [chunk, { stream: true }]);
      append(part);
    }
    append(apply(decode, decoder, []));
    flush();
    return apply(join, parts, ['']);
  }

  async function json(stream) {
    return parse(await text(stream));
  }

  return { arrayBuffer: arrayBuffer, blob: blob, buffer: buffer, text: text, json: json };
})()
