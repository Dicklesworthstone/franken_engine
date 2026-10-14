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
  const values = Array.prototype.values;
  const iterator = Symbol.iterator;
  const defineProperty = Object.defineProperty;
  const create = Object.create;

  async function blob(stream) {
    const parts = [];
    // The private list must not consult a replaced Array iterator when Blob
    // copies it. Chunk coercion itself remains observable, as for new Blob.
    const descriptor = create(null);
    descriptor.value = values;
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
    const parts = [];
    for await (const chunk of stream) {
      // String chunks are already decoded. Do not flush pending byte state
      // between them: a later byte chunk can complete the previous codepoint.
      const part = typeof chunk === 'string' ? chunk : apply(decode, decoder, [chunk, { stream: true }]);
      apply(push, parts, [part]);
    }
    apply(push, parts, [apply(decode, decoder, [])]);
    // One final join avoids repeatedly copying the accumulated output for
    // highly fragmented input. Collection is explicit in this API.
    return apply(join, parts, ['']);
  }

  async function json(stream) {
    return parse(await text(stream));
  }

  return { arrayBuffer: arrayBuffer, blob: blob, buffer: buffer, text: text, json: json };
})()
