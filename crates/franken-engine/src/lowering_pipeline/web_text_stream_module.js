(function installTextStreams(Web) {
  'use strict';
  // Compose with the canonical TransformStream, not a second queue or codec.
  // TextDecoder's native carry/BOM state stays in the existing codec object;
  // UTF-8 encoding retains at most one leading surrogate between writes.
  const Encoder = TextEncoder;
  const Decoder = TextDecoder;
  const encode = TextEncoder.prototype.encode;
  const decode = TextDecoder.prototype.decode;
  const asString = String;
  const codeAt = String.prototype.charCodeAt;
  const slice = String.prototype.slice;
  const apply = Reflect.apply;
  const create = Object.create;
  const define = Object.defineProperty;
  const getDescriptor = Object.getOwnPropertyDescriptor;
  const Weak = WeakMap;
  const weakGet = WeakMap.prototype.get;
  const weakSet = WeakMap.prototype.set;
  const Invalid = TypeError;
  const tag = Symbol.toStringTag;
  const Transform = Web.TransformStream;
  const enqueue = Web.TransformStreamDefaultController.prototype.enqueue;
  const getReadable = getDescriptor(Transform.prototype, 'readable').get;
  const getWritable = getDescriptor(Transform.prototype, 'writable').get;
  const encoders = new Weak(), decoders = new Weak();

  function text(value) {
    // String(Symbol) is the special constructor form, not Web IDL ToString.
    if (typeof value === 'symbol') throw new Invalid('Cannot convert a Symbol to a string');
    return asString(value);
  }
  function state(map, receiver) {
    const value = apply(weakGet, map, [receiver]);
    if (value === undefined) throw new Invalid('Invalid text stream receiver');
    return value;
  }
  function install(object, name, value, enumerable) {
    const descriptor = create(null);
    descriptor.value = value; descriptor.writable = true; descriptor.configurable = true;
    descriptor.enumerable = enumerable === true;
    define(object, name, descriptor);
  }
  function publish(controller, value) {
    if (value.length !== 0) apply(enqueue, controller, [value]);
  }
  function endpoints(transform) {
    const record = create(null);
    record.readable = apply(getReadable, transform, []);
    record.writable = apply(getWritable, transform, []);
    return record;
  }
  class TextEncoderStream {
    constructor() {
      const encoder = new Encoder();
      let pending = '';
      const algorithms = create(null);
      algorithms.transform = function (chunk, controller) {
        let input = text(chunk);
        if (input.length === 0) return;
        if (pending !== '') { input = pending + input; pending = ''; }
        const last = apply(codeAt, input, [input.length - 1]);
        if (last >= 0xD800 && last <= 0xDBFF) {
          pending = apply(slice, input, [-1]);
          input = apply(slice, input, [0, -1]);
        }
        if (input.length !== 0) publish(controller, apply(encode, encoder, [input]));
      };
      algorithms.flush = function (controller) {
        if (pending !== '') {
          const last = pending; pending = '';
          publish(controller, apply(encode, encoder, [last]));
        }
      };
      apply(weakSet, encoders, [this, endpoints(new Transform(algorithms))]);
    }
    get encoding() { state(encoders, this); return 'utf-8'; }
    get readable() { return state(encoders, this).readable; }
    get writable() { return state(encoders, this).writable; }
  }
  class TextDecoderStream {
    constructor(label, options) {
      // Normalize the Web IDL boundary once; the native decoder continues to
      // own supported labels, fatal errors, views and streaming state.
      const encoding = label === undefined ? 'utf-8' : text(label);
      if (options === undefined || options === null) options = create(null);
      if (typeof options !== 'object' && typeof options !== 'function') {
        throw new Invalid('TextDecoderStream options must be an object');
      }
      const config = create(null);
      config.fatal = !!options.fatal; config.ignoreBOM = !!options.ignoreBOM;
      const decoder = new Decoder(encoding, config);
      const streaming = create(null); streaming.stream = true;
      const algorithms = create(null);
      algorithms.transform = function (chunk, controller) {
        // decode(undefined) means EOF in the codec API, but an undefined
        // stream chunk is not a BufferSource and must not flush native carry.
        if (chunk === undefined) throw new Invalid('TextDecoderStream chunk must be a BufferSource');
        publish(controller, apply(decode, decoder, [chunk, streaming]));
      };
      algorithms.flush = function (controller) { publish(controller, apply(decode, decoder, [])); };
      const record = endpoints(new Transform(algorithms));
      record.encoding = decoder.encoding; record.fatal = config.fatal; record.ignoreBOM = config.ignoreBOM;
      apply(weakSet, decoders, [this, record]);
    }
    get encoding() { return state(decoders, this).encoding; }
    get fatal() { return state(decoders, this).fatal; }
    get ignoreBOM() { return state(decoders, this).ignoreBOM; }
    get readable() { return state(decoders, this).readable; }
    get writable() { return state(decoders, this).writable; }
  }
  install(TextEncoderStream.prototype, tag, 'TextEncoderStream');
  install(TextDecoderStream.prototype, tag, 'TextDecoderStream');
  install(Web, 'TextEncoderStream', TextEncoderStream, true);
  install(Web, 'TextDecoderStream', TextDecoderStream, true);
  return Web;
})
