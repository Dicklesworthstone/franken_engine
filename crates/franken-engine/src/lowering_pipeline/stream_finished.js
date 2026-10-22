(function installWebFinished(stream, loadWeb) {
  'use strict';
  // Observe canonical Web completion without acquiring, releasing or consuming
  // anyone's reader/writer. Node-only calls retain the original EOS owner.
  const apply = Reflect.apply;
  const descriptor = Object.getOwnPropertyDescriptor;
  const define = Object.defineProperty;
  const create = Object.create;
  const isArray = Array.isArray;
  const P = Promise;
  const promiseThen = P.prototype.then;
  const key = Symbol.for('nodejs.webstream.isClosedPromise');
  const custom = Symbol.for('nodejs.util.promisify.custom');
  const iterator = Symbol.iterator;
  const Controller = AbortController;
  const controllerSignal = descriptor(Controller.prototype, 'signal').get;
  const abort = Controller.prototype.abort;
  const any = AbortSignal.any;
  const aborted = descriptor(AbortSignal.prototype, 'aborted').get;
  const reason = descriptor(AbortSignal.prototype, 'reason').get;
  const listen = EventTarget.prototype.addEventListener;
  const unlisten = EventTarget.prototype.removeEventListener;
  const Type = TypeError, ErrorClass = Error;
  const core = stream.finished, promises = stream.promises;
  const corePromise = promises.finished;
  let web;
  function invalid(name) {
    const error = new Type('Invalid ' + name); error.code = 'ERR_INVALID_ARG_TYPE'; return error;
  }
  function then(p, yes, no) { return apply(promiseThen, p, [yes, no]); }
  function completion(value) {
    if (value === null || typeof value !== 'object' || typeof value.on === 'function' ||
        (!('getReader' in value) && !('getWriter' in value))) return undefined;
    if (web === undefined) {
      const m = loadWeb();
      const r = m.ReadableStream.prototype, w = m.WritableStream.prototype;
      const rc = descriptor(r, key), wc = descriptor(w, key);
      web = { r: descriptor(r, 'locked').get, w: descriptor(w, 'locked').get,
        rc: rc && rc.get, wc: wc && wc.get };
    }
    let read = false, write = false;
    try { apply(web.r, value, []); read = true; } catch (error) {}
    if (!read) { try { apply(web.w, value, []); write = true; } catch (error) {} }
    if (!read && !write) throw invalid('stream');
    // The engine's getter authenticates state and is captured once. Native
    // Node Web streams publish the same interoperable promise as an own slot.
    const getter = read ? web.rc : web.wc;
    const state = getter === undefined ? value[key] : apply(getter, value, []);
    if (state === null || typeof state !== 'object') throw invalid('stream completion');
    return state.promise;
  }
  function dependencies(external, internal) {
    const pair = [external, internal], d = create(null);
    d.value = function () {
      let i = 0;
      return { next: function () {
        if (i++ === 0) return { value: external, done: false };
        if (i === 2) return { value: internal, done: false };
        return { done: true };
      } };
    };
    define(pair, iterator, d); return pair;
  }
  function webFinished(value, options, callback) {
    if (typeof options === 'function') { callback = options; options = undefined; }
    // Preserve all ordinary Node/custom-emitter overload and validation paths.
    if (value === null || typeof value !== 'object' || typeof value.on === 'function' ||
        (!('getReader' in value) && !('getWriter' in value))) {
      return apply(core, stream, [value, options, callback]);
    }
    if (options === undefined || options === null) options = create(null);
    if (typeof options !== 'object' || isArray(options)) throw invalid('options');
    if (typeof callback !== 'function') throw invalid('callback');
    const signal = options.signal;
    if (signal !== undefined) { try { apply(aborted, signal, []); } catch (e) { throw invalid('options.signal'); } }
    const promise = completion(value);
    const record = { callback: callback, target: value, signal: signal, dependent: undefined, release: undefined };
    function cleanup() {
      record.callback = undefined; record.target = undefined; record.signal = undefined;
      if (record.dependent !== undefined) {
        apply(unlisten, record.dependent, ['abort', onAbort]); record.dependent = undefined;
      }
      if (record.release !== undefined) {
        const release = record.release; record.release = undefined; apply(abort, release, [null]);
      }
    }
    function cancelError() {
      const error = new ErrorClass('The operation was aborted');
      error.name = 'AbortError'; error.code = 'ABORT_ERR';
      const d = create(null); d.value = apply(reason, record.signal, []);
      d.writable = true; d.configurable = true; define(error, 'cause', d); return error;
    }
    function complete(error) {
      if (record.callback === undefined) return;
      if (record.signal !== undefined && apply(aborted, record.signal, [])) error = cancelError();
      const callback = record.callback, target = record.target; cleanup();
      apply(callback, target, [error]);
    }
    function onAbort() {
      if (record.signal !== undefined && apply(aborted, record.signal, [])) complete(cancelError());
    }
    try {
      if (signal !== undefined) {
        record.release = new Controller();
        record.dependent = any(dependencies(signal, apply(controllerSignal, record.release, [])));
        apply(listen, record.dependent, ['abort', onAbort]);
        if (apply(aborted, signal, [])) __franken_stream_web_tick(onAbort);
      }
      then(promise, function () {
        __franken_stream_web_tick(function () { complete(); });
      }, function (error) {
        // Callback conventions must not mistake a falsy Web rejection for EOF.
        if (!error) {
          const failure = new ErrorClass('Web stream failed');
          failure.code = 'ERR_STREAM_WEB'; failure.cause = error; error = failure;
        }
        __franken_stream_web_tick(function () { complete(error); });
      });
    } catch (error) { cleanup(); throw error; }
    return cleanup;
  }
  function finishedPromise(value, options) {
    if (value === null || typeof value !== 'object' || typeof value.on === 'function' ||
        (!('getReader' in value) && !('getWriter' in value))) {
      return apply(corePromise, promises, [value, options]);
    }
    const cleanup = options == null ? undefined : options.cleanup;
    if (cleanup && typeof cleanup !== 'boolean') throw invalid('options.cleanup');
    return new P(function (resolve, reject) {
      webFinished(value, options, function (error) { if (error) reject(error); else resolve(); });
    });
  }
  function property(target, name, value) {
    const d = create(null); d.value = value; d.writable = true; d.configurable = true; d.enumerable = true;
    define(target, name, d);
  }
  property(webFinished, custom, finishedPromise);
  property(webFinished, 'finished', finishedPromise);
  property(stream, 'finished', webFinished);
  property(promises, 'finished', finishedPromise);
  return stream;
})
