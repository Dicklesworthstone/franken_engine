(function installStreamWebBridge(stream, loadWeb) {
  'use strict';
  // Adapt existing Node/Web queues and lifetimes. No I/O backend, chunk
  // collection, external runtime, or authority grant is introduced here.
  const apply = Reflect.apply;
  const define = Object.defineProperty;
  const descriptor = Object.getOwnPropertyDescriptor;
  const create = Object.create;
  const P = Promise;
  const resolve = Promise.resolve;
  const promiseThen = Promise.prototype.then;
  const Bytes = Uint8Array;
  const isBuffer = Buffer.isBuffer;
  const Type = TypeError;
  // Authenticate binary payloads without invoking guest metadata getters.
  // The actual read remains the public arrayBuffer method, as Duplex.from
  // specifies; the existing generic converter owns its promise and lifetime.
  const blobSize = typeof Blob === 'function' ? descriptor(Blob.prototype, 'size').get : undefined;
  function isBlob(value) {
    if (blobSize === undefined || value === null || typeof value !== 'object') return false;
    try { apply(blobSize, value, []); return true; } catch (error) { return false; }
  }
  const ErrorClass = Error;
  const R = stream.Readable, W = stream.Writable, D = stream.Duplex;
  const push = R.prototype.push, pause = R.prototype.pause, resume = R.prototype.resume;
  const destroyR = R.prototype.destroy, destroyW = W.prototype.destroy;
  const write = W.prototype.write, end = W.prototype.end;
  const on = R.prototype.on, remove = R.prototype.removeListener;
  const finished = stream.finished;
  const listen = EventTarget.prototype.addEventListener;
  const unlisten = EventTarget.prototype.removeEventListener;
  const aborted = descriptor(AbortSignal.prototype, 'aborted').get;
  const abortReason = descriptor(AbortSignal.prototype, 'reason').get;
  let web;

  function fail(name) { const e = new Type('Invalid ' + name); e.code = 'ERR_INVALID_ARG_TYPE'; return e; }
  function premature() { const e = new ErrorClass('Premature close'); e.code = 'ERR_STREAM_PREMATURE_CLOSE'; return e; }
  function failure(reason) {
    // Node's destroy callback treats falsy values as success. Never turn a
    // rejected Web operation into EOF: keep that value as an explicit cause.
    if (reason) return reason;
    const e = new ErrorClass('Web stream operation failed');
    e.code = 'ERR_STREAM_WEB'; e.cause = reason; return e;
  }
  function then(p, yes, no) { return apply(promiseThen, p, [yes, no]); }
  function resolved(value) { return apply(resolve, P, [value]); }
  function options(value) {
    if (value === undefined) return create(null);
    if (value === null || typeof value !== 'object') throw fail('options');
    return value;
  }
  function property(object, name, value) {
    const d = create(null); d.value = value; d.writable = true; d.configurable = true; d.enumerable = true;
    define(object, name, d);
  }
  function api() {
    if (web !== undefined) return web;
    const m = loadWeb();
    // Retain canonical methods, not guest replacements on individual streams.
    web = { R: m.ReadableStream, W: m.WritableStream,
      getReader: m.ReadableStream.prototype.getReader,
      rLocked: descriptor(m.ReadableStream.prototype, 'locked').get,
      read: m.ReadableStreamDefaultReader.prototype.read,
      cancel: m.ReadableStreamDefaultReader.prototype.cancel,
      releaseReader: m.ReadableStreamDefaultReader.prototype.releaseLock,
      rClosed: descriptor(m.ReadableStreamDefaultReader.prototype, 'closed').get,
      getWriter: m.WritableStream.prototype.getWriter,
      wLocked: descriptor(m.WritableStream.prototype, 'locked').get,
      write: m.WritableStreamDefaultWriter.prototype.write,
      close: m.WritableStreamDefaultWriter.prototype.close,
      abort: m.WritableStreamDefaultWriter.prototype.abort,
      wClosed: descriptor(m.WritableStreamDefaultWriter.prototype, 'closed').get,
      enqueue: m.ReadableStreamDefaultController.prototype.enqueue,
      closeR: m.ReadableStreamDefaultController.prototype.close,
      errorR: m.ReadableStreamDefaultController.prototype.error,
      desired: descriptor(m.ReadableStreamDefaultController.prototype, 'desiredSize').get,
      errorW: m.WritableStreamDefaultController.prototype.error,
      transformReadable: descriptor(m.TransformStream.prototype, 'readable').get,
      transformWritable: descriptor(m.TransformStream.prototype, 'writable').get,
      signal: descriptor(m.WritableStreamDefaultController.prototype, 'signal').get };
    return web;
  }
  function nodeOptions(value, readable) {
    const input = options(value), out = create(null);
    out.highWaterMark = input.highWaterMark; out.objectMode = input.objectMode;
    out.signal = input.signal;
    if (out.objectMode !== undefined && typeof out.objectMode !== 'boolean') throw fail('options.objectMode');
    if (readable) out.encoding = input.encoding;
    else {
      out.decodeStrings = input.decodeStrings;
      if (out.decodeStrings !== undefined && typeof out.decodeStrings !== 'boolean') throw fail('options.decodeStrings');
    }
    // A pre-aborted signal can destroy a Node stream inside its constructor.
    // Keep _destroy behind the existing construction barrier until the Web
    // endpoints below have been acquired. Otherwise destruction sees no owner,
    // reports close, and only then acquires a permanently live Web resource.
    // No signal means no extra construction job on the ordinary data path.
    if (out.signal) out.construct = constructAfterAdoption;
    return out;
  }
  function constructAfterAdoption(done) { done(); }
  function discardAdapter(node, destroy) {
    // Setup throws synchronously, so the caller never receives this Node
    // object. Observe its possible queued abort error while its construction
    // barrier drains. Do not cancel an endpoint whose lock we never acquired.
    apply(on, node, ['error', function () {}]);
    apply(destroy, node, []);
  }
  function readableFromWeb(source, settings) { return makeReadableFromWeb(source, settings); }
  function makeReadableFromWeb(source, settings, owner) {
    const a = api(); apply(a.rLocked, source, []); // brand check before taking ownership
    const config = nodeOptions(settings, true);
    let reader, node, reading = false, stopping = false, ended = false, readError;
    config.read = function () {
      if (reading || stopping || ended || readError !== undefined) return;
      reading = true;
      then(apply(a.read, reader, []), function (item) {
        reading = false;
        if (stopping) return;
        try {
          if (item.done) { ended = true; apply(push, node, [null]); }
          else {
            // null is Node EOF, not an object-mode value. Refuse explicitly
            // instead of silently truncating the remaining Web stream.
            if (item.value === null) {
              const e = new Type('A Web null chunk cannot be represented by a Node stream');
              e.code = 'ERR_STREAM_NULL_VALUES'; apply(destroyR, node, [e]); return;
            }
            apply(push, node, [item.value]);
          }
          // A synchronous Web pull can fulfill this read and then error
          // before read() returns. Its closed reaction may run first: publish
          // the already-admitted chunk before reporting that terminal error.
          if (readError !== undefined && !stopping) apply(destroyR, node, [readError]);
        } catch (error) { apply(destroyR, node, [error]); }
      }, function (reason) { reading = false; if (!stopping) apply(destroyR, node, [failure(reason)]); });
    };
    config.destroy = function (error, done) {
      stopping = true;
      if (reader === undefined || ended) { done(error); return; }
      then(apply(a.cancel, reader, [error]), function () { done(error); },
        function (reason) { done(error || failure(reason)); });
    };
    // Validate Node settings before acquiring the Web lock. The private Node
    // constructor does not start reading until a consumer asks for data.
    node = new R(config);
    try { reader = apply(a.getReader, source, []); }
    catch (error) { discardAdapter(node, destroyR); throw error; }
    then(apply(a.rClosed, reader, []), undefined, function (reason) {
      if (stopping) return;
      readError = failure(reason);
      // A pending read settles on the same Web error. Let its result decide
      // whether a chunk was admitted; idle failures still destroy promptly.
      if (!reading) apply(destroyR, node, [readError]);
    });
    if (owner !== undefined) owner.own(node, function () { stopping = true; apply(a.releaseReader, reader, []); });
    // Like Node's adapters, ownership of the Web lock is permanent. It is
    // not returned to a second consumer after EOF or destroy.
    return node;
  }
  function writableFromWeb(destination, settings) { return makeWritableFromWeb(destination, settings); }
  function makeWritableFromWeb(destination, settings, owner) {
    const a = api(); apply(a.wLocked, destination, []);
    const config = nodeOptions(settings, false);
    let writer, node, stopping = false, ended = false;
    config.write = function (chunk, encoding, done) {
      then(apply(a.write, writer, [chunk]), function () { done(); }, function (reason) { done(failure(reason)); });
    };
    config.final = function (done) {
      then(apply(a.close, writer, []), function () { ended = true; done(); }, function (reason) { done(failure(reason)); });
    };
    config.destroy = function (error, done) {
      stopping = true;
      if (writer === undefined || ended) { done(error); return; }
      then(apply(a.abort, writer, [error]), function () { done(error); }, function (reason) { done(error || failure(reason)); });
    };
    node = new W(config);
    try { writer = apply(a.getWriter, destination, []); }
    catch (error) { discardAdapter(node, destroyW); throw error; }
    then(apply(a.wClosed, writer, []), undefined, function (reason) {
      if (!stopping) apply(destroyW, node, [failure(reason)]);
    });
    if (owner !== undefined) owner.own(node, function () { stopping = true; });
    return node;
  }
  function observableClose(state) {
    // Without close notifications there is no public completion signal for
    // an asynchronous _destroy(null, callback). Do not poll, detach early, or
    // claim that cancellation completed before its resource was released.
    if (state && state.emitClose === false) {
      const e = new Type('Web adapters require Node close notifications');
      e.code = 'ERR_STREAM_WEB_UNSUPPORTED'; throw e;
    }
  }
  function duplexFromWeb(pair, settings) { return makeDuplexFromWeb(pair, settings); }
  function makeDuplexFromWeb(pair, settings, owner, modes) {
    if (pair === null || typeof pair !== 'object') throw fail('pair');
    const source = pair.readable, destination = pair.writable, a = api();
    apply(a.rLocked, source, []); apply(a.wLocked, destination, []);
    const config = nodeOptions(settings, true), input = options(settings);
    // Composition exposes only its outer two sides to Node byte mode. Web
    // stages inside the chain may exchange arbitrary non-null objects.
    if (modes !== undefined) {
      config.objectMode = false;
      config.readableObjectMode = modes.readable;
      config.writableObjectMode = modes.writable;
    }
    config.decodeStrings = input.decodeStrings;
    if (config.decodeStrings !== undefined && typeof config.decodeStrings !== 'boolean') throw fail('options.decodeStrings');
    const halfOpen = input.allowHalfOpen;
    config.allowHalfOpen = halfOpen === undefined ? false : halfOpen;
    if (typeof config.allowHalfOpen !== 'boolean') throw fail('options.allowHalfOpen');
    let node, reader, writer, reading = false, stopping = false;
    let readEnded = false, writeEnded = false, readError;
    config.read = function () {
      if (reading || stopping || readEnded || readError !== undefined) return;
      reading = true;
      then(apply(a.read, reader, []), function (item) {
        reading = false;
        if (stopping) return;
        try {
          if (item.done) { readEnded = true; apply(push, node, [null]); return; }
          if (item.value === null) {
            const error = new Type('A Web null chunk cannot be represented by a Node stream');
            error.code = 'ERR_STREAM_NULL_VALUES'; throw error;
          }
          apply(push, node, [item.value]);
          if (readError !== undefined && !stopping) apply(destroyR, node, [readError]);
        } catch (error) { apply(destroyR, node, [error]); }
      }, function (reason) { reading = false; if (!stopping) apply(destroyR, node, [failure(reason)]); });
    };
    config.write = function (chunk, encoding, done) {
      then(apply(a.write, writer, [chunk]), function () { done(); }, function (reason) { done(failure(reason)); });
    };
    config.final = function (done) {
      then(apply(a.close, writer, []), function () { writeEnded = true; done(); }, function (reason) { done(failure(reason)); });
    };
    config.destroy = function (error, done) {
      stopping = true;
      // Start BOTH cleanup algorithms before awaiting either. A readable
      // cancellation can wait for writable abort (or vice versa). Resolving
      // only one side is not completion, even if that side rejects first.
      let remaining = 2, readError, writeError;
      function complete() { if (--remaining === 0) done(error || readError || writeError); }
      function cancel() {
        if (reader === undefined || readEnded) { complete(); return; }
        try {
          then(apply(a.cancel, reader, [error]), complete, function (reason) { readError = failure(reason); complete(); });
        } catch (reason) { readError = failure(reason); complete(); }
      }
      function abort() {
        if (writer === undefined || writeEnded) { complete(); return; }
        try {
          then(apply(a.abort, writer, [error]), complete, function (reason) { writeError = failure(reason); complete(); });
        } catch (reason) { writeError = failure(reason); complete(); }
      }
      cancel(); abort();
    };
    // Node option validation precedes Web ownership. Recheck BOTH endpoint
    // locks after observable option getters, before acquiring either one.
    node = new D(config);
    try {
      if (apply(a.rLocked, source, []) || apply(a.wLocked, destination, [])) {
        const error = new Type('Web stream endpoint is locked'); error.code = 'ERR_INVALID_STATE'; throw error;
      }
      reader = apply(a.getReader, source, []);
      try { writer = apply(a.getWriter, destination, []); }
      catch (error) { apply(a.releaseReader, reader, []); reader = undefined; throw error; }
    } catch (error) { discardAdapter(node, destroyR); throw error; }
    function rejected(reason) { if (!stopping) apply(destroyR, node, [failure(reason)]); }
    then(apply(a.rClosed, reader, []), undefined, function (reason) {
      if (stopping) return;
      readError = failure(reason);
      if (!reading) apply(destroyR, node, [readError]);
    });
    // A destination failure is different: stop immediately and suppress any
    // late source delivery instead of waiting for a stalled read.
    then(apply(a.wClosed, writer, []), undefined, rejected);
    if (owner !== undefined) owner.own(node, function () { stopping = true; apply(a.releaseReader, reader, []); });
    return node;
  }
  function completionOptions(readable) {
    const o = create(null); o.readable = readable; o.writable = !readable; return o;
  }
  function readableToWeb(node, settings) {
    if (!(node instanceof R)) throw fail('Readable');
    observableClose(node._readableState);
    const a = api(), input = options(settings);
    const requestedStrategy = input.strategy;
    const strategy = requestedStrategy === undefined ? create(null) : requestedStrategy;
    if (requestedStrategy === undefined) strategy.highWaterMark = node.readableHighWaterMark;
    let controller, cleanup, complete = false, cancelling = false, stopped = false;
    let cancelResolve;
    const objectMode = node.readableObjectMode;
    function detach() {
      apply(remove, node, ['data', data]);
      if (cleanup !== undefined) { const fn = cleanup; cleanup = undefined; fn(); }
    }
    function settled(error) {
      complete = true; stopped = true; detach();
      if (cancelling) { if (cancelResolve !== undefined) cancelResolve(); return; }
      if (error) apply(a.errorR, controller, [error]); else apply(a.closeR, controller, []);
    }
    function data(chunk) {
      if (stopped) return;
      try {
        // Node.toWeb copies Buffer chunks in byte mode, but keeps values and
        // byte views identical in object mode. No backing Buffer is leaked.
        const value = !objectMode && isBuffer(chunk) ? new Bytes(chunk) : chunk;
        apply(a.enqueue, controller, [value]);
        if (apply(a.desired, controller, []) <= 0) apply(pause, node, []);
      } catch (error) { stopped = true; apply(destroyR, node, [error]); }
    }
    const source = create(null);
    source.start = function (c) {
        controller = c;
        if (node.destroyed || node.readableEnded) {
          complete = true; stopped = true;
          if (node.errored) apply(a.errorR, c, [node.errored]); else apply(a.closeR, c, []);
          return;
        }
        apply(pause, node, []);
        cleanup = finished(node, completionOptions(true), settled);
        if (complete) { detach(); return; }
        apply(on, node, ['data', data]);
      };
    source.pull = function () { if (!stopped) apply(resume, node, []); };
    source.cancel = function (reason) {
        if (complete) return;
        cancelling = true; stopped = true;
        apply(pause, node, []);
        return new P(function (resolveCancel) {
          cancelResolve = resolveCancel;
          apply(destroyR, node, [reason]);
        });
      };
    return new a.R(source, strategy);
  }
  function writableToWeb(node) {
    if (!(node instanceof W) && !(node instanceof D)) throw fail('Writable');
    observableClose(node._writableState);
    const a = api();
    let controller, signal, cleanup, complete = false, terminalError;
    let closing = false, aborting = false, active, finishResolve, finishReject;
    function detach() {
      if (signal !== undefined) { apply(unlisten, signal, ['abort', abortNow]); signal = undefined; }
      if (cleanup !== undefined) { const fn = cleanup; cleanup = undefined; fn(); }
    }
    function abortNow() {
      if (signal !== undefined && apply(aborted, signal, [])) {
        aborting = true;
        apply(destroyW, node, [apply(abortReason, signal, [])]);
      }
    }
    function settled(error) {
      complete = true; terminalError = error; detach();
      if (active !== undefined) active(error || premature());
      if (finishResolve !== undefined) {
        if (aborting || !error) finishResolve(); else finishReject(error);
      }
      if (!closing && !aborting) apply(a.errorW, controller, [error || premature()]);
    }
    function finish(abort, reason) {
      if (abort) aborting = true; else closing = true;
      if (complete) {
        return !abort && terminalError ? new P(function (_, reject) { reject(terminalError); }) : resolved();
      }
      return new P(function (resolveFinish, rejectFinish) {
        finishResolve = resolveFinish; finishReject = rejectFinish;
        if (abort) apply(destroyW, node, [reason]); else apply(end, node, []);
      });
    }
    const sink = create(null);
    sink.start = function (c) {
        controller = c;
        signal = apply(a.signal, c, []);
        apply(listen, signal, ['abort', abortNow]);
        cleanup = finished(node, completionOptions(false), settled);
        if (complete) detach();
      };
    sink.write = function (chunk) {
        return new P(function (resolveWrite, rejectWrite) {
          if (complete) { rejectWrite(terminalError || premature()); return; }
          let returned = false, callbackDone = false, accepted = false, drained = false, done = false;
          function finishWrite(error) {
            if (done) return;
            if (!error && (!returned || !callbackDone || (!accepted && !drained))) return;
            done = true; active = undefined;
            apply(remove, node, ['drain', drain]);
            if (error) rejectWrite(error); else resolveWrite();
          }
          function drain() { drained = true; finishWrite(); }
          active = finishWrite;
          apply(on, node, ['drain', drain]);
          try {
            accepted = apply(write, node, [chunk, function (error) { callbackDone = true; finishWrite(error); }]);
            returned = true; finishWrite();
          } catch (error) { finishWrite(error); }
        });
      };
    sink.close = function () { return finish(false); };
    sink.abort = function (reason) { return finish(true, reason); };
    const strategy = create(null); strategy.highWaterMark = node.writableHighWaterMark;
    return new a.W(sink, strategy);
  }
  property(R, 'fromWeb', readableFromWeb); property(R, 'toWeb', readableToWeb);
  property(W, 'fromWeb', writableFromWeb); property(W, 'toWeb', writableToWeb);
  function duplexToWeb(node) {
    if (!(node instanceof D)) throw fail('Duplex');
    // Refuse an unobservable lifetime before either side installs listeners.
    observableClose(node._readableState); observableClose(node._writableState);
    return { readable: readableToWeb(node), writable: writableToWeb(node) };
  }
  property(D, 'fromWeb', duplexFromWeb); property(D, 'toWeb', duplexToWeb);
  const genericDuplexFrom = D.from;
  function from(body) { return fromValue(body, 0); }
  function fromPair(body, depth) {
    // Match the generic converter's nesting bound. Normalize only the pair's
    // endpoints; the existing Duplex owner still implements all data movement,
    // backpressure, finalization and destruction of both independent halves.
    const originalRead = body.readable, originalWrite = body.writable;
    let readable = originalRead, writable = originalWrite;
    try {
      if (readable != null && !nodeStage(readable)) readable = fromValue(readable, depth + 1);
      if (writable != null && !nodeStage(writable)) writable = fromValue(writable, depth + 1);
      const pair = create(null); pair.readable = readable; pair.writable = writable;
      return apply(genericDuplexFrom, D, [pair]);
    } catch (error) {
      // Setup is synchronous, but acquired endpoints may own asynchronous Web
      // cancellation. Observe their errors and start every owned cleanup before
      // returning the original failure. Leave untouched Node endpoints alone.
      for (let side = 0; side < 2; side++) {
        const node = side === 0 ? readable : writable;
        const original = side === 0 ? originalRead : originalWrite;
        if (node != null && node !== original) {
          try { apply(on, node, ['error', function () {}]); apply(destroyR, node, []); }
          catch (cleanupError) { /* The inaccessible adapter cannot replace setup failure. */ }
        }
      }
      throw error;
    }
  }
  function fromValue(body, depth) {
    if (depth > 32) {
      const error = new Type('Duplex source nesting exceeds its limit');
      error.code = 'ERR_INVALID_ARG_VALUE'; throw error;
    }
    if (!(body instanceof R) && !(body instanceof W) && isBlob(body)) {
      // Node publishes a Blob as one ArrayBuffer in object mode, including
      // an empty Blob. Do not turn it into a byte iterator or split its record.
      return apply(genericDuplexFrom, D, [body.arrayBuffer()]);
    }
    // Keep the canonical generic converter for Node streams, iterables,
    // functions, promises and user-defined pairs. Only native Web brands
    // select these adapters; properties on a lookalike are not authority.
    if (body === null || typeof body !== 'object' || body instanceof R || body instanceof W ||
        (!('getReader' in body) && !('getWriter' in body) &&
         !('readable' in body) && !('writable' in body))) {
      return apply(genericDuplexFrom, D, [body]);
    }
    // A single-ended record cannot be a branded TransformStream. Keep the
    // existing Node-only path lazy: adapting a Node readable/writable alone
    // must not initialize the unrelated Web kernel.
    if (!('getReader' in body) && !('getWriter' in body) &&
        !('readable' in body && 'writable' in body) &&
        !(Symbol.asyncIterator in body) && !(Symbol.iterator in body) && !('then' in body)) {
      return fromPair(body, depth);
    }
    const a = api();
    let kind = 0;
    try { apply(a.rLocked, body, []); kind = 1; } catch (error) {}
    if (kind === 0) {
      try { apply(a.wLocked, body, []); kind = 2; } catch (error) {}
    }
    if (kind === 0) {
      let source, destination;
      try {
        source = apply(a.transformReadable, body, []);
        destination = apply(a.transformWritable, body, []);
      } catch (error) {
        // A plain pair is not a branded TransformStream. Delegate competing
        // iterator/thenable protocols unchanged, including their getter order.
        // For ordinary pairs, recursively reuse this same bridge on endpoints
        // so Web/Blob inputs cannot bypass their canonical adapters.
        if (('readable' in body || 'writable' in body) &&
            !(Symbol.asyncIterator in body) && !(Symbol.iterator in body) && !('then' in body)) {
          return fromPair(body, depth);
        }
        return apply(genericDuplexFrom, D, [body]);
      }
      const pair = create(null); pair.readable = source; pair.writable = destination;
      return duplexFromWeb(pair);
    }
    // The existing generic converter supplies the disabled half and Duplex
    // lifecycle; the Web adapter supplies byte-mode validation, serialized
    // demand, exclusive ownership and asynchronous cancellation/finalization.
    // Do not classify a Web readable as an object-mode generic iterable.
    const endpoint = kind === 1 ? readableFromWeb(body) : writableFromWeb(body);
    try { return apply(genericDuplexFrom, D, [endpoint]); }
    catch (error) {
      // Only the conversion-created intermediate is ours on setup failure.
      apply(on, endpoint, ['error', function () {}]);
      apply(kind === 1 ? destroyR : destroyW, endpoint, [failure(error)]);
      throw error;
    }
  }
  if (typeof genericDuplexFrom === 'function') property(D, 'from', from);
  // Pipeline still owns scheduling, cancellation, function stages and Node
  // teardown. This boundary normalizes explicit Web stages and promised
  // sources through existing adapters; it builds no new pump or input buffer.
  // As at the explicit Node/Web boundary, null readable chunks are refused,
  // not interpreted as EOF. The writer lock has Node's retained ownership.
  const pipelineSlice = Array.prototype.slice;
  const pipelineIsArray = Array.isArray;
  const pipelineIterator = Symbol.iterator;
  const pipelineAsyncIterator = Symbol.asyncIterator;
  const callbackPipeline = stream.pipeline;
  const pipelinePromises = stream.promises;
  const promisePipeline = pipelinePromises && pipelinePromises.pipeline;
  function nodeStage(value) {
    return value != null && typeof value.on === 'function' &&
      (typeof value.pipe === 'function' || typeof value.write === 'function');
  }
  function iterableStage(value) {
    return value != null && (typeof value[pipelineIterator] === 'function' ||
      typeof value[pipelineAsyncIterator] === 'function');
  }
  function lockedEndpoint() {
    const error = new Type('Web stream endpoint is locked or used twice');
    error.code = 'ERR_INVALID_STATE'; return error;
  }
  function webStage(value, index, count, openEnds) {
    if (value === null || typeof value !== 'object' || nodeStage(value) || pipelineIsArray(value)) return undefined;
    if (isBlob(value)) {
      if (index !== 0) throw fail('read-only Blob pipeline stage');
      return { blob: value };
    }
    // Hints do not grant a brand. They avoid loading the Web module for an
    // ordinary Node-only pipeline, iterable, or options dictionary. An own
    // replacement of getReader/getWriter is never invoked or trusted.
    if (!('getReader' in value) && !('getWriter' in value) &&
        !('readable' in value && 'writable' in value)) return undefined;
    const a = api();
    let readable = false, writable = false;
    try { apply(a.rLocked, value, []); readable = true; } catch (error) {}
    try { apply(a.wLocked, value, []); writable = true; } catch (error) {}
    let source, destination;
    if (readable) source = value;
    else if (writable) destination = value;
    else {
      source = value.readable; destination = value.writable;
      apply(a.rLocked, source, []); apply(a.wLocked, destination, []);
    }
    const reading = index < count - 1, writing = index > 0;
    if ((reading && source === undefined) || (writing && destination === undefined)) throw fail('pipeline stage');
    if (!openEnds) {
      if (!reading) source = undefined;
      if (!writing) destination = undefined;
    }
    if ((source !== undefined && apply(a.rLocked, source, [])) ||
        (destination !== undefined && apply(a.wLocked, destination, []))) throw lockedEndpoint();
    return { source: source, destination: destination };
  }
  function pipelineOwner() {
    const records = [];
    let finished = false;
    return {
      own: function (node, release) {
        const record = { node: node, release: release, closed: false, waiters: [] };
        record.error = function () {}; // Teardown may precede core registration.
        record.close = function () {
          record.closed = true;
          const waiting = record.waiters; record.waiters = [];
          for (let i = 0; i < waiting.length; i++) waiting[i]();
        };
        apply(on, node, ['error', record.error]);
        apply(on, node, ['close', record.close]);
        records[records.length] = record;
      },
      finish: function (error, done) {
        if (finished) return;
        finished = true;
        let pending = 1;
        function complete() {
          if (--pending !== 0) return;
          for (let i = 0; i < records.length; i++) {
            const record = records[i];
            record.release();
            apply(remove, record.node, ['error', record.error]);
            apply(remove, record.node, ['close', record.close]);
          }
          done();
        }
        if (error) {
          // Every adopted stage belongs to this invocation, even if a later
          // factory throws before the original pipeline registers that stage.
          // Start all destruction before waiting for any close notification.
          for (let i = 0; i < records.length; i++) {
            const record = records[i];
            if (!record.closed) {
              pending++;
              record.waiters[record.waiters.length] = complete;
              apply(destroyR, record.node, [error]);
            }
          }
        }
        complete();
      }
    };
  }
  function adaptPipelineStage(value, shape, owner, modes, sourceValue) {
    if (shape === undefined) {
      // The core source protocol accepts streams and iterables. A promised
      // source must first pass through the EXISTING generic Duplex converter,
      // which observes the producer now and owns cancellation/late delivery.
      // Do not await it here: that would let a never-settling producer prevent
      // the pipeline from acquiring its abort signal and closing its sinks.
      if (sourceValue && value !== null && typeof value === 'object' &&
          !nodeStage(value) && !iterableStage(value) && 'then' in value) {
        const node = apply(genericDuplexFrom, D, [value]);
        // A later setup failure can precede registration by the core. Keep
        // this conversion-created source owned until teardown has completed.
        owner.own(node, function () {});
        return node;
      }
      return value;
    }
    if (shape.blob !== undefined) {
      const node = from(shape.blob);
      // A later stage may fail before the core takes this source. The same
      // pipeline owner suppresses late results and observes its teardown.
      owner.own(node, function () {});
      return node;
    }
    const config = create(null);
    config.objectMode = true; config.highWaterMark = 1;
    config.decodeStrings = false; config.allowHalfOpen = true;
    if (shape.source === undefined) {
      if (modes !== undefined) config.objectMode = modes.writable;
      return makeWritableFromWeb(shape.destination, config, owner);
    }
    if (shape.destination === undefined) {
      if (modes !== undefined) config.objectMode = modes.readable;
      return makeReadableFromWeb(shape.source, config, owner);
    }
    const pair = create(null); pair.readable = shape.source; pair.writable = shape.destination;
    return makeDuplexFromWeb(pair, config, owner, modes);
  }
  function preparePipeline(values, owner) {
    const stages = values.length === 1 && pipelineIsArray(values[0]) ? apply(pipelineSlice, values[0], []) : values;
    const count = stages.length, shapes = [], endpoints = [];
    if (count < 2) return { stages: stages, destination: undefined, webDestination: false };
    // Read all pair properties, check all brands/roles and detect duplicate
    // ownership before any adapter takes a lock or subscribes to a source.
    for (let i = 0; i < count; i++) {
      const shape = webStage(stages[i], i, count); shapes[i] = shape;
      if (shape === undefined) continue;
      for (let side = 0; side < 2; side++) {
        const endpoint = side === 0 ? shape.source : shape.destination;
        if (endpoint === undefined) continue;
        for (let j = 0; j < endpoints.length; j++) if (endpoints[j] === endpoint) throw lockedEndpoint();
        endpoints[endpoints.length] = endpoint;
      }
    }
    const normalized = [];
    for (let i = 0; i < count; i++) {
      const value = stages[i];
      if (typeof value === 'function' && i === 0) {
        // Source factories run only when the core invokes them. Keep the
        // core-provided signal and return-value validation, including throws.
        normalized[i] = function (options) {
          const result = value(options);
          // A function source must still return an iterable/Web stream. Node
          // accepts Blob as an explicit stage, not as a factory return value.
          return isBlob(result) ? result :
            adaptPipelineStage(result, webStage(result, 0, count), owner);
        };
      } else normalized[i] = adaptPipelineStage(value, shapes[i], owner, undefined, i === 0);
    }
    return { stages: normalized, destination: count ? stages[count - 1] : undefined,
      webDestination: count ? shapes[count - 1] !== undefined : false };
  }
  function pipeline(...values) {
    const args = apply(pipelineSlice, values, []);
    const callback = args[args.length - 1];
    // Preserve the core's synchronous argument errors before taking ownership.
    if (typeof callback !== 'function') return apply(callbackPipeline, stream, args);
    args.length--;
    const owner = pipelineOwner();
    try {
      const plan = preparePipeline(args, owner);
      plan.stages[plan.stages.length] = function (error, value) {
        owner.finish(error, function () { callback(error, value); });
      };
      const returned = apply(callbackPipeline, stream, plan.stages);
      return plan.webDestination ? plan.destination : returned;
    } catch (error) { owner.finish(failure(error), function () {}); throw error; }
  }
  function pipelinePromise(...values) {
    const args = apply(pipelineSlice, values, []);
    const owner = pipelineOwner();
    return new P(function (resolvePipeline, rejectPipeline) {
      try {
        const last = args[args.length - 1];
        let config;
        // A Web destination is not an options dictionary. Snapshot options
        // and validate the signal before adopting any endpoint.
        if (last && typeof last === 'object' && !nodeStage(last) && !iterableStage(last) &&
            !isBlob(last) && !('getReader' in last) && !('getWriter' in last) && !('readable' in last && 'writable' in last)) {
          args.length--; config = create(null); config.end = last.end; config.signal = last.signal;
          if (config.signal !== undefined) apply(aborted, config.signal, []);
        }
        const plan = preparePipeline(args, owner);
        if (config !== undefined) plan.stages[plan.stages.length] = config;
        then(apply(promisePipeline, pipelinePromises, plan.stages), function (value) {
          owner.finish(undefined, function () { resolvePipeline(value); });
        }, function (error) {
          owner.finish(failure(error), function () { rejectPipeline(error); });
        });
      } catch (error) { owner.finish(failure(error), function () { rejectPipeline(error); }); }
    });
  }
  if (typeof callbackPipeline === 'function' && typeof promisePipeline === 'function') {
    property(stream, 'pipeline', pipeline);
    property(pipelinePromises, 'pipeline', pipelinePromise);
    property(pipeline, Symbol.for('nodejs.util.promisify.custom'), pipelinePromise);
  }
  // Reusable composition keeps the head's writable and tail's readable
  // endpoints. The existing composition owner still runs all data movement,
  // function transforms, backpressure and teardown; this only adopts Web
  // stages before entering it. Node-only chains do not load the Web module.
  const coreCompose = stream.compose;
  const coreReadableCompose = R.prototype.compose;
  function composeOwned(values, receiver, config) {
    const shapes = [], endpoints = [];
    let hasWeb = false;
    for (let i = 0; i < values.length; i++) {
      const shape = webStage(values[i], i, values.length, true);
      shapes[i] = shape;
      if (shape === undefined) continue;
      hasWeb = true;
      for (let side = 0; side < 2; side++) {
        const endpoint = side === 0 ? shape.source : shape.destination;
        if (endpoint === undefined) continue;
        for (let j = 0; j < endpoints.length; j++) if (endpoints[j] === endpoint) throw lockedEndpoint();
        endpoints[endpoints.length] = endpoint;
      }
    }
    if (!hasWeb) {
      return receiver === undefined ? apply(coreCompose, stream, values) :
        apply(coreReadableCompose, receiver, [values[1], config]);
    }
    // Single Web streams use the same generic Duplex adoption, including
    // disabled halves and byte-mode boundaries, rather than a new wrapper.
    if (values.length === 1) return from(values[0]);
    const owner = pipelineOwner();
    try {
      const stages = [];
      for (let i = 0; i < values.length; i++) {
        stages[i] = adaptPipelineStage(values[i], shapes[i], owner, {
          readable: i < values.length - 1, writable: i > 0
        });
      }
      const output = receiver === undefined ? apply(coreCompose, stream, stages) :
        apply(coreReadableCompose, receiver, [stages[1], config]);
      // Core composition's destructor drains its own pipeline first. Delay
      // its callback until any adopted-but-unregistered endpoint is closed
      // and the internal reader locks have been released. Never wait for the
      // outer stream's close from inside its own destructor.
      const originalDestroy = output._destroy;
      const onClose = function () {
        apply(remove, output, ['close', onClose]);
        owner.finish(output.errored, function () {});
      };
      if (output.closed) onClose();
      else {
        apply(on, output, ['close', onClose]);
        property(output, '_destroy', function (error, callback) {
          let called = false;
          function done(reason) {
            if (called) return;
            called = true;
            apply(remove, output, ['close', onClose]);
            owner.finish(reason, function () { callback(reason); });
          }
          try { apply(originalDestroy, this, [error, done]); }
          catch (reason) { done(failure(reason)); }
        });
      }
      return output;
    } catch (error) { owner.finish(failure(error), function () {}); throw error; }
  }
  function compose(...stages) { return composeOwned(stages, undefined, undefined); }
  function readableCompose(stage, settings) {
    // Read the signal exactly once and validate it before adopting a Web
    // endpoint. The core keeps ownership of abort propagation and its cause.
    const input = options(settings), config = create(null);
    config.signal = input.signal;
    if (config.signal !== undefined) apply(aborted, config.signal, []);
    return composeOwned([this, stage], this, config);
  }
  if (typeof coreCompose === 'function' && typeof coreReadableCompose === 'function') {
    property(stream, 'compose', compose);
    const d = create(null); d.value = readableCompose; d.writable = true; d.configurable = true;
    define(R.prototype, 'compose', d);
  }
  return stream;
})
