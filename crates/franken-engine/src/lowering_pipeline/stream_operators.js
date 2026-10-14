(function installReadableOperators(Stream) {
  'use strict';
  // This factory is parsed together with stream_module.js by native lowering.
  // There is no host/runtime delegation: work, promises, queue entries and
  // callback values stay in the engine's existing interpreter-managed heap.
  const Readable = Stream.Readable;
  const from = Readable.from;
  const apply = Reflect.apply;
  const PromiseClass = Promise;
  const resolvePromise = Promise.resolve;
  const promiseThen = Promise.prototype.then;
  const Controller = AbortController;
  const controllerAbort = Controller.prototype.abort;
  const controllerSignal = Object.getOwnPropertyDescriptor(Controller.prototype, 'signal').get;
  const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
  const signalReason = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'reason').get;
  const anySignal = AbortSignal.any;
  const addEvent = EventTarget.prototype.addEventListener;
  const removeEvent = EventTarget.prototype.removeEventListener;
  const defineProperty = Object.defineProperty;
  const createObject = Object.create;
  const asyncIteratorKey = Symbol.asyncIterator;
  const iteratorKey = Symbol.iterator;
  const floor = Math.floor;
  const NumberClass = Number;
  const arrayIsArray = Array.isArray;
  const SetClass = Set;
  const setAdd = Set.prototype.add;
  const setDelete = Set.prototype.delete;
  const setForEach = Set.prototype.forEach;
  const setClear = Set.prototype.clear;
  const MAX_SAFE_INTEGER = 9007199254740991;

  function resolved(value) { return apply(resolvePromise, PromiseClass, [value]); }
  function then(promise, success, failure) {
    return apply(promiseThen, promise, [success, failure]);
  }
  function failure(code, message, Range) {
    const error = Range ? new RangeError(message) : new TypeError(message);
    error.code = code;
    return error;
  }
  function abortError(signal) {
    const error = new Error('The operation was aborted');
    error.name = 'AbortError';
    error.code = 'ABORT_ERR';
    const descriptor = createObject(null);
    descriptor.value = apply(signalReason, signal, []);
    descriptor.writable = true;
    descriptor.configurable = true;
    defineProperty(error, 'cause', descriptor);
    return error;
  }
  function optionsFor(options, concurrent) {
    if (options == null) options = {};
    if (typeof options !== 'object' || arrayIsArray(options)) {
      throw failure('ERR_INVALID_ARG_TYPE', 'The "options" argument must be an object');
    }
    const signal = options.signal;
    if (signal != null) {
      try { apply(signalAborted, signal, []); }
      catch (error) { throw failure('ERR_INVALID_ARG_TYPE', 'The "options.signal" argument must be an AbortSignal'); }
    }
    let concurrency = 1;
    let highWaterMark = 0;
    if (concurrent) {
      const c = options.concurrency;
      if (c != null) concurrency = floor(c);
      if (!(concurrency >= 1 && concurrency <= MAX_SAFE_INTEGER)) {
        throw failure('ERR_OUT_OF_RANGE', 'The "options.concurrency" option must be a positive safe integer', true);
      }
      const h = options.highWaterMark;
      highWaterMark = h == null ? concurrency - 1 : floor(h);
      if (!(highWaterMark >= 0 && highWaterMark <= MAX_SAFE_INTEGER)) {
        throw failure('ERR_OUT_OF_RANGE', 'The "options.highWaterMark" option must be a non-negative safe integer', true);
      }
    }
    return { signal: signal == null ? undefined : signal, concurrency: concurrency,
      capacity: concurrency + highWaterMark };
  }
  function callback(fn) {
    if (typeof fn !== 'function') throw failure('ERR_INVALID_ARG_TYPE', 'The "fn" argument must be a function');
  }

  // Do not let a replaced Array iterator change private abort dependencies.
  function signalSources(external, internal) {
    const sources = [external, internal];
    const descriptor = createObject(null);
    descriptor.value = function () {
      let position = 0;
      return { next: function () {
        if (position++ === 0) return { value: external, done: false };
        if (position === 2) return { value: internal, done: false };
        return { value: undefined, done: true };
      } };
    };
    defineProperty(sources, iteratorKey, descriptor);
    return sources;
  }

  function scopeFor(external, wake) {
    const controller = new Controller();
    const ownSignal = apply(controllerSignal, controller, []);
    const signal = external === undefined ? ownSignal : anySignal(signalSources(external, ownSignal));
    let stopped = false;
    let listening = true;
    let cancellation;
    const pending = new SetClass();
    function isAborted() {
      return stopped || apply(signalAborted, signal, []) ||
        (external !== undefined && apply(signalAborted, external, []));
    }
    function reason() {
      if (cancellation === undefined) {
        const source = external !== undefined && apply(signalAborted, external, []) ? external : signal;
        cancellation = abortError(source);
      }
      return cancellation;
    }
    function onAbort() {
      // A source's native state is published before dependent public events.
      // Every publication path checks it too, so stopImmediatePropagation or
      // a synthetic abort event cannot grant late callback publication.
      if (!isAborted()) return;
      apply(setForEach, pending, [function (reject) { reject(reason()); }]);
      apply(setClear, pending, []);
      wake();
    }
    // A synthetic event must not consume cancellation ownership before the
    // native aborted flag is set. release() removes this private listener.
    apply(addEvent, signal, ['abort', onAbort]);
    function check() { if (isAborted()) throw reason(); }
    function race(promise) {
      return new PromiseClass(function (resolve, reject) {
        // next()/a callback may synchronously abort and then return a rejected
        // promise. Always observe that promise, including an already-stopped
        // operation, or cancellation creates an unhandled rejection.
        apply(setAdd, pending, [reject]);
        then(resolved(promise), function (value) {
          apply(setDelete, pending, [reject]);
          try { check(); resolve(value); } catch (error) { reject(error); }
        }, function (error) {
          apply(setDelete, pending, [reject]);
          reject(error);
        });
        try { check(); } catch (error) {
          apply(setDelete, pending, [reject]);
          reject(error);
        }
      });
    }
    return {
      signal: signal, check: check, race: race,
      abort: function () {
        if (!stopped) {
          stopped = true;
          apply(controllerAbort, controller, [null]);
          onAbort();
        }
      },
      release: function () {
        if (listening) {
          listening = false;
          apply(removeEvent, signal, ['abort', onAbort]);
        }
        // Break the native any() dependency on a long-lived caller signal.
        // No operation listener remains to interpret success as failure.
        if (!stopped) { stopped = true; apply(controllerAbort, controller, [null]); }
        apply(setClear, pending, []);
      }
    };
  }

  // A linked FIFO releases completed values immediately and never shifts an
  // array or retains an unbounded consumed prefix. The producer has one
  // outstanding upstream read; callback concurrency and buffered results are
  // bounded independently. Results (including failures) stay in input order.
  function concurrentIterator(source, fn, config, mode, operation) {
    return (async function* () {
      let head;
      let tail;
      let queued = 0;
      let active = 0;
      let done = false;
      let stopped = false;
      let failed = false;
      let changed;
      let upstream;
      let upstreamDone = false;
      let inner;
      let innerIterator;
      function wake() { const resolve = changed; changed = undefined; if (resolve) resolve(); }
      function wait() { return new PromiseClass(function (resolve) { changed = resolve; }); }
      const scope = scopeFor(config.signal, wake);
      function cancel() { stopped = true; scope.abort(); wake(); }
      operation.cancel = cancel;
      function push(value) {
        const slot = { input: value, value: undefined, error: undefined, failed: false, ready: false, next: undefined };
        if (tail === undefined) head = slot; else tail.next = slot;
        tail = slot;
        queued++;
        return slot;
      }
      function settle(slot, value, error, isFailure) {
        active--;
        if (stopped) return;
        slot.value = value;
        slot.error = error;
        slot.failed = isFailure;
        slot.ready = true;
        if (isFailure) failed = true;
        wake();
      }
      async function pump() {
        try {
          scope.check();
          upstream = source[asyncIteratorKey]();
          while (!stopped && !failed) {
            // This loop's wait is independent of the consumer's wait: one
            // notification wakes both without accumulating promise reactions.
            while (!stopped && !failed && (active >= config.concurrency || queued >= config.capacity)) {
              await capacityWait();
            }
            if (stopped || failed) break;
            scope.check();
            const step = await scope.race(upstream.next());
            if (step.done) { upstreamDone = true; break; }
            scope.check();
            if (stopped || failed) break;
            const slot = push(step.value);
            active++;
            try {
              const value = fn(step.value, { signal: scope.signal });
              then(resolved(value), function (value) { settle(slot, value, undefined, false); capacityWake(); },
                function (error) { settle(slot, undefined, error, true); capacityWake(); });
            } catch (error) { settle(slot, undefined, error, true); }
            wake();
          }
        } catch (error) {
          if (!stopped) {
            const slot = push(undefined);
            slot.failed = true;
            slot.error = error;
            slot.ready = true;
          }
        } finally { done = true; wake(); }
      }
      let capacityChanged;
      function capacityWait() { return new PromiseClass(function (resolve) { capacityChanged = resolve; }); }
      function capacityWake() { const resolve = capacityChanged; capacityChanged = undefined; if (resolve) resolve(); }
      const cancelWork = cancel;
      operation.cancel = function () { cancelWork(); capacityWake(); };
      // The pump catches its failures into ordered slots. It is not detached
      // user work; cancellation always wakes its capacity wait and retires it.
      const pumping = pump();
      try {
        while (true) {
          scope.check();
          while (head === undefined || !head.ready) {
            if (head === undefined && done) return;
            await scope.race(wait());
          }
          scope.check();
          const slot = head;
          head = slot.next;
          if (head === undefined) tail = undefined;
          slot.next = undefined;
          queued--;
          capacityWake();
          if (slot.failed) throw slot.error;
          if (mode === 'filter') {
            if (slot.value) yield slot.input;
          } else if (mode === 'flatMap') {
            inner = slot.value;
            // Delegate through an async generator for the language's own
            // AsyncFromSyncIterator, promise unwrapping and result validation.
            // No array/Buffer materialization: pull an inner value on demand.
            innerIterator = (async function* () { yield* inner; })();
            let innerDone = false;
            try {
              while (true) {
                const step = await scope.race(innerIterator.next());
                if (step.done) { innerDone = true; break; }
                scope.check();
                yield step.value;
              }
            } finally {
              // Interrupt native Readable reads before waiting for return().
              // Arbitrary async iterators must still cooperate with close.
              if (!innerDone) {
                if (typeof (inner && inner.destroy) === 'function' && !inner.destroyed) inner.destroy();
                await innerIterator.return();
              }
              innerIterator = undefined;
              inner = undefined;
            }
          } else {
            yield slot.value;
          }
        }
      } finally {
        stopped = true;
        operation.cancel = undefined;
        scope.abort();
        capacityWake();
        wake();
        head = undefined;
        tail = undefined;
        queued = 0;
        try {
          if (upstream !== undefined && !upstreamDone) {
            // A pending Readable.next() must be unblocked before awaiting its
            // generator return(). Otherwise an idle input strands destroy().
            if (typeof source.destroy === 'function' && !source.destroyed) source.destroy();
            if (typeof upstream.return === 'function') await upstream.return();
          }
          await pumping;
        } finally { scope.release(); }
      }
    })();
  }

  function readableFromOperation(iterator, operation) {
    const result = apply(from, Readable, [iterator, { objectMode: true, highWaterMark: 1 }]);
    const originalDestroy = result._destroy;
    result._destroy = function (error, done) {
      // AsyncGenerator.return alone queues behind an in-flight await. Cancel
      // the operation first so even a never-settling mapper cannot pin it.
      if (operation.cancel !== undefined) operation.cancel();
      return apply(originalDestroy, this, [error, done]);
    };
    return result;
  }
  function mapped(source, fn, options, mode) {
    callback(fn);
    const config = optionsFor(options, true);
    const operation = {};
    return readableFromOperation(concurrentIterator(source, fn, config, mode, operation), operation);
  }
  function map(fn, options) { return mapped(this, fn, options, 'map'); }
  function filter(fn, options) { return mapped(this, fn, options, 'filter'); }
  function flatMap(fn, options) { return mapped(this, fn, options, 'flatMap'); }

  function limited(source, limit, options, taking) {
    // Node coerces counts once: fractions consume ceil(count) chunks, NaN
    // behaves like zero, and Infinity is useful for unbounded sources.
    const remaining = NumberClass(limit);
    if (remaining < 0) {
      throw failure('ERR_OUT_OF_RANGE', 'The "limit" argument must be non-negative', true);
    }
    const config = optionsFor(options, false);
    const operation = {};
    const iterator = (async function* () {
      const scope = scopeFor(config.signal, function () {});
      let upstream;
      let done = false;
      let count = remaining;
      operation.cancel = function () { scope.abort(); };
      try {
        scope.check();
        upstream = source[asyncIteratorKey]();
        // Pull on demand rather than implementing slicing as filter/map:
        // no callback, worker queue, or counter retained for every chunk.
        // Even take(0) admits one read, as the Node stream operator does.
        while (true) {
          const step = await scope.race(upstream.next());
          if (step.done) { done = true; return; }
          scope.check();
          if (taking) {
            if (count > 0) {
              count--;
              yield step.value;
            }
            if (!(count > 0)) return;
          } else if (count > 0) {
            count--;
          } else {
            yield step.value;
          }
        }
      } finally {
        operation.cancel = undefined;
        scope.abort();
        try {
          if (upstream !== undefined && !done) {
            // Release the source on a satisfied take, early break, or abort.
            // Destroy first to wake a native Readable.next() before closing
            // the iterator; arbitrary async iterators must cooperate.
            if (typeof source.destroy === 'function' && !source.destroyed) source.destroy();
            if (typeof upstream.return === 'function') await upstream.return();
          }
        } finally { scope.release(); }
      }
    })();
    return readableFromOperation(iterator, operation);
  }
  function take(limit, options) { return limited(this, limit, options, true); }
  function drop(limit, options) { return limited(this, limit, options, false); }

  async function consumeSequential(source, config, visit) {
    // Collectors and concurrency-one sinks need neither a worker queue nor a
    // mapped output stream. One abortable upstream read and, only when the
    // visitor is asynchronous, one abortable callback are live at a time.
    const scope = scopeFor(config.signal, function () {});
    let iterator;
    let done = false;
    try {
      scope.check();
      iterator = source[asyncIteratorKey]();
      while (true) {
        const step = await scope.race(iterator.next());
        if (step.done) { done = true; break; }
        scope.check();
        const pending = visit(step.value, { signal: scope.signal });
        if (pending !== undefined) await scope.race(pending);
      }
    } finally {
      scope.abort();
      try {
        if (iterator !== undefined && !done) {
          if (typeof source.destroy === 'function' && !source.destroyed) source.destroy();
          if (typeof iterator.return === 'function') await iterator.return();
        }
      } finally { scope.release(); }
    }
  }
  async function toArray(options) {
    const config = optionsFor(options, false);
    const values = [];
    // Only this explicit collecting API retains all consumed chunks.
    await consumeSequential(this, config, function (value) { values.push(value); });
    return values;
  }
  async function forEach(fn, options) {
    callback(fn);
    const config = optionsFor(options, true);
    if (config.concurrency === 1) {
      await consumeSequential(this, config, fn);
    } else {
      const iterator = concurrentIterator(this, fn, config, 'map', {});
      for await (const value of iterator) { /* Await callbacks without retaining their results. */ }
    }
  }
  async function some(fn, options) {
    callback(fn);
    const iterator = concurrentIterator(this, fn, optionsFor(options, true), 'filter', {});
    for await (const value of iterator) return true;
    return false;
  }
  async function every(fn, options) {
    callback(fn);
    const inverse = async function (value, context) { return !(await fn(value, context)); };
    const iterator = concurrentIterator(this, inverse, optionsFor(options, true), 'filter', {});
    for await (const value of iterator) return false;
    return true;
  }
  async function find(fn, options) {
    callback(fn);
    const iterator = concurrentIterator(this, fn, optionsFor(options, true), 'filter', {});
    for await (const value of iterator) return value;
    return undefined;
  }
  async function reduce(fn, initial, options) {
    callback(fn);
    const config = optionsFor(options, false);
    let hasValue = arguments.length >= 2;
    let accumulated = initial;
    const step = async function (value, context) {
      if (hasValue) accumulated = await fn(accumulated, value, context);
      else { accumulated = value; hasValue = true; }
    };
    await consumeSequential(this, config, step);
    if (!hasValue) throw failure('ERR_MISSING_ARGS', 'Reduce of an empty stream requires an initial value');
    return accumulated;
  }
  function install(name, value) {
    const descriptor = createObject(null);
    descriptor.value = value;
    descriptor.writable = true;
    descriptor.configurable = true;
    defineProperty(Readable.prototype, name, descriptor);
  }
  install('map', map);
  install('filter', filter);
  install('flatMap', flatMap);
  install('take', take);
  install('drop', drop);
  install('toArray', toArray);
  install('forEach', forEach);
  install('some', some);
  install('every', every);
  install('find', find);
  install('reduce', reduce);
  return Stream;
})
