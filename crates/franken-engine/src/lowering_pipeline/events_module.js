(function () {
  'use strict';
  // Obtain the native, branded constructor. Listener storage, dispatch, IFC,
  // and memory accounting remain in the existing EventEmitter implementation.
  var EventEmitter = __franken_events_constructor();

  // Capture the native signal operations before guest code can replace public
  // methods. A private dependent signal cannot have its abort event stopped by
  // a listener on the caller's signal. Its second source lets completed waits
  // detach through the native abort-graph cleanup instead of retaining one
  // dependent on a long-lived caller signal for each completed operation.
  // Dependent events run after the source's public event. Delivery paths below
  // therefore consult native aborted state too; synthetic public abort events
  // do not cancel work. This is an API cancellation boundary, not execution
  // preemption, and assumes genuine realm intrinsics at module initialization.
  var Controller = AbortController;
  var composeSignal = AbortSignal.any;
  var apply = Reflect.apply;
  var defineProperty = Object.defineProperty;
  var createObject = Object.create;
  var iteratorKey = Symbol.iterator;
  var controllerSignal = Object.getOwnPropertyDescriptor(AbortController.prototype, 'signal').get;
  var signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
  var signalReason = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'reason').get;
  var abortController = AbortController.prototype.abort;
  var addListener = EventTarget.prototype.addEventListener;
  var removeListener = EventTarget.prototype.removeEventListener;

  function isAborted(signal) { return apply(signalAborted, signal, []); }
  function signalPair(first, second) {
    var pair = [first, second];
    // The native any() consumes an iterable. Do not let guest replacement of
    // Array.prototype's iterator change these private cancellation sources.
    // Keep a real array for Node's Array-only reference implementation too.
    var descriptor = createObject(null);
    descriptor.value = function () {
      var index = 0;
      return {
        next: function () {
          if (index === 0) { index = 1; return { value: first, done: false }; }
          if (index === 1) { index = 2; return { value: second, done: false }; }
          return { value: undefined, done: true };
        },
        return: function () { index = 2; return { value: undefined, done: true }; }
      };
    };
    defineProperty(pair, iteratorKey, descriptor);
    return pair;
  }
  function protectedAbort(signal, listener) {
    var release = new Controller();
    var dependent;
    var disposed = false;
    function dispose() {
      if (disposed) { return; }
      disposed = true;
      try {
        if (dependent !== undefined) {
          apply(removeListener, dependent, ['abort', listener]);
        }
      } finally {
        // Remove the listener first: disposal must not report cancellation.
        // This source and its dependent are private and cannot call guest code.
        // A private null reason avoids allocating a default DOMException.
        apply(abortController, release, [null]);
      }
    }
    try {
      dependent = composeSignal(signalPair(signal, apply(controllerSignal, release, [])));
      apply(addListener, dependent, ['abort', listener,
        { once: true, capture: false, passive: false, signal: undefined }]);
    } catch (error) {
      try { dispose(); } finally { throw error; }
    }
    return dispose;
  }

  function invalidType(name) {
    var error = new TypeError('Invalid ' + name);
    error.code = 'ERR_INVALID_ARG_TYPE';
    return error;
  }
  function optionsObject(options) {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) {
      throw invalidType('options');
    }
    return options;
  }
  function abortSignal(signal) {
    if (signal !== undefined) {
      // Authenticate through the native accessor, not guest-replaceable
      // properties or methods. Duck-typed lookalikes confer no cancellation.
      try { isAborted(signal); }
      catch (error) { throw invalidType('options.signal'); }
    }
    return signal;
  }
  function aborted(signal) {
    var error = new Error('The operation was aborted');
    error.name = 'AbortError';
    error.code = 'ABORT_ERR';
    var descriptor = createObject(null);
    descriptor.value = apply(signalReason, signal, []);
    descriptor.writable = true;
    descriptor.configurable = true;
    defineProperty(error, 'cause', descriptor);
    return error;
  }

  // Register removers before calling user-observable listener APIs. A
  // newListener callback can complete/abort the operation during registration;
  // after registration, remove again if close already ran. Exceptions roll
  // back every prior listener, including partially registered listeners.
  function subscriptions(emitter) {
    var nativeEmitter = emitter !== null && emitter !== undefined &&
      typeof emitter.on === 'function' && typeof emitter.removeListener === 'function';
    var eventTarget = !nativeEmitter && emitter !== null && emitter !== undefined &&
      typeof emitter.addEventListener === 'function' && typeof emitter.removeEventListener === 'function';
    if (!nativeEmitter && !eventTarget) {
      throw invalidType('emitter');
    }
    var removers = [];
    var closed = false;
    function close() {
      if (closed) { return; }
      closed = true;
      var pending = removers;
      removers = [];
      var firstError;
      var failed = false;
      for (var i = 0; i < pending.length; i++) {
        try { pending[i](); } catch (error) {
          if (!failed) { failed = true; firstError = error; }
        }
      }
      if (failed) { throw firstError; }
    }
    function register(add, remove) {
      if (closed) { return; }
      removers.push(remove);
      try { add(); } catch (error) {
        try { close(); } finally { throw error; }
      }
      if (closed) { remove(); }
    }
    return {
      isEmitter: nativeEmitter,
      close: close,
      event: function (name, listener) {
        register(function () {
          if (nativeEmitter) { emitter.on(name, listener); }
          else { emitter.addEventListener(name, listener); }
        }, function () {
          if (nativeEmitter) { emitter.removeListener(name, listener); }
          else { emitter.removeEventListener(name, listener); }
        });
      },
      abort: function (signal, listener) {
        if (signal === undefined || closed) { return; }
        var dispose = function () {};
        register(function () { dispose = protectedAbort(signal, listener); },
          function () { dispose(); });
        // The signal may have changed while another listener was installed.
        if (!closed && isAborted(signal)) { listener(); }
      }
    };
  }

  function once(emitter, eventName, options = {}) {
    var signal;
    try {
      signal = abortSignal(optionsObject(options).signal);
      if (signal !== undefined && isAborted(signal)) { throw aborted(signal); }
      // Preserve the native Promise/IFC path and its reaction ordering when
      // there is no cancellation obligation to attach.
      var isEventTarget = emitter !== null && emitter !== undefined &&
        typeof emitter.on !== 'function' && typeof emitter.addEventListener === 'function';
      if (signal === undefined && !isEventTarget) { return __franken_events_once(emitter, eventName); }
    } catch (error) { return Promise.reject(error); }
    // Node's once awaits its internal event Promise before settling the
    // returned Promise. Preserve that reaction boundary for the adapter path
    // too (the native no-signal path above already owns its Promise contract).
    return new Promise(function (resolve, reject) {
      var links = subscriptions(emitter);
      var settled = false;
      function finish(error, values, failed) {
        if (settled) { return; }
        // Native state is published before public abort listeners. A listener
        // on that public event must not race cancellation by emitting success
        // while the private dependent's abort event is still awaiting delivery.
        if (signal !== undefined && isAborted(signal)) {
          error = aborted(signal); values = undefined; failed = true;
        }
        settled = true;
        try { links.close(); } catch (cleanupError) { reject(cleanupError); return; }
        if (failed) { reject(error); } else { resolve(values); }
      }
      try {
        links.event(eventName, function (...values) { finish(undefined, values, false); });
        if (eventName !== 'error' && links.isEmitter) {
          links.event('error', function (error) { finish(error, undefined, true); });
        }
        links.abort(signal, function () { finish(aborted(signal), undefined, true); });
      } catch (error) { finish(error, undefined, true); }
    }).then();
  }

  // Linked FIFOs release dequeued nodes without array shifting or retaining
  // an ever-growing prefix. Values and waiting resolvers are ordinary
  // interpreter-managed objects, not unaccounted Rust-side storage.
  function queue() { return { first: null, last: null, size: 0 }; }
  function put(queue, value) {
    var node = { value: value, next: null };
    if (queue.last === null) { queue.first = node; } else { queue.last.next = node; }
    queue.last = node;
    queue.size++;
  }
  function take(queue) {
    var node = queue.first;
    queue.first = node.next;
    if (queue.first === null) { queue.last = null; }
    queue.size--;
    return node.value;
  }
  function watermark(options, current, legacy, fallback) {
    var value = options[current];
    if (value === undefined || value === null) { value = options[legacy]; }
    if (value === undefined || value === null) { return fallback; }
    if (typeof value !== 'number') { throw invalidType('options.' + current); }
    if (value < 1 || value > 9007199254740991 || value % 1 !== 0) {
      var error = new RangeError('Invalid options.' + current);
      error.code = 'ERR_OUT_OF_RANGE';
      throw error;
    }
    return value;
  }
  function on(emitter, eventName, options = {}) {
    optionsObject(options);
    var signal = abortSignal(options.signal);
    if (signal !== undefined && isAborted(signal)) { throw aborted(signal); }
    var high = watermark(options, 'highWaterMark', 'highWatermark', 9007199254740991);
    var low = watermark(options, 'lowWaterMark', 'lowWatermark', 1);
    var closeEvents = options.close;
    var links = subscriptions(emitter);
    var values = queue();
    var waiters = queue();
    var finished = false;
    var paused = false;
    var hasError = false;
    var terminalError;
    function result(value, done) { return { value: value, done: done }; }
    function finish(error, failed) {
      if (finished) { return; }
      if (signal !== undefined && isAborted(signal)) {
        error = aborted(signal); failed = true;
      }
      finished = true;
      try { links.close(); } catch (cleanupError) { error = cleanupError; failed = true; }
      if (failed && waiters.size > 0) { take(waiters).reject(error); }
      else if (failed) { hasError = true; terminalError = error; }
      while (waiters.size > 0) { take(waiters).resolve(result(undefined, true)); }
    }
    function event(...args) {
      if (finished) { return; }
      if (signal !== undefined && isAborted(signal)) { fail(aborted(signal)); return; }
      if (waiters.size > 0) { take(waiters).resolve(result(args, false)); }
      else {
        put(values, args);
        if (!paused && values.size > high) {
          paused = true;
          emitter.pause();
        }
      }
    }
    function fail(error) { finish(error, true); }
    function close() { finish(undefined, false); }
    var iterator = {
      next: function () {
        if (!finished && signal !== undefined && isAborted(signal)) { fail(aborted(signal)); }
        if (values.size > 0) {
          var value = take(values);
          if (paused && values.size < low) { paused = false; emitter.resume(); }
          return Promise.resolve(result(value, false));
        }
        if (hasError) {
          hasError = false;
          var error = terminalError;
          terminalError = undefined;
          return Promise.reject(error);
        }
        if (finished) { return Promise.resolve(result(undefined, true)); }
        return new Promise(function (resolve, reject) { put(waiters, { resolve: resolve, reject: reject }); });
      },
      return: function () { close(); return Promise.resolve(result(undefined, true)); },
      throw: function (error) {
        if (!(error instanceof Error)) { throw invalidType('error'); }
        // Explicit iterator injection is permitted even after return/close,
        // and replaces an as-yet-unconsumed terminal error.
        if (finished) { hasError = true; terminalError = error; }
        else { fail(error); }
      }
    };
    iterator[Symbol.asyncIterator] = function () { return this; };
    try {
      links.event(eventName, event);
      if (eventName !== 'error' && links.isEmitter) { links.event('error', fail); }
      if (closeEvents !== undefined && closeEvents !== null) {
        for (var i = 0; i < closeEvents.length; i++) { links.event(closeEvents[i], close); }
      }
      links.abort(signal, function () { fail(aborted(signal)); });
    } catch (error) {
      // Construction did not return an iterator, so nobody can consume its
      // terminal state. Remove its native listeners and propagate the error.
      try { links.close(); } finally { throw error; }
    }
    return iterator;
  }
  EventEmitter.EventEmitter = EventEmitter;
  EventEmitter.once = once;
  EventEmitter.on = on;
  // Node's constant statics (bd-9vouw.210): a native emitter's default
  // maximum is 10. errorMonitor is the key Node gives listeners that see
  // 'error' first; the native emitter does not dispatch to it yet.
  EventEmitter.defaultMaxListeners = 10;
  EventEmitter.errorMonitor = Symbol('events.errorMonitor');
  EventEmitter.captureRejections = false;
  return EventEmitter;
})()