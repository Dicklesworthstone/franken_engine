(function () {
  'use strict';
  // Non-terminal readline over the canonical events and string_decoder
  // modules. Input/output streams keep ownership of their own I/O authority.
  // No host filesystem, process reader, evaluation fallback or terminal mode.
  const E = __franken_readline_events;
  const Decoder = __franken_readline_decoder.StringDecoder;
  const apply = Reflect.apply;
  const create = Object.create;
  const define = Object.defineProperty;
  const setPrototype = Object.setPrototypeOf;
  const getDescriptor = Object.getOwnPropertyDescriptor;
  const Weak = WeakMap;
  const weakGet = WeakMap.prototype.get;
  const weakSet = WeakMap.prototype.set;
  const decode = Decoder.prototype.write;
  const emit = E.prototype.emit;
  const eventsOn = E.on;
  const addAbort = E.addAbortListener;
  const asyncKey = Symbol.asyncIterator;
  const iteratorKey = Symbol.iterator;
  const disposeKey = Symbol.dispose;
  const Abort = AbortController;
  const abortController = AbortController.prototype.abort;
  const controllerSignal = getDescriptor(AbortController.prototype, 'signal').get;
  const Signals = AbortSignal;
  const anySignal = AbortSignal.any;
  const signalAborted = getDescriptor(AbortSignal.prototype, 'aborted').get;
  const signalReason = getDescriptor(AbortSignal.prototype, 'reason').get;
  const P = Promise;
  const promiseResolve = Promise.resolve;
  const promiseThen = Promise.prototype.then;
  const slice = String.prototype.slice;
  const codeAt = String.prototype.charCodeAt;
  const indexOf = String.prototype.indexOf;
  const join = [].join;
  const asString = String;
  const now = Date.now;
  const Type = TypeError;
  const ErrorClass = Error;
  const states = new Weak();

  function error(code, message, type) {
    const e = type ? new Type(message) : new ErrorClass(message);
    e.code = code;
    return e;
  }
  function invalid(name) { return error('ERR_INVALID_ARG_TYPE', 'Invalid ' + name, true); }
  function closedError() { return error('ERR_USE_AFTER_CLOSE', 'readline was closed'); }
  function iteratorDone() { return apply(promiseResolve, P, [{ value: undefined, done: true }]); }
  function unsupported() {
    return error('ERR_READLINE_TERMINAL_UNSUPPORTED', 'Terminal editing is not supported by this readline implementation');
  }
  function then(promise, yes, no) { return apply(promiseThen, promise, [yes, no]); }
  function textSlice(text, start, end) { return apply(slice, text, [start, end]); }
  function code(text, at) { return apply(codeAt, text, [at]); }
  function state(rl) {
    const s = apply(weakGet, states, [rl]);
    if (s === undefined) throw invalid('Interface receiver');
    return s;
  }
  function property(object, key, value) {
    const d = create(null);
    d.value = value; d.writable = true; d.configurable = true;
    define(object, key, d);
  }
  function signal(value) {
    if (value !== undefined) {
      try { apply(signalAborted, value, []); }
      catch (e) { throw invalid('options.signal'); }
    }
    return value;
  }
  function isAborted(value) { return value !== undefined && apply(signalAborted, value, []); }
  function abortError(value) {
    const e = error('ABORT_ERR', 'The operation was aborted');
    e.name = 'AbortError';
    const d = create(null);
    d.value = apply(signalReason, value, []); d.writable = true; d.configurable = true;
    define(e, 'cause', d);
    return e;
  }
  function watch(value, listener) {
    if (value === undefined) return function () {};
    // The caller can synthesize an abort event or stop its propagation. Use
    // a private dependent signal, and an owned source to detach the native
    // dependency graph on completion. Merely observing an event is not abort.
    const own = new Abort(), ownSignal = apply(controllerSignal, own, []);
    const sources = [value, ownSignal];
    property(sources, iteratorKey, function () {
      let index = 0;
      return { next: function () {
        if (index++ === 0) return { value: value, done: false };
        if (index === 2) return { value: ownSignal, done: false };
        return { value: undefined, done: true };
      } };
    });
    const dependent = apply(anySignal, Signals, [sources]);
    let subscription, disposed = false;
    function dispose() {
      if (disposed) return;
      disposed = true;
      try {
        if (subscription !== undefined) apply(subscription[disposeKey], subscription, []);
      } finally { apply(abortController, own, [null]); }
    }
    try {
      subscription = addAbort(dependent, function () {
        if (!disposed && isAborted(value)) listener();
      });
    } catch (e) { dispose(); throw e; }
    return dispose;
  }
  function queue() { const q = create(null); q.head = undefined; q.tail = undefined; return q; }
  function append(q, value) {
    const node = create(null); node.value = value; node.next = undefined;
    if (q.tail === undefined) q.head = node; else q.tail.next = node;
    q.tail = node;
  }
  function take(q) {
    const node = q.head; q.head = node.next;
    if (q.head === undefined) q.tail = undefined;
    node.next = undefined;
    return node.value;
  }
  function fragmentParts() {
    // These lists are private storage, not guest arrays. Removing the inherited
    // indexed setters keeps an append from calling guest code or losing data.
    // The captured join is generic and only needs own length/index properties.
    return setPrototype([], null);
  }
  function fragments() {
    const q = queue(); q.pending = fragmentParts(); q.units = 0; return q;
  }
  function flushFragments(q) {
    const pending = q.pending;
    if (pending.length === 0) return;
    const text = pending.length === 1 ? pending[0] : apply(join, pending, ['']);
    q.pending = fragmentParts(); q.units = 0;
    append(q, text);
  }
  function appendFragment(q, text) {
    // Bound per-chunk metadata for highly fragmented, unterminated lines.
    // Each small fragment participates in at most one batch join and the
    // final line join; never repeatedly join the entire accumulated prefix.
    if (text.length >= 16384) {
      flushFragments(q);
      append(q, text);
      return;
    }
    q.pending[q.pending.length] = text;
    q.units += text.length;
    if (q.pending.length >= 64 || q.units >= 16384) flushFragments(q);
  }
  function joinFragments(q) {
    flushFragments(q);
    if (q.head === undefined) return '';
    const first = take(q);
    if (q.head === undefined) return first;
    const parts = fragmentParts(); parts[0] = first;
    while (q.head !== undefined) parts[parts.length] = take(q);
    return apply(join, parts, ['']);
  }
  function validate(input, output, completer, terminal) {
    let o;
    if (input !== null && typeof input === 'object' && typeof input.on !== 'function') {
      o = input; input = o.input; output = o.output; terminal = o.terminal;
    } else o = create(null);
    if (input === null || input === undefined || typeof input.on !== 'function' ||
        typeof input.removeListener !== 'function' || typeof input.resume !== 'function' ||
        typeof input.pause !== 'function') throw invalid('input');
    if (output !== undefined && output !== null && typeof output.write !== 'function') throw invalid('output');
    if (terminal === undefined) terminal = output && output.isTTY;
    // Do not silently provide line splitting when the caller requested TTY
    // key handling, cursor state, raw mode and history ownership.
    if (terminal) throw unsupported();
    const delay = o.crlfDelay === undefined ? 100 : +o.crlfDelay;
    const result = create(null);
    result.input = input; result.output = output;
    result.prompt = o.prompt === undefined ? '> ' : asString(o.prompt);
    result.delay = delay >= 100 ? delay : 100;
    result.signal = signal(o.signal);
    return result;
  }
  function clearQuestion(s) {
    const q = s.question;
    s.question = undefined;
    if (q !== undefined) { s.prompt = q.prompt; q.dispose(); }
    return q;
  }
  function publish(rl, value) {
    const s = state(rl);
    if (s.question !== undefined && isAborted(s.question.signal)) s.question.onAbort();
    if (s.question !== undefined) {
      const q = clearQuestion(s);
      apply(q.answer, undefined, [value]);
    } else apply(emit, rl, ['line', value]);
  }
  function consume(rl, text) {
    const s = state(rl);
    let start = 0;
    if (s.afterCR && code(text, 0) === 10 &&
        (s.delay === Infinity || now() - s.crTime <= s.delay)) start = 1;
    s.afterCR = false;
    if (start === text.length) return;
    // Keep the first completed line inline. Only multi-line chunks need a
    // publication list, and that private list has no inherited indexed hooks.
    let firstLine, lines;
    // Scan ONLY newly decoded text, using native search rather than one
    // interpreted charCodeAt call per code unit. Keep independent cursors:
    // recomputing a missing CR for every LF (or vice versa) would rescan the
    // whole remaining suffix and become quadratic on single-delimiter input.
    // A -1 cursor stays exhausted for this chunk. No all-matches array or
    // persistent search state is needed, and UTF-16 offsets still feed slice.
    // Finish state before publishing: callbacks may synchronously reenter.
    let lf = apply(indexOf, text, ['\n', start]);
    let cr = apply(indexOf, text, ['\r', start]);
    while (lf !== -1 || cr !== -1) {
      let at = lf === -1 || (cr !== -1 && cr < lf) ? cr : lf;
      const carriage = at === cr;
      let line;
      if (s.fragments.head === undefined && s.fragments.pending.length === 0) {
        // A complete line in this chunk needs no fragment node, batch join
        // or replacement scratch array. Slicing still preserves exact UTF-16.
        line = textSlice(text, start, at);
      } else {
        if (at > start) appendFragment(s.fragments, textSlice(text, start, at));
        line = joinFragments(s.fragments);
      }
      if (firstLine === undefined) firstLine = line;
      else {
        if (lines === undefined) lines = fragmentParts();
        lines[lines.length] = line;
      }
      if (carriage) {
        if (lf === at + 1) at++;
        else if (at + 1 === text.length) {
          s.afterCR = true;
          if (s.delay !== Infinity) s.crTime = now();
        }
      }
      start = at + 1;
      if (lf !== -1 && lf < start) lf = apply(indexOf, text, ['\n', start]);
      if (cr !== -1 && cr < start) cr = apply(indexOf, text, ['\r', start]);
    }
    if (start < text.length) appendFragment(s.fragments, textSlice(text, start));
    // close()/pause() in a line listener do not discard other complete lines
    // already received in this chunk, matching the documented Node contract.
    if (firstLine !== undefined) {
      const line = firstLine;
      firstLine = undefined;
      publish(rl, line);
    }
    for (let i = 0; lines !== undefined && i < lines.length; i++) {
      const line = lines[i];
      // Release each consumed string before guest code runs, as take() did.
      // Do not shift the remaining entries or keep prior lines alive on reentry.
      lines[i] = undefined;
      publish(rl, line);
    }
  }
  function Interface(input, output, completer, terminal) {
    if (!(this instanceof Interface)) return new Interface(input, output, completer, terminal);
    const config = validate(input, output, completer, terminal);
    apply(E, this, []);
    const rl = this, s = create(null);
    s.fragments = fragments(); s.decoder = new Decoder('utf8'); s.afterCR = false; s.crTime = 0;
    s.delay = config.delay; s.prompt = config.prompt; s.question = undefined;
    s.iterator = undefined; s.dispose = function () {}; s.removers = queue();
    s.signal = config.signal; s.closed = false;
    apply(weakSet, states, [rl, s]);
    rl.input = config.input; rl.output = config.output; rl.terminal = false;
    rl.closed = false; rl.paused = false; rl.line = '';
    function removeAll() {
      let failed = false, reason;
      while (s.removers.head !== undefined) {
        const pair = take(s.removers);
        try { apply(config.input.removeListener, config.input, [pair.name, pair.fn]); }
        catch (e) { if (!failed) { failed = true; reason = e; } }
      }
      try { s.dispose(); }
      catch (e) { if (!failed) { failed = true; reason = e; } }
      if (failed) throw reason;
    }
    s.detach = removeAll;
    function register(name, fn) {
      const pair = create(null); pair.name = name; pair.fn = fn;
      append(s.removers, pair);
      apply(config.input.on, config.input, [name, fn]);
      if (s.closed) apply(config.input.removeListener, config.input, [name, fn]);
    }
    try {
      register('error', function (reason) { apply(emit, rl, ['error', reason]); });
      register('data', function (chunk) {
        if (s.closed) return;
        if (isAborted(s.signal)) { closeInterface(rl); return; }
        consume(rl, typeof chunk === 'string' ? chunk : apply(decode, s.decoder, [chunk]));
      });
      register('end', function () {
        if (s.closed) return;
        // Node readline emits its already decoded suffix at EOF; unlike a
        // direct StringDecoder.end(), it does not flush incomplete UTF-8 bytes.
        if (s.fragments.head !== undefined || s.fragments.pending.length !== 0) {
          publish(rl, joinFragments(s.fragments));
        }
        closeInterface(rl);
      });
      s.dispose = watch(s.signal, function () { closeInterface(rl); });
      if (s.closed) s.dispose();
      if (!s.closed) apply(config.input.resume, config.input, []);
    } catch (e) {
      s.closed = true; rl.closed = true;
      try { removeAll(); }
      finally { try { config.input.pause(); } finally { throw e; } }
    }
  }
  setPrototype(Interface.prototype, E.prototype);
  setPrototype(Interface, E);
  function pauseInterface(rl) {
    state(rl);
    if (!rl.paused) { rl.paused = true; rl.input.pause(); apply(emit, rl, ['pause']); }
    return rl;
  }
  function resumeInterface(rl) {
    const s = state(rl);
    if (!s.closed && rl.paused) { rl.paused = false; rl.input.resume(); apply(emit, rl, ['resume']); }
    return rl;
  }
  function closeInterface(rl) {
    const s = state(rl);
    if (s.closed) return;
    s.closed = true; rl.closed = true;
    let failed = false, reason;
    try { clearQuestion(s); } catch (e) { failed = true; reason = e; }
    try { s.detach(); } catch (e) { if (!failed) { failed = true; reason = e; } }
    s.fragments = fragments(); s.decoder = undefined;
    try { pauseInterface(rl); } catch (e) { if (!failed) { failed = true; reason = e; } }
    try { apply(emit, rl, ['close']); } catch (e) { if (!failed) { failed = true; reason = e; } }
    if (failed) throw reason;
  }
  property(Interface.prototype, 'close', function () { closeInterface(this); });
  property(Interface.prototype, disposeKey, Interface.prototype.close);
  property(Interface.prototype, 'pause', function () { return pauseInterface(this); });
  property(Interface.prototype, 'resume', function () { return resumeInterface(this); });
  property(Interface.prototype, 'setPrompt', function (value) { state(this).prompt = asString(value); });
  property(Interface.prototype, 'getPrompt', function () { return state(this).prompt; });
  function prompt(rl) {
    const s = state(rl);
    resumeInterface(rl);
    if (rl.output !== undefined && rl.output !== null) rl.output.write(s.prompt);
  }
  property(Interface.prototype, 'prompt', function () { prompt(this); });
  property(Interface.prototype, 'write', function (data, key) {
    const s = state(this);
    if (s.closed) return;
    if (key !== undefined && key !== null) throw unsupported();
    resumeInterface(this);
    consume(this, typeof data === 'string' ? data : apply(decode, s.decoder, [data]));
  });
  function ask(rl, query, opts, answer, reject) {
    const s = state(rl);
    if (s.closed) throw closedError();
    if (typeof query !== 'string') throw invalid('query');
    if (opts === null || typeof opts !== 'object') opts = create(null);
    const requestedSignal = opts.signal;
    const sourceSignal = requestedSignal ? signal(requestedSignal) : undefined;
    if (isAborted(sourceSignal)) {
      if (reject !== undefined) reject(abortError(sourceSignal));
      return;
    }
    if (s.question !== undefined) { prompt(rl); return; }
    const q = create(null);
    q.prompt = s.prompt; q.answer = answer; q.signal = sourceSignal; q.dispose = function () {};
    q.onAbort = function () {
      if (s.question !== q || !isAborted(sourceSignal)) return;
      clearQuestion(s);
      if (reject !== undefined) reject(abortError(sourceSignal));
    };
    s.question = q; s.prompt = query;
    try {
      q.dispose = watch(sourceSignal, q.onAbort);
      if (s.question !== q) { q.dispose(); return; }
      if (isAborted(sourceSignal)) { q.onAbort(); return; }
      prompt(rl);
    } catch (e) { if (s.question === q) clearQuestion(s); throw e; }
  }
  property(Interface.prototype, 'question', function (query, opts, callback) {
    if (typeof opts === 'function') { callback = opts; opts = undefined; }
    if (typeof callback !== 'function') return;
    ask(this, query, opts, callback, undefined);
  });
  // A readline callback has ONE answer argument, not an error-first pair.
  // The canonical util.promisify hook must not reject with a successful
  // answer or strand a cancelled question. Dispatch through the public
  // method so existing subclasses and wrappers retain their behavior.
  property(Interface.prototype.question, Symbol.for('nodejs.util.promisify.custom'),
    function question(query, opts) {
      const rl = this;
      return new P(function (resolveAnswer, rejectAnswer) {
        if (opts === null || typeof opts !== 'object') opts = create(null);
        const requestedSignal = opts.signal;
        const sourceSignal = requestedSignal ? signal(requestedSignal) : undefined;
        let completed = false, dispose = function () {};
        function finish(value, failed) {
          if (completed) return;
          completed = true;
          if (!failed && isAborted(sourceSignal)) { value = abortError(sourceSignal); failed = true; }
          try { dispose(); } catch (e) { value = e; failed = true; }
          if (failed) rejectAnswer(value); else resolveAnswer(value);
        }
        if (isAborted(sourceSignal)) { finish(abortError(sourceSignal), true); return; }
        try {
          dispose = watch(sourceSignal, function () { finish(abortError(sourceSignal), true); });
          if (completed) { dispose(); return; }
          if (isAborted(sourceSignal)) { finish(abortError(sourceSignal), true); return; }
          rl.question(query, opts, function (answer) { finish(answer, false); });
        } catch (e) { finish(e, true); }
      });
    });
  property(Interface.prototype, asyncKey, function () {
    const rl = this, s = state(rl);
    if (s.iterator !== undefined) return s.iterator;
    const opts = create(null);
    opts.close = ['close']; opts.highWaterMark = 1024; opts.lowWaterMark = 1;
    let events = s.closed ? undefined : eventsOn(rl, 'line', opts);
    let next = events === undefined ? undefined : events.next;
    let finish = events === undefined ? undefined : events.return;
    let throwInto = events === undefined ? undefined : events.throw;
    function release() { events = undefined; next = undefined; finish = undefined; throwInto = undefined; }
    const iterator = {
      next: function () {
        if (events === undefined) return iteratorDone();
        return then(apply(next, events, []), function (item) {
          if (item.done) release();
          return item.done ? item : { value: item.value[0], done: false };
        });
      },
      return: function () {
        if (events === undefined) return iteratorDone();
        try { return apply(finish, events, []); }
        finally { release(); closeInterface(rl); }
      },
      throw: function (reason) {
        if (events === undefined) return iteratorDone();
        try { return apply(throwInto, events, [reason]); }
        finally { release(); closeInterface(rl); }
      }
    };
    property(iterator, asyncKey, function () { return this; });
    s.iterator = iterator;
    return iterator;
  });
  function PromiseInterface(input, output, completer, terminal) {
    if (!(this instanceof PromiseInterface)) return new PromiseInterface(input, output, completer, terminal);
    apply(Interface, this, [input, output, completer, terminal]);
  }
  setPrototype(PromiseInterface.prototype, Interface.prototype);
  setPrototype(PromiseInterface, Interface);
  property(PromiseInterface.prototype, 'question', function (query, opts) {
    const rl = this;
    return new P(function (resolveAnswer, rejectAnswer) {
      ask(rl, query, opts, resolveAnswer, rejectAnswer);
    });
  });
  function createInterface(input, output, completer, terminal) { return new Interface(input, output, completer, terminal); }
  function createPromiseInterface(input, output, completer, terminal) { return new PromiseInterface(input, output, completer, terminal); }
  const promises = { Interface: PromiseInterface, createInterface: createPromiseInterface };
  return { Interface: Interface, createInterface: createInterface, promises: promises };
})()
