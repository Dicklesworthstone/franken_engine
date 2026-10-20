(function installReadlineCursor(readline) {
  'use strict';
  // Output-only cursor control. The supplied Writable owns I/O, pressure and
  // errors; this module never opens a terminal or switches an input to raw mode.
  const apply = Reflect.apply;
  const define = Object.defineProperty;
  const create = Object.create;
  const join = Array.prototype.join;
  const push = Array.prototype.push;
  const integer = Number.isInteger;
  const nan = Number.isNaN;
  const P = Promise;
  const Type = TypeError;
  const Range = RangeError;
  const Weak = WeakMap;
  const weakGet = WeakMap.prototype.get;
  const weakSet = WeakMap.prototype.set;
  const transactions = new Weak();
  const CSI = '\x1b[';

  function failure(Base, code, message) {
    const e = new Base(message);
    e.code = code;
    return e;
  }
  function invalid(name) {
    return failure(Type, 'ERR_INVALID_ARG_TYPE', 'Invalid ' + name);
  }
  function callbackArgument(callback) {
    if (callback !== undefined && typeof callback !== 'function') throw invalid('callback');
  }
  function noop(callback) {
    if (typeof callback === 'function') {
      // The existing intrinsic supplies process.nextTick semantics without
      // reading guest process properties or adding module-load authority.
      __franken_readline_cursor_tick(function () { callback(null); });
    }
    return true;
  }
  function position(x, y) {
    return typeof y === 'number' ? CSI + (y + 1) + ';' + (x + 1) + 'H' : CSI + (x + 1) + 'G';
  }
  function movement(dx, dy) {
    let text = '';
    if (dx < 0) text += CSI + (-dx) + 'D';
    else if (dx > 0) text += CSI + dx + 'C';
    if (dy < 0) text += CSI + (-dy) + 'A';
    else if (dy > 0) text += CSI + dy + 'B';
    return text;
  }
  function line(dir) { return CSI + (dir < 0 ? '1K' : dir > 0 ? '0K' : '2K'); }
  function cursorTo(stream, x, y, callback) {
    callbackArgument(callback);
    if (typeof y === 'function') { callback = y; y = undefined; }
    if (nan(x)) throw failure(Type, 'ERR_INVALID_ARG_VALUE', 'Invalid x');
    if (nan(y)) throw failure(Type, 'ERR_INVALID_ARG_VALUE', 'Invalid y');
    if (stream == null || (typeof x !== 'number' && typeof y !== 'number')) return noop(callback);
    if (typeof x !== 'number') throw failure(Type, 'ERR_INVALID_CURSOR_POS', 'A row requires a numeric column');
    return stream.write(position(x, y), callback);
  }
  function moveCursor(stream, dx, dy, callback) {
    callbackArgument(callback);
    if (stream == null || !(dx || dy)) return noop(callback);
    return stream.write(movement(dx, dy), callback);
  }
  function clearLine(stream, dir, callback) {
    callbackArgument(callback);
    if (stream == null) return noop(callback);
    return stream.write(line(dir), callback);
  }
  function clearScreenDown(stream, callback) {
    callbackArgument(callback);
    if (stream == null) return noop(callback);
    return stream.write(CSI + '0J', callback);
  }

  function checkInteger(value, name, minimum, maximum) {
    if (typeof value !== 'number') throw invalid(name);
    if (!integer(value) || value < minimum || value > maximum) {
      throw failure(Range, 'ERR_OUT_OF_RANGE', 'Invalid integer ' + name);
    }
  }
  function record(receiver) {
    const s = apply(weakGet, transactions, [receiver]);
    if (s === undefined) throw new Type('Invalid Readline receiver');
    return s;
  }
  function enqueue(receiver, text) {
    const s = record(receiver);
    if (s.autoCommit) {
      // Each automatic action is admitted now and written next tick. rollback
      // owns only the uncommitted batch, not already scheduled output.
      __franken_readline_cursor_tick(function () { s.stream.write(text); });
    } else apply(push, s.pending, [text]);
    return receiver;
  }
  function writable(stream) {
    if (stream == null || stream.writable !== true || stream.destroyed || stream.writableEnded) return false;
    if (typeof stream.write !== 'function' || typeof stream.on !== 'function') return false;
    // Match the Node-style writable boundary, not a Web WritableStream or
    // an arbitrary object carrying only a write function.
    return !stream._readableState || !!(stream._writableState && stream._writableState.writable !== false);
  }
  class Readline {
    constructor(stream, options = undefined) {
      if (!writable(stream)) throw invalid('stream');
      let autoCommit = false;
      if (options != null && options.autoCommit != null) {
        if (typeof options.autoCommit !== 'boolean') throw invalid('options.autoCommit');
        autoCommit = options.autoCommit;
      }
      const s = create(null);
      s.stream = stream; s.autoCommit = autoCommit; s.pending = [];
      apply(weakSet, transactions, [this, s]);
    }
    cursorTo(x, y = undefined) {
      checkInteger(x, 'x', -9007199254740991, 9007199254740991);
      if (y != null) checkInteger(y, 'y', -9007199254740991, 9007199254740991);
      return enqueue(this, position(x, y));
    }
    moveCursor(dx, dy) {
      if (dx || dy) {
        checkInteger(dx, 'dx', -9007199254740991, 9007199254740991);
        checkInteger(dy, 'dy', -9007199254740991, 9007199254740991);
        return enqueue(this, movement(dx, dy));
      }
      // Node's no-movement path neither writes nor accesses private state.
      return this;
    }
    clearLine(dir) {
      checkInteger(dir, 'dir', -1, 1);
      return enqueue(this, line(dir));
    }
    clearScreenDown() { return enqueue(this, CSI + '0J'); }
    commit() {
      const receiver = this;
      return new P(function (resolve, reject) {
        const s = record(receiver);
        // Detach before invoking user output. Reentrant actions or commits
        // must not be discarded, replayed, or acknowledged by this batch.
        const batch = s.pending;
        s.pending = [];
        try { s.stream.write(apply(join, batch, ['']), resolve); }
        catch (error) { reject(error); }
      });
    }
    rollback() { record(this).pending = []; return this; }
  }
  function publish(target, key, value) {
    const d = create(null);
    d.value = value; d.writable = true; d.enumerable = true; d.configurable = true;
    define(target, key, d);
  }
  publish(readline, 'cursorTo', cursorTo);
  publish(readline, 'moveCursor', moveCursor);
  publish(readline, 'clearLine', clearLine);
  publish(readline, 'clearScreenDown', clearScreenDown);
  publish(readline.promises, 'Readline', Readline);
  return readline;
})
