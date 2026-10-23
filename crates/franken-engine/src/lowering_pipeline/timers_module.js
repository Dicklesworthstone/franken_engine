(function () {
  'use strict';
  // Callback exports are the realm's native functions, not forwarding wrappers:
  // identity, timer handles, ref/unref, cancellation and capability checks stay
  // in the existing interpreter. Merely constructing this module schedules nothing.
  var timers = {
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    setImmediate: setImmediate,
    clearImmediate: clearImmediate,
    setInterval: setInterval,
    clearInterval: clearInterval
  };
  // Keep the native Promise/async-iterator implementations. In particular, do
  // not add a second Promise reaction or a JavaScript interval queue here.
  var promises = {
    setTimeout: function (delay, value) {
      return __franken_timers_timeout(delay, value, arguments[2]);
    },
    setImmediate: function (value) {
      return __franken_timers_immediate(value, arguments[1]);
    },
    setInterval: function (delay, value) {
      return __franken_timers_interval(delay, value, arguments[2]);
    }
  };
  // Scheduler methods enter the same native Promise timer operations. Return
  // their original Promise directly: no extra reaction, callback queue, or
  // timer authority is created by the module facade.
  var NativeTypeError = TypeError;
  var schedulerBrand = Symbol('kScheduler');
  var schedulerToken = {};
  function schedulerError(code, message) {
    var error = new NativeTypeError(message);
    error.code = code;
    return error;
  }
  class Scheduler {
    constructor() {
      if (arguments[0] !== schedulerToken) {
        throw schedulerError('ERR_ILLEGAL_CONSTRUCTOR', 'Illegal constructor');
      }
      this[schedulerBrand] = true;
    }
    yield() {
      if (!this[schedulerBrand]) {
        throw schedulerError('ERR_INVALID_THIS', 'Value of "this" must be of type Scheduler');
      }
      return __franken_timers_immediate(undefined, undefined);
    }
    wait(delay, options) {
      if (!this[schedulerBrand]) {
        throw schedulerError('ERR_INVALID_THIS', 'Value of "this" must be of type Scheduler');
      }
      return __franken_timers_timeout(delay, undefined, options);
    }
  }
  var schedulerDescriptor = Object.create(null);
  schedulerDescriptor.value = new Scheduler(schedulerToken);
  schedulerDescriptor.writable = true;
  schedulerDescriptor.enumerable = true;
  schedulerDescriptor.configurable = true;
  Object.defineProperty(promises, 'scheduler', schedulerDescriptor);

  // Callback timer functions are not error-first callbacks. Ordinary
  // promisification would put its callback in the delay/value position.
  var custom = Symbol.for('nodejs.util.promisify.custom');
  function promisifyTimer(name) {
    var timer = timers[name];
    if (Object.getOwnPropertyDescriptor(timer, custom) !== undefined) return;
    var descriptor = Object.create(null);
    // Property assignment does not infer a name. Keep Node's observable name
    // and the immutable factory's audited accessor identity.
    descriptor.get = function get() { return promises[name]; };
    descriptor.enumerable = true;
    descriptor.configurable = false;
    Object.defineProperty(timer, custom, descriptor);
  }
  promisifyTimer('setTimeout');
  promisifyTimer('setImmediate');
  Object.defineProperty(timers, 'promises', {
    enumerable: true,
    configurable: true,
    get: function () { return promises; }
  });
  return timers;
})()
