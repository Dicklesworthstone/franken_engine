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
  var scheduler = {
    wait: function (delay, options) {
      return __franken_timers_timeout(delay, undefined, options);
    },
    yield: function () {
      return __franken_timers_immediate(undefined, undefined);
    }
  };
  Object.defineProperty(promises, 'scheduler', {
    value: scheduler,
    enumerable: true,
    configurable: true,
    writable: true
  });
  var custom = Symbol.for('nodejs.util.promisify.custom');
  function installCustom(timer, promise) {
    if (Object.getOwnPropertyDescriptor(timer, custom) !== undefined) return;
    Object.defineProperty(timer, custom, {
      value: promise,
      enumerable: true,
      configurable: false,
      writable: false
    });
  }
  installCustom(timers.setTimeout, promises.setTimeout);
  installCustom(timers.setImmediate, promises.setImmediate);
  Object.defineProperty(timers, 'promises', {
    enumerable: true,
    configurable: true,
    get: function () { return promises; }
  });
  return timers;
})()
