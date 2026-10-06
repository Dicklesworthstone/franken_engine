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
  Object.defineProperty(timers, 'promises', {
    enumerable: true,
    configurable: true,
    get: function () { return promises; }
  });
  return timers;
})()
