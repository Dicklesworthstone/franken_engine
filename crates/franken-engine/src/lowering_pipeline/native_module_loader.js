// Engine-owned synchronous module initialization. The Rust lowerer replaces
// the initializer placeholder with an AST expression, not generated guest text.
// The initializer thunk is an argument, outside the cache's lexical scope.
(function (initialize) {
  'use strict';
  let state = 0;
  let value;
  return function () {
    if (state === 2) return value;
    if (state === 1) {
      const error = new globalThis.TypeError('reentrant native module initialization');
      error.code = 'ERR_NATIVE_MODULE_REENTRANT';
      throw error;
    }
    state = 1;
    try {
      const initialized = initialize();
      value = initialized;
      state = 2;
      return initialized;
    } finally {
      // A throwing initializer must not publish partial exports or poison
      // the next require. Successfully initialized dependencies stay cached.
      if (state !== 2) {
        value = void 0;
        state = 0;
      }
    }
  };
})(function () {
  return __franken_native_module_initializer;
})
