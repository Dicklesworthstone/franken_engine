(function () {
  'use strict';
  // Capture the engine's private dependency before guest code can replace
  // public util exports. No filesystem or module-loader authority is used.
  var util = __franken_assert_util;
  var strictDeep = util.isDeepStrictEqual;
  var inspect = util.inspect;
  var isRegExp = util.types.isRegExp;
  var isNativeError = util.types.isNativeError;
  var apply = Reflect.apply;
  var regexpExec = RegExp.prototype.exec;
  var mapEntries = Map.prototype.entries;
  var setValues = Set.prototype.values;

  function invalidType(name) {
    var error = new TypeError('Invalid ' + name);
    error.code = 'ERR_INVALID_ARG_TYPE';
    return error;
  }
  function requiredPair(count) {
    if (count < 2) {
      var error = new TypeError('The "actual" and "expected" arguments must be specified');
      error.code = 'ERR_MISSING_ARGS';
      throw error;
    }
  }
  function defaultMessage(actual, expected, operator) {
    return inspect(actual) + ' ' + operator + ' ' + inspect(expected);
  }
  function errorSnapshot(error) {
    var copy = Object.assign(Object.create(Object.getPrototypeOf(error)), error);
    Object.defineProperty(copy, 'message', { value: error.message });
    for (var key of ['cause', 'errors']) {
      if (key in error) { Object.defineProperty(copy, key, { value: error[key] }); }
    }
    return copy;
  }
  class AssertionError extends Error {
    constructor(options) {
      if (options === null || typeof options !== 'object') {
        throw invalidType('options');
      }
      var generated = options.message === undefined || options.message === null;
      super(generated
        ? defaultMessage(options.actual, options.expected, options.operator)
        : String(options.message));
      Object.defineProperty(this, 'name', {
        value: 'AssertionError', writable: true, configurable: true
      });
      this.generatedMessage = generated;
      this.code = 'ERR_ASSERTION';
      var copyErrors = generated && isNativeError(options.actual) && isNativeError(options.expected);
      this.actual = copyErrors ? errorSnapshot(options.actual) : options.actual;
      this.expected = copyErrors ? errorSnapshot(options.expected) : options.expected;
      this.operator = options.operator;
    }
    toString() {
      return this.name + ' [' + this.code + ']: ' + this.message;
    }
  }
  function failure(actual, expected, message, operator) {
    if (isNativeError(message)) { throw message; }
    throw new AssertionError({
      actual: actual, expected: expected, message: message, operator: operator
    });
  }
  function fail(message) {
    // Preserve the legacy overload without pretending to emit Node warnings.
    if (arguments.length > 1) {
      return failure(arguments[0], arguments[1], arguments[2], arguments[3] ||
        (arguments.length === 2 ? '!=' : 'fail'));
    }
    if (isNativeError(message)) { throw message; }
    var error = new AssertionError({
      actual: message, expected: undefined,
      message: message === undefined || message === null ? 'Failed' : message,
      operator: 'fail'
    });
    if (message === undefined || message === null) { error.generatedMessage = true; }
    // In the one-message form actual is not the message being asserted.
    if (message !== null) { error.actual = undefined; }
    throw error;
  }
  function ok(value, message) {
    if (value) { return; }
    if (arguments.length === 0) {
      var error = new AssertionError({
        actual: undefined, expected: true,
        message: 'No value argument passed to `assert.ok()`', operator: '=='
      });
      error.generatedMessage = true;
      throw error;
    }
    failure(value, true, message, '==');
  }
  function coercivelyEqual(a, b) {
    return a == b || (a !== a && b !== b);
  }
  function equal(actual, expected, message) {
    requiredPair(arguments.length);
    if (!coercivelyEqual(actual, expected)) { failure(actual, expected, message, '=='); }
  }
  function notEqual(actual, expected, message) {
    requiredPair(arguments.length);
    if (coercivelyEqual(actual, expected)) { failure(actual, expected, message, '!='); }
  }
  function strictEqual(actual, expected, message) {
    requiredPair(arguments.length);
    if (!Object.is(actual, expected)) { failure(actual, expected, message, 'strictEqual'); }
  }
  function notStrictEqual(actual, expected, message) {
    requiredPair(arguments.length);
    if (Object.is(actual, expected)) { failure(actual, expected, message, 'notStrictEqual'); }
  }

  // Legacy deep equality deliberately differs from util's strict comparator:
  // prototypes and symbol keys are ignored and primitive leaves are coercive.
  // Active pairs break cycles, but are removed on every return/exception so a
  // failed unordered candidate cannot poison later candidate comparisons.
  function looseDeep(a, b, seen) {
    if (a === b) { return true; }
    if (a === null || typeof a !== 'object') {
      return (b === null || typeof b !== 'object') && coercivelyEqual(a, b);
    }
    if (b === null || typeof b !== 'object') { return false; }
    var tag = __franken_util_type_tag(a);
    if (tag !== __franken_util_type_tag(b)) { return false; }
    if (tag === 'WeakMap' || tag === 'WeakSet') { return false; }
    for (var i = 0; i < seen.length; i++) {
      if (seen[i][0] === a && seen[i][1] === b) { return true; }
    }
    seen.push([a, b]);
    try { return looseObject(a, b, tag, seen); }
    finally { seen.pop(); }
  }
  function looseBytes(a, b, view) {
    if (a.byteLength !== b.byteLength) { return false; }
    var left = view ? new Uint8Array(a.buffer, a.byteOffset, a.byteLength) : new Uint8Array(a);
    var right = view ? new Uint8Array(b.buffer, b.byteOffset, b.byteLength) : new Uint8Array(b);
    for (var i = 0; i < left.length; i++) {
      if (left[i] !== right[i]) { return false; }
    }
    return true;
  }
  function looseCollection(a, b, seen, isMap) {
    if (a.size !== b.size) { return false; }
    var iterate = isMap ? mapEntries : setValues;
    var has = isMap ? Map.prototype.has : Set.prototype.has;
    var pending = [];
    // Exact primitive keys need no search. Object keys must still compare
    // structurally, even when the same object occurs in both collections.
    for (var entry of apply(iterate, a, [])) {
      var key = isMap ? entry[0] : entry;
      if (key !== null && typeof key === 'object' ||
          !apply(has, b, [key]) ||
          isMap && !looseDeep(entry[1], apply(Map.prototype.get, b, [key]), seen)) {
        pending.push(entry);
      }
    }
    var matched = [];
    var remaining = pending.length;
    for (var other of apply(iterate, b, [])) {
      var found = false;
      for (var i = 0; i < pending.length; i++) {
        if (matched[i]) { continue; }
        var candidate = pending[i];
        if (isMap
          ? looseDeep(candidate[0], other[0], seen) && looseDeep(candidate[1], other[1], seen)
          : looseDeep(candidate, other, seen)) {
          matched[i] = true;
          remaining--;
          found = true;
          break;
        }
      }
      if (found) { continue; }
      var otherKey = isMap ? other[0] : other;
      if (otherKey !== null && typeof otherKey === 'object' ||
          !apply(has, a, [otherKey]) ||
          isMap && !looseDeep(apply(Map.prototype.get, a, [otherKey]), other[1], seen)) {
        return false;
      }
    }
    return remaining === 0;
  }
  function looseObject(a, b, tag, seen) {
    if (tag === 'Date' && a.getTime() !== b.getTime()) { return false; }
    if (tag === 'RegExp' &&
        (a.source !== b.source || a.flags !== b.flags || a.lastIndex !== b.lastIndex)) {
      return false;
    }
    if (tag.indexOf('Boxed') === 0 && !Object.is(a.valueOf(), b.valueOf())) { return false; }
    if (tag === 'Error' && (a.name !== b.name || a.message !== b.message ||
        !looseDeep(a.cause, b.cause, seen) || !looseDeep(a.errors, b.errors, seen))) {
      return false;
    }
    if ((tag === 'ArrayBuffer' || tag === 'DataView') && !looseBytes(a, b, tag === 'DataView')) {
      return false;
    }
    if (tag === 'Float32Array' || tag === 'Float64Array') {
      if (a.length !== b.length) { return false; }
      for (var index = 0; index < a.length; index++) {
        if (a[index] !== b[index]) { return false; }
      }
    }
    if (Array.isArray(a) && a.length !== b.length) { return false; }
    if ((tag === 'Map' || tag === 'Set') && !looseCollection(a, b, seen, tag === 'Map')) {
      return false;
    }
    var keysA = Object.keys(a);
    var keysB = Object.keys(b);
    if (keysA.length !== keysB.length) { return false; }
    for (var i = 0; i < keysA.length; i++) {
      var key = keysA[i];
      if (!Object.prototype.propertyIsEnumerable.call(b, key) || !looseDeep(a[key], b[key], seen)) {
        return false;
      }
    }
    return true;
  }
  function deepEqual(actual, expected, message) {
    requiredPair(arguments.length);
    if (!looseDeep(actual, expected, [])) { failure(actual, expected, message, 'deepEqual'); }
  }
  function notDeepEqual(actual, expected, message) {
    requiredPair(arguments.length);
    if (looseDeep(actual, expected, [])) { failure(actual, expected, message, 'notDeepEqual'); }
  }
  function deepStrictEqual(actual, expected, message) {
    requiredPair(arguments.length);
    if (!strictDeep(actual, expected)) { failure(actual, expected, message, 'deepStrictEqual'); }
  }
  function notDeepStrictEqual(actual, expected, message) {
    requiredPair(arguments.length);
    if (strictDeep(actual, expected)) { failure(actual, expected, message, 'notDeepStrictEqual'); }
  }
  function regexMatches(regexp, value) {
    return apply(regexpExec, regexp, [value]) !== null;
  }
  function match(string, regexp, message) {
    if (!isRegExp(regexp)) { throw invalidType('regexp'); }
    if (typeof string !== 'string' || !regexMatches(regexp, string)) {
      failure(string, regexp, message, 'match');
    }
  }
  function doesNotMatch(string, regexp, message) {
    if (!isRegExp(regexp)) { throw invalidType('regexp'); }
    if (typeof string !== 'string' || regexMatches(regexp, string)) {
      failure(string, regexp, message, 'doesNotMatch');
    }
  }
  function ifError(value) {
    if (value === undefined || value === null) { return; }
    failure(value, null, 'ifError got unwanted exception: ' +
      (isNativeError(value) ? (value.message || value.name) : inspect(value)), 'ifError');
  }
  function strict() { return apply(ok, undefined, arguments); }

  ok.AssertionError = AssertionError;
  ok.fail = fail;
  ok.ok = ok;
  ok.equal = equal;
  ok.notEqual = notEqual;
  ok.deepEqual = deepEqual;
  ok.notDeepEqual = notDeepEqual;
  ok.strictEqual = strictEqual;
  ok.notStrictEqual = notStrictEqual;
  ok.deepStrictEqual = deepStrictEqual;
  ok.notDeepStrictEqual = notDeepStrictEqual;
  ok.match = match;
  ok.doesNotMatch = doesNotMatch;
  ok.ifError = ifError;
  Object.assign(strict, ok);
  strict.equal = strictEqual;
  strict.notEqual = notStrictEqual;
  strict.deepEqual = deepStrictEqual;
  strict.notDeepEqual = notDeepStrictEqual;
  strict.strict = strict;
  ok.strict = strict;
  return ok;
})()
