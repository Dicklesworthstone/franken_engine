(function () {
  'use strict';
  var promisifyCustom = Symbol.for('nodejs.util.promisify.custom');
  var typedArrayNames = ['Int8Array', 'Uint8Array', 'Uint8ClampedArray', 'Int16Array',
    'Uint16Array', 'Int32Array', 'Uint32Array', 'Float32Array', 'Float64Array',
    'BigInt64Array', 'BigUint64Array'];
  function typeTag(value) {
    return __franken_util_type_tag(value);
  }
  // Node's determineSpecificType.
  function specificType(value) {
    if (value === null || value === undefined) {
      return String(value);
    }
    switch (typeof value) {
      case 'bigint':
        return 'type bigint (' + value + 'n)';
      case 'number':
        return 'type number (' + (Object.is(value, -0) ? '-0' : String(value)) + ')';
      case 'boolean':
      case 'symbol':
        return 'type ' + typeof value + ' (' + String(value) + ')';
      case 'function':
        return 'function ' + value.name;
      case 'object':
        if (value.constructor && 'name' in value.constructor) {
          return 'an instance of ' + value.constructor.name;
        }
        return inspect(value, { depth: -1 });
      default:
        if (value.length > 28) {
          value = value.slice(0, 25) + '...';
        }
        return 'type string (' + (value.indexOf("'") === -1 ? "'" + value + "'"
          : JSON.stringify(value)) + ')';
    }
  }
  // ERR_INVALID_ARG_TYPE.
  function invalidArgType(name, type, value) {
    var kind = name.indexOf('.') === -1 ? 'argument' : 'property';
    var error = new TypeError('The "' + name + '" ' + kind + ' must be of type ' + type + '. Received ' +
      specificType(value));
    error.code = 'ERR_INVALID_ARG_TYPE';
    return error;
  }
  function validateFunction(value, name) {
    if (typeof value !== 'function') {
      throw invalidArgType(name, 'function', value);
    }
  }
  // Own properties of `source` onto `target`, as Object.defineProperties
  // of Object.getOwnPropertyDescriptors does.
  function copyOwnProperties(target, source, adjust) {
    var keys = Reflect.ownKeys(source);
    for (var i = 0; i < keys.length; i++) {
      var descriptor = Object.getOwnPropertyDescriptor(source, keys[i]);
      if (descriptor === undefined) {
        continue;
      }
      if (adjust) {
        adjust(keys[i], descriptor);
      }
      Object.defineProperty(target, keys[i], descriptor);
    }
    return target;
  }
  function inspect(value, options) {
    var depth = inspect.defaultOptions.depth;
    if (typeof options === 'boolean') {
      if (arguments.length > 2 && arguments[2] !== undefined) {
        depth = arguments[2];
      }
    } else if (options !== null && typeof options === 'object' && options.depth !== undefined) {
      depth = options.depth;
    }
    return __franken_util_inspect(value, depth === null ? Infinity : depth);
  }
  inspect.custom = Symbol.for('nodejs.util.inspect.custom');
  inspect.defaultOptions = { showHidden: false, depth: 2, colors: false, customInspect: true,
    showProxy: false, maxArrayLength: 100, maxStringLength: 10000, breakLength: 128,
    compact: 3, sorted: false, getters: false, numericSeparator: false };
  function format(...args) {
    return __franken_util_format(args);
  }
  function formatWithOptions(inspectOptions, ...args) {
    if (inspectOptions === null || typeof inspectOptions !== 'object') {
      throw invalidArgType('inspectOptions', 'object', inspectOptions);
    }
    return __franken_util_format(args);
  }
  function inherits(ctor, superCtor) {
    if (ctor === undefined || ctor === null) {
      throw invalidArgType('ctor', 'function', ctor);
    }
    if (superCtor === undefined || superCtor === null) {
      throw invalidArgType('superCtor', 'function', superCtor);
    }
    if (superCtor.prototype === undefined) {
      throw invalidArgType('superCtor.prototype', 'object', superCtor.prototype);
    }
    Object.defineProperty(ctor, 'super_', { value: superCtor, writable: true, configurable: true });
    Object.setPrototypeOf(ctor.prototype, superCtor.prototype);
  }
  function promisify(original) {
    validateFunction(original, 'original');
    if (original[promisifyCustom]) {
      var custom = original[promisifyCustom];
      validateFunction(custom, 'util.promisify.custom');
      return Object.defineProperty(custom, promisifyCustom, { value: custom, enumerable: false,
        writable: false, configurable: true });
    }
    function fn(...args) {
      var self = this;
      return new Promise(function (resolve, reject) {
        args.push(function (error, ...values) {
          if (error) {
            return reject(error);
          }
          resolve(values[0]);
        });
        Reflect.apply(original, self, args);
      });
    }
    Object.setPrototypeOf(fn, Object.getPrototypeOf(original));
    Object.defineProperty(fn, promisifyCustom, { value: fn, enumerable: false, writable: false,
      configurable: true });
    return copyOwnProperties(fn, original);
  }
  promisify.custom = promisifyCustom;
  function callbackifyOnRejected(reason, callback) {
    if (!reason) {
      var error = new Error('Promise was rejected with falsy value');
      error.code = 'ERR_FALSY_VALUE_REJECTION';
      error.reason = reason;
      reason = error;
    }
    return callback(reason);
  }
  function callbackify(original) {
    validateFunction(original, 'original');
    function callbackified(...args) {
      var maybeCallback = args.pop();
      validateFunction(maybeCallback, 'last argument');
      var callback = maybeCallback.bind(this);
      Reflect.apply(original, this, args).then(function (value) {
        callback(null, value);
      }, function (reason) {
        callbackifyOnRejected(reason, callback);
      });
    }
    return copyOwnProperties(callbackified, original, function (key, descriptor) {
      if (key === 'length' && typeof descriptor.value === 'number') {
        descriptor.value++;
      }
      if (key === 'name' && typeof descriptor.value === 'string') {
        descriptor.value += 'Callbackified';
      }
    });
  }
  function deprecate(fn) {
    validateFunction(fn, 'fn');
    function deprecated(...args) {
      if (new.target) {
        return Reflect.construct(fn, args, new.target);
      }
      return Reflect.apply(fn, this, args);
    }
    Object.setPrototypeOf(deprecated, fn);
    if (fn.prototype) {
      deprecated.prototype = fn.prototype;
    }
    return deprecated;
  }
  function debuglog() {
    var log = function () {};
    log.enabled = false;
    return log;
  }
  // Capture the native iterators before guest code runs. An own `entries`,
  // `values`, `has`, `get`, or Symbol.iterator must not replace collection
  // contents with a fabricated sequence during a structural comparison.
  var mapEntries = Map.prototype.entries;
  var setValues = Set.prototype.values;
  function enumerableKeys(value) {
    var keys = Reflect.ownKeys(value);
    var result = [];
    for (var i = 0; i < keys.length; i++) {
      if (Object.prototype.propertyIsEnumerable.call(value, keys[i])) {
        result.push(keys[i]);
      }
    }
    return result;
  }
  function unorderedEqual(a, b, seen, isMap) {
    var iterate = isMap ? mapEntries : setValues;
    var candidates = [];
    for (var candidate of Reflect.apply(iterate, b, [])) {
      candidates.push(candidate);
    }
    var matched = [];
    var count = 0;
    for (var entry of Reflect.apply(iterate, a, [])) {
      var found = false;
      for (var i = 0; i < candidates.length; i++) {
        if (matched[i]) {
          continue;
        }
        var other = candidates[i];
        var equal = isMap
          ? deepEqual(entry[0], other[0], seen) && deepEqual(entry[1], other[1], seen)
          : deepEqual(entry, other, seen);
        if (equal) {
          // Distinct object identities can be structurally equal; every
          // right-hand entry may nevertheless satisfy only one left entry.
          matched[i] = true;
          count++;
          found = true;
          break;
        }
      }
      if (!found) {
        return false;
      }
    }
    return count === candidates.length;
  }
  // Compare the visible range, not a view's entire backing store. Construct
  // byte views only after checking lengths; indexed reads stay on the native
  // typed-array path and use ordinary interpreter memory/work accounting.
  function equalByteRanges(bufferA, offsetA, lengthA, bufferB, offsetB, lengthB) {
    if (lengthA !== lengthB) {
      return false;
    }
    var bytesA = new Uint8Array(bufferA, offsetA, lengthA);
    var bytesB = new Uint8Array(bufferB, offsetB, lengthB);
    for (var i = 0; i < lengthA; i++) {
      if (bytesA[i] !== bytesB[i]) {
        return false;
      }
    }
    return true;
  }
  function equalObject(a, b, tag, seen) {
    // Node 22 does not equate distinct invalid dates (NaN time values).
    if (tag === 'Date' && a.getTime() !== b.getTime()) {
      return false;
    }
    if (tag === 'RegExp' &&
        (a.source !== b.source || a.flags !== b.flags || a.lastIndex !== b.lastIndex)) {
      return false;
    }
    if (tag.indexOf('Boxed') === 0 && !Object.is(a.valueOf(), b.valueOf())) {
      return false;
    }
    if (tag === 'Error') {
      if (a.message !== b.message || a.name !== b.name) {
        return false;
      }
      var causeA = Object.prototype.hasOwnProperty.call(a, 'cause');
      var causeB = Object.prototype.hasOwnProperty.call(b, 'cause');
      if (causeA !== causeB || (causeA && !deepEqual(a.cause, b.cause, seen)) ||
          !deepEqual(a.errors, b.errors, seen)) {
        return false;
      }
    }
    if (tag === 'ArrayBuffer' &&
        !equalByteRanges(a, 0, a.byteLength, b, 0, b.byteLength)) {
      return false;
    }
    if (tag === 'DataView' &&
        !equalByteRanges(a.buffer, a.byteOffset, a.byteLength,
          b.buffer, b.byteOffset, b.byteLength)) {
      return false;
    }
    if (Array.isArray(a) && a.length !== b.length) {
      return false;
    }
    if (tag === 'Map' || tag === 'Set') {
      if (a.size !== b.size || !unorderedEqual(a, b, seen, tag === 'Map')) {
        return false;
      }
    }
    var keysA = enumerableKeys(a);
    var keysB = enumerableKeys(b);
    if (keysA.length !== keysB.length) {
      return false;
    }
    for (var j = 0; j < keysA.length; j++) {
      var key = keysA[j];
      if (!Object.prototype.propertyIsEnumerable.call(b, key) || !deepEqual(a[key], b[key], seen)) {
        return false;
      }
    }
    return true;
  }
  function deepEqual(a, b, seen) {
    if (Object.is(a, b)) {
      return true;
    }
    if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) {
      return false;
    }
    if (Object.getPrototypeOf(a) !== Object.getPrototypeOf(b)) {
      return false;
    }
    var tag = typeTag(a);
    if (tag !== typeTag(b)) {
      return false;
    }
    // Weak collections have no structurally observable entry set. Only
    // the identical object, already handled by Object.is, can be equal.
    if (tag === 'WeakMap' || tag === 'WeakSet') {
      return false;
    }
    for (var i = 0; i < seen.length; i++) {
      if (seen[i][0] === a && seen[i][1] === b) {
        return true;
      }
    }
    // Only active ancestors break cycles. A failed unordered candidate must
    // not leave "equal" pairs behind for the next candidate or sibling.
    seen.push([a, b]);
    try {
      return equalObject(a, b, tag, seen);
    } finally {
      seen.pop();
    }
  }
  function isDeepStrictEqual(a, b) {
    return deepEqual(a, b, []);
  }
  function tagIs(name) {
    return function (value) {
      return typeTag(value) === name;
    };
  }
  var types = {
    isDate: tagIs('Date'),
    isRegExp: tagIs('RegExp'),
    isMap: tagIs('Map'),
    isSet: tagIs('Set'),
    isWeakMap: tagIs('WeakMap'),
    isWeakSet: tagIs('WeakSet'),
    isPromise: tagIs('Promise'),
    isArrayBuffer: tagIs('ArrayBuffer'),
    isAnyArrayBuffer: tagIs('ArrayBuffer'),
    isDataView: tagIs('DataView'),
    isNativeError: tagIs('Error'),
    isProxy: tagIs('Proxy'),
    isGeneratorFunction: function (value) {
      var tag = typeTag(value);
      return tag === 'GeneratorFunction' || tag === 'AsyncGeneratorFunction';
    },
    isAsyncFunction: function (value) {
      var tag = typeTag(value);
      return tag === 'AsyncFunction' || tag === 'AsyncGeneratorFunction';
    },
    isGeneratorObject: tagIs('Generator'),
    isNumberObject: tagIs('BoxedNumber'),
    isStringObject: tagIs('BoxedString'),
    isBooleanObject: tagIs('BoxedBoolean'),
    isBigIntObject: tagIs('BoxedBigInt'),
    isSymbolObject: tagIs('BoxedSymbol'),
    isBoxedPrimitive: function (value) {
      return typeTag(value).indexOf('Boxed') === 0;
    },
    isTypedArray: function (value) {
      return typedArrayNames.indexOf(typeTag(value)) !== -1;
    },
    isArrayBufferView: function (value) {
      var tag = typeTag(value);
      return tag === 'DataView' || typedArrayNames.indexOf(tag) !== -1;
    }
  };
  typedArrayNames.forEach(function (name) {
    types['is' + name] = tagIs(name);
  });
  return {
    format: format,
    formatWithOptions: formatWithOptions,
    inspect: inspect,
    inherits: inherits,
    promisify: promisify,
    callbackify: callbackify,
    deprecate: deprecate,
    debuglog: debuglog,
    debug: debuglog,
    isDeepStrictEqual: isDeepStrictEqual,
    types: types,
    isArray: Array.isArray,
    TextEncoder: TextEncoder,
    TextDecoder: TextDecoder
  };
})()
