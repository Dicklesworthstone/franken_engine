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

  // Node's util.inspect.colors (bd-9vouw.440): the enumerable SGR code pairs
  // in Node v22's order on a null-prototype object, and its non-enumerable
  // aliases as accessors onto them.
  inspect.colors = Object.assign(Object.create(null), {
    reset: [0, 0],
    bold: [1, 22],
    dim: [2, 22],
    italic: [3, 23],
    underline: [4, 24],
    blink: [5, 25],
    inverse: [7, 27],
    hidden: [8, 28],
    strikethrough: [9, 29],
    doubleunderline: [21, 24],
    black: [30, 39],
    red: [31, 39],
    green: [32, 39],
    yellow: [33, 39],
    blue: [34, 39],
    magenta: [35, 39],
    cyan: [36, 39],
    white: [37, 39],
    bgBlack: [40, 49],
    bgRed: [41, 49],
    bgGreen: [42, 49],
    bgYellow: [43, 49],
    bgBlue: [44, 49],
    bgMagenta: [45, 49],
    bgCyan: [46, 49],
    bgWhite: [47, 49],
    framed: [51, 54],
    overlined: [53, 55],
    gray: [90, 39],
    redBright: [91, 39],
    greenBright: [92, 39],
    yellowBright: [93, 39],
    blueBright: [94, 39],
    magentaBright: [95, 39],
    cyanBright: [96, 39],
    whiteBright: [97, 39],
    bgGray: [100, 49],
    bgRedBright: [101, 49],
    bgGreenBright: [102, 49],
    bgYellowBright: [103, 49],
    bgBlueBright: [104, 49],
    bgMagentaBright: [105, 49],
    bgCyanBright: [106, 49],
    bgWhiteBright: [107, 49]
  });
  [
    ['grey', 'gray'],
    ['blackBright', 'gray'],
    ['bgGrey', 'bgGray'],
    ['bgBlackBright', 'bgGray'],
    ['faint', 'dim'],
    ['crossedout', 'strikethrough'],
    ['strikeThrough', 'strikethrough'],
    ['crossedOut', 'strikethrough'],
    ['conceal', 'hidden'],
    ['swapColors', 'inverse'],
    ['swapcolors', 'inverse'],
    ['doubleUnderline', 'doubleunderline']
  ].forEach(function (pair) {
    Object.defineProperty(inspect.colors, pair[0], {
      get: function () { return this[pair[1]]; },
      set: function (value) { this[pair[1]] = value; },
      configurable: true,
      enumerable: false
    });
  });
  function escapeStyleCode(code) {
    return '\u001b[' + code + 'm';
  }
  // ERR_INVALID_ARG_VALUE as validateOneOf throws it.
  function invalidOneOf(name, value, allowed) {
    var error = new TypeError('The argument \'' + name + '\' must be one of: ' +
      allowed.map(function (key) { return '\'' + key + '\''; }).join(', ') +
      '. Received ' + inspect(value));
    error.code = 'ERR_INVALID_ARG_VALUE';
    return error;
  }
  function styleText(format, text) {
    if (typeof text !== 'string') {
      throw invalidArgType('text', 'string', text);
    }
    var formats = Array.isArray(format) ? format : [format];
    var left = '';
    var right = '';
    for (var i = 0; i < formats.length; i++) {
      var codes = inspect.colors[formats[i]];
      if (codes === undefined || codes === null) {
        throw invalidOneOf('format', formats[i], Object.keys(inspect.colors));
      }
      left += escapeStyleCode(codes[0]);
      right = escapeStyleCode(codes[1]) + right;
    }
    return left + text + right;
  }
  // Node's ANSI escape pattern (internal/util/inspect.js).
  var ansi = new RegExp('[\\u001B\\u009B][[\\]()#;?]*' +
    '(?:(?:(?:(?:;[-a-zA-Z\\d\\/\\#&.:=?%@~_]+)*' +
    '|[a-zA-Z\\d]+(?:;[-a-zA-Z\\d\\/\\#&.:=?%@~_]*)*)?' +
    '(?:\\u0007|\\u001B\\u005C|\\u009C))' +
    '|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))', 'g');
  function stripVTControlCharacters(str) {
    if (typeof str !== 'string') {
      throw invalidArgType('str', 'string', str);
    }
    return str.replace(ansi, '');
  }
  function toUSVString(input) {
    return String(input).toWellFormed();
  }
  // util.parseArgs (bd-9vouw.441): Node v22's lib/internal/util/parse_args
  // algorithm. Without `args` it parses no arguments: frankenctl passes the
  // program none (Node would read process.argv).
  function parseArgsError(code, message) {
    var error = new TypeError(message);
    error.code = code;
    return error;
  }
  function ownValue(object, key) {
    return object !== null && object !== undefined &&
      Object.prototype.hasOwnProperty.call(object, key) ? object[key] : undefined;
  }
  function optionSetting(options, longOption, key) {
    return Object.prototype.hasOwnProperty.call(options, longOption)
      ? ownValue(options[longOption], key) : undefined;
  }
  function validateParseArgsObject(value, name) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      throw invalidArgType(name, 'object', value);
    }
  }
  function validateParseArgsBoolean(value, name) {
    if (typeof value !== 'boolean') { throw invalidArgType(name, 'boolean', value); }
  }
  function validateParseArgsString(value, name) {
    if (typeof value !== 'string') { throw invalidArgType(name, 'string', value); }
  }
  function validateParseArgsArrayOf(value, name, type) {
    if (!Array.isArray(value)) { throw invalidArgType(name, 'Array', value); }
    for (var i = 0; i < value.length; i++) {
      if (typeof value[i] !== type) {
        throw invalidArgType(name + '[' + i + ']', type, value[i]);
      }
    }
  }
  function findLongOptionForShort(shortOption, options) {
    var keys = Object.keys(options);
    for (var i = 0; i < keys.length; i++) {
      if (ownValue(options[keys[i]], 'short') === shortOption) { return keys[i]; }
    }
    return shortOption;
  }
  function isLoneShortOption(arg) {
    return arg.length === 2 && arg.charAt(0) === '-' && arg.charAt(1) !== '-';
  }
  function isLoneLongOption(arg) {
    return arg.length > 2 && arg.slice(0, 2) === '--' && arg.indexOf('=', 3) === -1;
  }
  function isLongOptionAndValue(arg) {
    return arg.length > 2 && arg.slice(0, 2) === '--' && arg.indexOf('=', 3) !== -1;
  }
  function isShortOptionGroup(arg, options) {
    if (arg.length <= 2 || arg.charAt(0) !== '-' || arg.charAt(1) === '-') { return false; }
    return optionSetting(options, findLongOptionForShort(arg.charAt(1), options), 'type') !== 'string';
  }
  function isShortOptionAndValue(arg, options) {
    if (arg.length <= 2 || arg.charAt(0) !== '-' || arg.charAt(1) === '-') { return false; }
    return optionSetting(options, findLongOptionForShort(arg.charAt(1), options), 'type') === 'string';
  }
  function isOptionLikeValue(value) {
    return value !== null && value !== undefined && value.length > 1 && value.charAt(0) === '-';
  }
  function argsToTokens(args, options) {
    var tokens = [];
    var index = -1;
    var groupCount = 0;
    var remaining = args.slice();
    while (remaining.length > 0) {
      var arg = remaining.shift();
      var nextArg = remaining[0];
      if (groupCount > 0) { groupCount--; } else { index++; }
      if (arg === '--') {
        tokens.push({ kind: 'option-terminator', index: index });
        for (var r = 0; r < remaining.length; r++) {
          tokens.push({ kind: 'positional', index: ++index, value: remaining[r] });
        }
        break;
      }
      var value;
      var inlineValue;
      var longOption;
      if (isLoneShortOption(arg)) {
        longOption = findLongOptionForShort(arg.charAt(1), options);
        value = undefined;
        inlineValue = undefined;
        if (optionSetting(options, longOption, 'type') === 'string' && nextArg !== undefined && nextArg !== null) {
          value = remaining.shift();
          inlineValue = false;
        }
        tokens.push({ kind: 'option', name: longOption, rawName: arg, index: index, value: value, inlineValue: inlineValue });
        if (value !== undefined && value !== null) { ++index; }
        continue;
      }
      if (isShortOptionGroup(arg, options)) {
        var expanded = [];
        for (var c = 1; c < arg.length; c++) {
          var shortOption = arg.charAt(c);
          longOption = findLongOptionForShort(shortOption, options);
          if (optionSetting(options, longOption, 'type') !== 'string' || c === arg.length - 1) {
            expanded.push('-' + shortOption);
          } else {
            expanded.push('-' + shortOption + arg.slice(c + 1));
            break;
          }
        }
        remaining.unshift.apply(remaining, expanded);
        groupCount = expanded.length;
        continue;
      }
      if (isShortOptionAndValue(arg, options)) {
        longOption = findLongOptionForShort(arg.charAt(1), options);
        tokens.push({ kind: 'option', name: longOption, rawName: '-' + arg.charAt(1), index: index,
          value: arg.slice(2), inlineValue: true });
        continue;
      }
      if (isLoneLongOption(arg)) {
        longOption = arg.slice(2);
        value = undefined;
        inlineValue = undefined;
        if (optionSetting(options, longOption, 'type') === 'string' && nextArg !== undefined && nextArg !== null) {
          value = remaining.shift();
          inlineValue = false;
        }
        tokens.push({ kind: 'option', name: longOption, rawName: arg, index: index, value: value, inlineValue: inlineValue });
        if (value !== undefined && value !== null) { ++index; }
        continue;
      }
      if (isLongOptionAndValue(arg)) {
        var equals = arg.indexOf('=');
        longOption = arg.slice(2, equals);
        tokens.push({ kind: 'option', name: longOption, rawName: '--' + longOption, index: index,
          value: arg.slice(equals + 1), inlineValue: true });
        continue;
      }
      tokens.push({ kind: 'positional', index: index, value: arg });
    }
    return tokens;
  }
  function checkOptionUsage(options, allowPositionals, token) {
    if (!Object.prototype.hasOwnProperty.call(options, token.name)) {
      var suggest = allowPositionals
        ? ". To specify a positional argument starting with a '-', place it at the end of the command after '--', as in '-- " +
          JSON.stringify(token.rawName)
        : '';
      throw parseArgsError('ERR_PARSE_ARGS_UNKNOWN_OPTION', "Unknown option '" + token.rawName + "'" + suggest);
    }
    var short = optionSetting(options, token.name, 'short');
    var shortAndLong = (short ? '-' + short + ', ' : '') + '--' + token.name;
    var type = optionSetting(options, token.name, 'type');
    if (type === 'string' && typeof token.value !== 'string') {
      throw parseArgsError('ERR_PARSE_ARGS_INVALID_OPTION_VALUE', "Option '" + shortAndLong + " <value>' argument missing");
    }
    if (type === 'boolean' && token.value !== undefined && token.value !== null) {
      throw parseArgsError('ERR_PARSE_ARGS_INVALID_OPTION_VALUE', "Option '" + shortAndLong + "' does not take an argument");
    }
  }
  function checkOptionLikeValue(token) {
    if (!token.inlineValue && isOptionLikeValue(token.value)) {
      var example = token.rawName.slice(0, 2) === '--'
        ? "'" + token.rawName + "=-XYZ'"
        : "'--" + token.name + "=-XYZ' or '" + token.rawName + "-XYZ'";
      throw parseArgsError('ERR_PARSE_ARGS_INVALID_OPTION_VALUE',
        "Option '" + token.rawName + "' argument is ambiguous.\nDid you forget to specify the option argument for '" +
        token.rawName + "'?\nTo specify an option argument starting with a dash use " + example + '.');
    }
  }
  function storeOption(longOption, optionValue, options, values) {
    if (longOption === '__proto__') { return; }
    var newValue = optionValue === undefined || optionValue === null ? true : optionValue;
    if (optionSetting(options, longOption, 'multiple')) {
      if (values[longOption]) { values[longOption].push(newValue); } else { values[longOption] = [newValue]; }
    } else {
      values[longOption] = newValue;
    }
  }
  function parseArgs(config) {
    if (config === undefined) { config = {}; }
    var args = ownValue(config, 'args');
    if (args === undefined || args === null) { args = []; }
    var strict = ownValue(config, 'strict');
    if (strict === undefined || strict === null) { strict = true; }
    var allowPositionals = ownValue(config, 'allowPositionals');
    if (allowPositionals === undefined || allowPositionals === null) { allowPositionals = !strict; }
    var returnTokens = ownValue(config, 'tokens');
    if (returnTokens === undefined || returnTokens === null) { returnTokens = false; }
    var options = ownValue(config, 'options');
    if (options === undefined || options === null) { options = Object.create(null); }
    if (!Array.isArray(args)) {
      var argsError = new TypeError('The "args" argument must be an instance of Array. Received ' + specificType(args));
      argsError.code = 'ERR_INVALID_ARG_TYPE';
      throw argsError;
    }
    validateParseArgsBoolean(strict, 'strict');
    validateParseArgsBoolean(allowPositionals, 'allowPositionals');
    validateParseArgsBoolean(returnTokens, 'tokens');
    validateParseArgsObject(options, 'options');
    Object.keys(options).forEach(function (longOption) {
      var optionConfig = options[longOption];
      validateParseArgsObject(optionConfig, 'options.' + longOption);
      var optionType = ownValue(optionConfig, 'type');
      if (optionType !== 'string' && optionType !== 'boolean') {
        var error = new TypeError('The "options.' + longOption + '.type" property must be (\'string|boolean\'). Received ' +
          specificType(optionType));
        error.code = 'ERR_INVALID_ARG_TYPE';
        throw error;
      }
      if (Object.prototype.hasOwnProperty.call(optionConfig, 'short')) {
        var shortOption = optionConfig.short;
        validateParseArgsString(shortOption, 'options.' + longOption + '.short');
        if (shortOption.length !== 1) {
          var shortError = new TypeError("The property 'options." + longOption + ".short' must be a single character. Received " +
            inspect(shortOption));
          shortError.code = 'ERR_INVALID_ARG_VALUE';
          throw shortError;
        }
      }
      var multipleOption = ownValue(optionConfig, 'multiple');
      if (Object.prototype.hasOwnProperty.call(optionConfig, 'multiple')) {
        validateParseArgsBoolean(multipleOption, 'options.' + longOption + '.multiple');
      }
      var defaultValue = ownValue(optionConfig, 'default');
      if (defaultValue !== undefined) {
        var defaultName = 'options.' + longOption + '.default';
        if (optionType === 'string') {
          if (multipleOption) { validateParseArgsArrayOf(defaultValue, defaultName, 'string'); }
          else { validateParseArgsString(defaultValue, defaultName); }
        } else if (multipleOption) {
          validateParseArgsArrayOf(defaultValue, defaultName, 'boolean');
        } else {
          validateParseArgsBoolean(defaultValue, defaultName);
        }
      }
    });
    var tokens = argsToTokens(args, options);
    var result = { values: Object.create(null), positionals: [] };
    if (returnTokens) { result.tokens = tokens; }
    tokens.forEach(function (token) {
      if (token.kind === 'option') {
        if (strict) {
          checkOptionUsage(options, allowPositionals, token);
          checkOptionLikeValue(token);
        }
        storeOption(token.name, token.value, options, result.values);
      } else if (token.kind === 'positional') {
        if (!allowPositionals) {
          throw parseArgsError('ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL',
            "Unexpected argument '" + token.value + "'. This command does not take positional arguments");
        }
        result.positionals.push(token.value);
      }
    });
    Object.keys(options).forEach(function (longOption) {
      var defaultValue = ownValue(options[longOption], 'default');
      if (defaultValue !== undefined && result.values[longOption] === undefined && longOption !== '__proto__') {
        result.values[longOption] = defaultValue;
      }
    });
    return result;
  }
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
    parseArgs: parseArgs,
    styleText: styleText,
    stripVTControlCharacters: stripVTControlCharacters,
    toUSVString: toUSVString,
    types: types,
    isArray: Array.isArray,
    TextEncoder: TextEncoder,
    TextDecoder: TextDecoder
  };
})()
