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
  // util.parseEnv is a content parser, not process.loadEnvFile: it must not
  // read files, mutate process.env, expand variables or execute shell text.
  // The scanner follows Node's .env grammar and the Node 22 compatibility
  // oracle (including permissive keys and recovery from an unclosed quote).
  function envWhitespace(character) {
    return character === ' ' || character === '\t' || character === '\n';
  }
  function envTrim(text) {
    var start = 0;
    var end = text.length;
    while (start < end && envWhitespace(text[start])) { start++; }
    while (end > start && envWhitespace(text[end - 1])) { end--; }
    return text.slice(start, end);
  }
  function envKeyOrder(a, b) {
    // Node returns keys in UTF-8 lexical order, i.e. scalar order for
    // well-formed strings, not UTF-16 order across the BMP boundary.
    var ai = 0;
    var bi = 0;
    while (ai < a.length && bi < b.length) {
      var ac = a.codePointAt(ai);
      var bc = b.codePointAt(bi);
      if (ac !== bc) { return ac < bc ? -1 : 1; }
      ai += ac > 65535 ? 2 : 1;
      bi += bc > 65535 ? 2 : 1;
    }
    return (ai < a.length ? 1 : 0) - (bi < b.length ? 1 : 0);
  }
  function parseEnv(content) {
    if (typeof content !== 'string') {
      throw invalidArgType('content', 'string', content);
    }
    // The reference parses UTF-8 and removes CR bytes, including inside
    // quotes. Repair unpaired surrogates just as that UTF-8 boundary does.
    var text = envTrim(content.toWellFormed().replace(/\r/g, ''));
    var entries = Object.create(null);
    var cursor = 0;
    var lineEnd = -1;
    var untrimmedContinuation = false;
    while (cursor < text.length) {
      var beforeIndent = cursor;
      while (cursor < text.length && envWhitespace(text[cursor])) {
        if (text[cursor] === '\n') { beforeIndent = cursor + 1; }
        cursor++;
      }
      var directComment = beforeIndent === cursor;
      if (cursor === text.length) { break; }
      // Empty-key recovery can resume on this same physical line. Retain
      // its boundary rather than searching the remaining suffix again for
      // every '=' in an input such as '====KEY=value'.
      if (cursor > lineEnd) {
        lineEnd = text.indexOf('\n', cursor);
        if (lineEnd === -1) { lineEnd = text.length; }
      }
      // Node 22's comment, quoted-value and empty-value continuations check
      // '#' before stripping the next line's indentation. Preserve that
      // observable permissive-key quirk without changing normal comments.
      if (text[cursor] === '#' && (!untrimmedContinuation || directComment)) {
        cursor = lineEnd + 1;
        untrimmedContinuation = true;
        continue;
      }
      untrimmedContinuation = false;
      // Bound the separator search without copying the whole line's tail.
      // Recovery from an empty key advances over the consumed separator,
      // so neither malformed lines nor separator runs rescan old input.
      var equals = cursor;
      while (equals < lineEnd && text[equals] !== '=') { equals++; }
      if (equals === lineEnd) { cursor = lineEnd + 1; continue; }
      var key = envTrim(text.slice(cursor, equals));
      if (key.slice(0, 7) === 'export ') { key = envTrim(key.slice(7)); }
      var start = equals + 1;
      cursor = lineEnd + 1;
      var value = '';
      if (start < text.length && text[start] !== '\n') {
        // An immediately empty value stays empty. Otherwise the reference
        // also skips newlines following leading spaces/tabs after the '='.
        while (start < text.length && envWhitespace(text[start])) { start++; }
        if (key === '' && start < text.length) { cursor = start; continue; }
        var quote = text[start];
        var close = -1;
        if (quote === '"' || quote === "'" || quote === '`') {
          close = text.indexOf(quote, start + 1);
        }
        if (close !== -1) {
          value = text.slice(start + 1, close);
          if (quote === '"') { value = value.replace(/\\n/g, '\n'); }
          lineEnd = text.indexOf('\n', close + 1);
          untrimmedContinuation = true;
        } else {
          if (start > lineEnd) {
            lineEnd = text.indexOf('\n', start);
            if (lineEnd === -1) { lineEnd = text.length; }
          }
          value = text.slice(start, lineEnd);
          var comment = value.indexOf('#');
          if (comment !== -1 && quote !== '"' && quote !== "'" && quote !== '`') {
            value = value.slice(0, comment);
          }
          if (quote !== '"' && quote !== "'" && quote !== '`') { value = envTrim(value); }
        }
        cursor = lineEnd === -1 ? text.length : lineEnd + 1;
      } else {
        untrimmedContinuation = true;
      }
      entries[key] = value;
    }
    var result = {};
    var keys = Object.keys(entries).sort(envKeyOrder);
    for (var i = 0; i < keys.length; i++) {
      // Ordinary property assignment is intentional: Node's returned object
      // has Object.prototype and observes inherited setters. The private
      // collection above never does, and all published values are strings.
      result[keys[i]] = entries[keys[i]];
    }
    return result;
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
  var parseArgsSlice = Array.prototype.slice;
  var parseArgsApply = Reflect.apply;
  var parseArgsIncludes = Array.prototype.includes;
  function mainArgs() {
    var execArgv = process.execArgv;
    var start = 2;
    if (execArgv !== undefined &&
        (parseArgsApply(parseArgsIncludes, execArgv, ['-e']) ||
         parseArgsApply(parseArgsIncludes, execArgv, ['--eval']) ||
         parseArgsApply(parseArgsIncludes, execArgv, ['-p']) ||
         parseArgsApply(parseArgsIncludes, execArgv, ['--print']))) {
      start = 1;
    }
    return parseArgsApply(parseArgsSlice, process.argv, [start]);
  }
  function argsToTokens(args, options) {
    var tokens = [];
    var index = -1;
    var groupCount = 0;
    // A cursor over snapshot blocks replaces shift/unshift of the whole
    // remaining argv. Each argument/expanded flag is visited once. In
    // particular, a large short group must not become a host call's argument
    // list (unshift.apply), nor repeatedly move the remaining argument tail.
    // Separate blocks preserve Node's unusual '--' inside a short group and
    // its token indices without mutating the caller's array.
    var snapshot = parseArgsApply(parseArgsSlice, args, []);
    var remaining = snapshot.length ? { items: snapshot, position: 0, next: null } : null;
    function take() {
      var value = remaining.items[remaining.position++];
      while (remaining !== null && remaining.position === remaining.items.length) {
        remaining = remaining.next;
      }
      return value;
    }
    while (remaining !== null) {
      var arg = take();
      var nextArg = remaining === null ? undefined : remaining.items[remaining.position];
      if (groupCount > 0) { groupCount--; } else { index++; }
      if (arg === '--') {
        tokens.push({ kind: 'option-terminator', index: index });
        while (remaining !== null) {
          tokens.push({ kind: 'positional', index: ++index, value: take() });
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
          value = take();
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
        remaining = { items: expanded, position: 0, next: remaining };
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
          value = take();
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
  function checkOptionUsage(options, allowPositionals, allowNegative, token) {
    var name = token.name;
    // An explicitly declared no-* option wins validation. Otherwise only a
    // declared boolean admits the synthetic spelling; a string option may
    // not silently lose its required value. Retain rawName in diagnostics.
    if (!Object.prototype.hasOwnProperty.call(options, name) && allowNegative &&
        name.slice(0, 3) === 'no-' && optionSetting(options, name.slice(3), 'type') === 'boolean') {
      name = name.slice(3);
    }
    if (!Object.prototype.hasOwnProperty.call(options, name)) {
      var suggest = allowPositionals
        ? ". To specify a positional argument starting with a '-', place it at the end of the command after '--', as in '-- " +
          JSON.stringify(token.rawName)
        : '';
      throw parseArgsError('ERR_PARSE_ARGS_UNKNOWN_OPTION', "Unknown option '" + token.rawName + "'" + suggest);
    }
    var short = optionSetting(options, name, 'short');
    var shortAndLong = (short ? '-' + short + ', ' : '') + '--' + name;
    var type = optionSetting(options, name, 'type');
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
  function storeOption(token, allowNegative, options, values) {
    var longOption = token.name;
    var optionValue = token.value;
    if (longOption === '__proto__') { return; }
    // Negation is a valueless-option operation, including a short alias for
    // an explicit no-* boolean. Token.name exposes the normalized key while
    // rawName, index and the absent value/inlineValue remain unchanged.
    var negative = allowNegative && (optionValue === undefined || optionValue === null) &&
      longOption.slice(0, 3) === 'no-';
    if (negative) {
      longOption = longOption.slice(3);
      token.name = longOption;
    }
    var newValue = negative ? false : optionValue === undefined || optionValue === null ? true : optionValue;
    if (optionSetting(options, longOption, 'multiple')) {
      if (values[longOption]) { values[longOption].push(newValue); } else { values[longOption] = [newValue]; }
    } else {
      values[longOption] = newValue;
    }
  }
  function parseArgs(config) {
    if (config === undefined) { config = {}; }
    var args = ownValue(config, 'args');
    if (args === undefined || args === null) { args = mainArgs(); }
    var strict = ownValue(config, 'strict');
    if (strict === undefined || strict === null) { strict = true; }
    var allowPositionals = ownValue(config, 'allowPositionals');
    if (allowPositionals === undefined || allowPositionals === null) { allowPositionals = !strict; }
    var allowNegative = ownValue(config, 'allowNegative');
    if (allowNegative === undefined || allowNegative === null) { allowNegative = false; }
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
    validateParseArgsBoolean(allowNegative, 'allowNegative');
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
          checkOptionUsage(options, allowPositionals, allowNegative, token);
          checkOptionLikeValue(token);
        }
        storeOption(token, allowNegative, options, result.values);
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
  var MapClass = Map;
  var mapHas = Map.prototype.has;
  var mapGet = Map.prototype.get;
  var mapSet = Map.prototype.set;
  var mapDelete = Map.prototype.delete;
  var mapSize = Object.getOwnPropertyDescriptor(Map.prototype, 'size').get;
  var collectionApply = Reflect.apply;
  var ComparisonBytes = Uint8Array;
  // Pure-ECMAScript embeddings may omit Buffer; retain the scalar fallback.
  var compareBytes = typeof Buffer === 'undefined' ? undefined : Buffer.compare;
  var collectionIterator = Symbol.iterator;
  var ComparisonTypeError = TypeError;
  var comparisonCreate = Object.create;
  // Small comparisons keep their short ancestor scan. Deep comparisons index
  // ACTIVE ordered pairs, never completed results: getters and failed unordered
  // candidates must still be evaluated again. The common, distinct-left path
  // needs one Map and no per-level partner-set allocation after promotion. A
  // repeated left object with a different right needs a secondary pair set.
  function indexedPair(seen, a, b) {
    var first = collectionApply(mapGet, seen[0], [a]);
    if (first === b) { return true; }
    if (first === undefined) {
      collectionApply(mapSet, seen[0], [a, b]);
      return false;
    }
    if (seen[1] === undefined) { seen[1] = new MapClass(); }
    var others = collectionApply(mapGet, seen[1], [a]);
    if (others === undefined) {
      others = new MapClass();
      collectionApply(mapSet, seen[1], [a, others]);
    } else if (collectionApply(mapHas, others, [b])) {
      return true;
    }
    collectionApply(mapSet, others, [b, true]);
    return false;
  }
  function leaveIndexedPair(seen, a, b) {
    if (collectionApply(mapGet, seen[0], [a]) === b) {
      collectionApply(mapDelete, seen[0], [a]);
    } else {
      var others = collectionApply(mapGet, seen[1], [a]);
      collectionApply(mapDelete, others, [b]);
      if (collectionApply(mapSize, others, []) === 0) {
        collectionApply(mapDelete, seen[1], [a]);
      }
    }
  }
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
  function snapshotCollection(value, isMap, snapshot) {
    var iterate = isMap ? mapEntries : setValues;
    var primitive, candidates, count = 0;
    for (var candidate of collectionApply(iterate, value, [])) {
      var key = isMap ? candidate[0] : candidate;
      if (key === null || typeof key !== 'object') {
        // Object-only collections need no primitive-key index. Keep the
        // iteration count separately: a replaced iterator can repeat a key.
        if (primitive === undefined) { primitive = new MapClass(); }
        collectionApply(mapSet, primitive, [key, isMap ? candidate[1] : true]);
      } else {
        if (candidates === undefined) { candidates = []; }
        candidates.push(candidate);
      }
      count++;
    }
    // Publish once, keeping per-entry work in locals rather than heap fields.
    snapshot.primitive = primitive;
    snapshot.candidates = candidates;
    snapshot.candidateCount = count;
  }
  function unorderedEqual(a, b, seen, isMap) {
    var iterate = isMap ? mapEntries : setValues;
    // Primitive keys (including symbols, NaN and function identities) can
    // only match the identical key. Index the right-hand snapshot once
    // instead of scanning it for every left-hand entry. Objects still need
    // one-to-one structural matching; object-key identity alone is not enough
    // for Maps whose structurally equal keys may carry different values.
    // Snapshot values as well as keys: a value getter in a nested comparison
    // must not rewrite a later candidate through the original Map.
    var snapshot = { primitive: undefined, candidates: undefined, candidateCount: 0 };
    snapshotCollection(b, isMap, snapshot);
    var primitive = snapshot.primitive, candidates = snapshot.candidates;
    var candidateCount = snapshot.candidateCount;
    // Start at the first still-available object candidate. Ordered matches
    // need no consumed flags; only out-of-order matches allocate a private
    // null-prototype table, never exposing bookkeeping to indexed setters.
    var matched, first = 0;
    var count = 0;
    for (var entry of collectionApply(iterate, a, [])) {
      var entryKey = isMap ? entry[0] : entry;
      if (entryKey === null || typeof entryKey !== 'object') {
        if (primitive === undefined || !collectionApply(mapHas, primitive, [entryKey]) ||
            (isMap && !deepEqual(entry[1], collectionApply(mapGet, primitive, [entryKey]), seen))) {
          return false;
        }
        // Consume the match. Reentrant mutation/reinsertion of a left key
        // must not allow the same right-hand snapshot entry to match twice.
        collectionApply(mapDelete, primitive, [entryKey]);
        count++;
        continue;
      }
      if (candidates === undefined) { return false; }
      var found = false;
      for (var i = first; i < candidates.length; i++) {
        if (matched !== undefined && matched[i]) {
          continue;
        }
        var other = candidates[i];
        var equal = isMap
          ? deepEqual(entry[0], other[0], seen) && deepEqual(entry[1], other[1], seen)
          : deepEqual(entry, other, seen);
        if (equal) {
          // Distinct object identities can be structurally equal; every
          // right-hand entry may nevertheless satisfy only one left entry.
          if (i === first) {
            first++;
            while (matched !== undefined && matched[first]) { delete matched[first++]; }
          } else {
            if (matched === undefined) { matched = comparisonCreate(null); }
            matched[i] = true;
          }
          // A consumed right entry can never match again. Release its
          // snapshot reference before the next left entry can run guest code.
          candidates[i] = undefined;
          other = undefined;
          count++;
          found = true;
          break;
        }
      }
      if (!found) {
        return false;
      }
    }
    return count === candidateCount;
  }
  // Compare only the selected byte windows. Large, ordinary buffers use the
  // existing native Buffer comparator rather than dispatching JavaScript for
  // every byte. Views share their input storage; no payload-sized copy is made.
  // Keep the scalar path for small or guest-coerced windows. Such coercion can
  // resize/detach an earlier view, whose indexed-read behavior must not change.
  function equalByteRanges(bufferA, offsetA, lengthA, bufferB, offsetB, lengthB, knownBuffers) {
    if (lengthA !== lengthB) {
      return false;
    }
    var ordinary = compareBytes !== undefined && typeof lengthA === 'number' && lengthA >= 1024 &&
      typeof offsetA === 'number' && typeof offsetB === 'number' &&
      (knownBuffers || (typeTag(bufferA) === 'ArrayBuffer' && typeTag(bufferB) === 'ArrayBuffer'));
    var bytesA = new ComparisonBytes(bufferA, offsetA, lengthA);
    var bytesB = new ComparisonBytes(bufferB, offsetB, lengthB);
    if (ordinary) {
      // Preserve cheap rejection when the first byte already differs.
      if (bytesA[0] !== bytesB[0]) { return false; }
      return compareBytes(bytesA, bytesB) === 0;
    }
    for (var i = 0; i < lengthA; i++) {
      if (bytesA[i] !== bytesB[i]) {
        return false;
      }
    }
    return true;
  }
  function equalErrorShape(a, b) {
    if (a.message !== b.message || a.name !== b.name) { return -1; }
    var causeA = Object.prototype.hasOwnProperty.call(a, 'cause');
    var causeB = Object.prototype.hasOwnProperty.call(b, 'cause');
    return causeA !== causeB ? -1 : causeA ? 1 : 0;
  }
  function equalObject(a, b, tag, seen, stateOnly) {
    if (!stateOnly && seen[0] !== undefined) { return equalIndexedGraph(a, b, tag, seen); }
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
      var shape = equalErrorShape(a, b);
      if (shape < 0 || (shape === 1 && !deepEqual(a.cause, b.cause, seen)) ||
          !deepEqual(a.errors, b.errors, seen)) {
        return false;
      }
    }
    if (tag === 'ArrayBuffer' &&
        !equalByteRanges(a, 0, a.byteLength, b, 0, b.byteLength, true)) {
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
    // Shallow payload comparisons can promote the shared index. Their own
    // payload is already complete; continue with properties without rerunning it.
    if (stateOnly) { return true; }
    if (seen[0] !== undefined) { return equalIndexedGraph(a, b, null, seen); }
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
  // Iterative frames cover properties AND special payloads. An unordered
  // candidate's false result belongs to its collection, not the entire graph:
  // unwind the candidate before trying the next one, without memoizing failure.
  function indexedCollection(frame) {
    var isMap = frame.tag === 'Map';
    var iterate = isMap ? mapEntries : setValues;
    var state = { primitive: undefined, candidates: undefined, matched: undefined, first: 0,
      candidateCount: 0, count: 0, isMap: isMap, open: false, iterator: undefined,
      next: undefined, entry: undefined, key: undefined, index: 0, other: undefined };
    // Keep the existing right snapshot / live left iteration contract. No
    // getter in a nested value comparison can rewrite a snapshot candidate.
    snapshotCollection(frame.right, isMap, state);
    var iterable = collectionApply(iterate, frame.left, []);
    state.iterator = collectionApply(iterable[collectionIterator], iterable, []);
    if (!iteratorObject(state.iterator)) { throw new ComparisonTypeError('Iterator must be an object'); }
    state.next = state.iterator.next;
    return state;
  }
  function iteratorObject(value) {
    return value !== null && (typeof value === 'object' || typeof value === 'function');
  }
  function closeIndexedCollection(state, throwing) {
    if (state === undefined || !state.open) { return; }
    state.open = false;
    // Like for-of, close on an early body return/throw, not on a failed next,
    // done or value read. A pending throw takes precedence over close errors.
    try {
      var finish = state.iterator.return;
      if (finish !== undefined && finish !== null) {
        var result = collectionApply(finish, state.iterator, []);
        if (!iteratorObject(result)) { throw new ComparisonTypeError('Iterator result must be an object'); }
      }
    } catch (error) { if (!throwing) { throw error; } }
  }
  function finishIndexedFrame(work, seen, equal) {
    var frame = work.top;
    if (!equal) { closeIndexedCollection(frame.collection, false); }
    work.top = frame.parent;
    if (frame.parent !== null) { leaveIndexedPair(seen, frame.left, frame.right); }
    work.equal = equal;
  }
  function equalIndexedGraph(a, b, tag, seen) {
    // The root pair belongs to deepEqual's finally. Each other frame owns
    // exactly one active pair. Values are read only at their comparison turn.
    var work = { top: { left: a, right: b, tag: tag, phase: tag === null ? 3 : 0,
      keys: null, index: 0, collection: undefined, parent: null }, equal: true };
    try {
      while (work.top !== null) {
        var frame = work.top;
        var left = frame.left, right = frame.right;
        if (frame.phase === 0) {
          if (frame.tag === 'Error') {
            var shape = equalErrorShape(left, right);
            if (shape < 0) { finishIndexedFrame(work, seen, false); continue; }
            frame.phase = 1;
            work.equal = shape === 0 || deepEqual(left.cause, right.cause, seen, work);
            continue;
          }
          if (frame.tag === 'Map' || frame.tag === 'Set') {
            if (left.size !== right.size) { finishIndexedFrame(work, seen, false); continue; }
            frame.collection = indexedCollection(frame);
            frame.phase = 5;
            continue;
          }
          if (!equalObject(left, right, frame.tag, seen, true)) {
            finishIndexedFrame(work, seen, false); continue;
          }
          frame.phase = 3;
        }
        if (frame.phase === 1) { // Error cause completed; errors is read AFTER it.
          if (!work.equal) { finishIndexedFrame(work, seen, false); continue; }
          frame.phase = 2;
          work.equal = deepEqual(left.errors, right.errors, seen, work);
          continue;
        }
        if (frame.phase === 2) {
          if (!work.equal) { finishIndexedFrame(work, seen, false); continue; }
          frame.phase = 3;
        }
        if (frame.phase === 3) {
          frame.keys = enumerableKeys(left);
          if (frame.keys.length !== enumerableKeys(right).length) {
            finishIndexedFrame(work, seen, false); continue;
          }
          frame.phase = 4;
          work.equal = true;
        }
        if (frame.phase === 4) {
          if (!work.equal) { finishIndexedFrame(work, seen, false); continue; }
          if (frame.index === frame.keys.length) {
            finishIndexedFrame(work, seen, true); continue;
          }
          var property = frame.keys[frame.index++];
          work.equal = Object.prototype.propertyIsEnumerable.call(right, property) &&
            deepEqual(left[property], right[property], seen, work);
          continue;
        }
        var state = frame.collection;
        if (frame.phase === 5) { // Advance the live left iterator once.
          state.open = false;
          var step = collectionApply(state.next, state.iterator, []);
          if (!iteratorObject(step)) { throw new ComparisonTypeError('Iterator result must be an object'); }
          if (step.done) {
            if (state.count !== state.candidateCount) { finishIndexedFrame(work, seen, false); }
            else { frame.collection = undefined; frame.phase = 3; }
            continue;
          }
          state.entry = step.value;
          state.open = true;
          state.key = state.isMap ? state.entry[0] : state.entry;
          if (state.key === null || typeof state.key !== 'object') {
            if (state.primitive === undefined || !collectionApply(mapHas, state.primitive, [state.key])) {
              finishIndexedFrame(work, seen, false); continue;
            }
            frame.phase = 6;
            work.equal = !state.isMap || deepEqual(state.entry[1],
              collectionApply(mapGet, state.primitive, [state.key]), seen, work);
            continue;
          }
          if (state.candidates === undefined) { finishIndexedFrame(work, seen, false); continue; }
          state.index = state.first;
          frame.phase = 7;
        }
        if (frame.phase === 6) { // A primitive key's value completed.
          if (!work.equal) { finishIndexedFrame(work, seen, false); continue; }
          collectionApply(mapDelete, state.primitive, [state.key]);
          state.count++;
          frame.phase = 5;
          continue;
        }
        if (frame.phase === 7) { // Try unmatched object candidates in original order.
          while (state.index < state.candidates.length && state.matched !== undefined && state.matched[state.index]) { state.index++; }
          if (state.index === state.candidates.length) { finishIndexedFrame(work, seen, false); continue; }
          state.other = state.candidates[state.index];
          frame.phase = 8;
          work.equal = deepEqual(state.isMap ? state.entry[0] : state.entry,
            state.isMap ? state.other[0] : state.other, seen, work);
          continue;
        }
        if (frame.phase === 8 && work.equal && state.isMap) {
          frame.phase = 9; // A Map value is compared only AFTER its key succeeds.
          work.equal = deepEqual(state.entry[1], state.other[1], seen, work);
          continue;
        }
        // A failed key/value releases its own pairs before retrying. A
        // successful candidate is consumed once, even if later keys are equal.
        if (work.equal) {
          if (state.index === state.first) {
            state.first++;
            while (state.matched !== undefined && state.matched[state.first]) { delete state.matched[state.first++]; }
          } else {
            if (state.matched === undefined) { state.matched = comparisonCreate(null); }
            state.matched[state.index] = true;
          }
          state.candidates[state.index] = undefined;
          state.other = undefined;
          state.count++;
          frame.phase = 5;
        } else { state.index++; frame.phase = 7; }
      }
      return work.equal;
    } finally {
      while (work.top !== null) {
        var pending = work.top;
        work.top = pending.parent;
        closeIndexedCollection(pending.collection, true);
        if (pending.parent !== null) { leaveIndexedPair(seen, pending.left, pending.right); }
      }
    }
  }
  function deepEqual(a, b, seen, work) {
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
    if (seen === undefined) { seen = [undefined, undefined]; }
    // Two own header slots hold the optional indexes; later slots are the
    // short ancestor stack. This avoids a second context allocation on the
    // common shallow path, and never reads an inherited metadata property.
    if (seen[0] === undefined) {
      for (var i = 2; i < seen.length; i++) {
        if (seen[i][0] === a && seen[i][1] === b) {
          return true;
        }
      }
      if (seen.length < 66) { // two headers plus at most 64 active pairs
        seen.push([a, b]);
        try {
          return equalObject(a, b, tag, seen);
        } finally {
          seen.pop();
          // A descendant may have promoted this same comparison. Its index
          // includes these earlier ancestors and must unwind them too.
          if (seen[0] !== undefined) { leaveIndexedPair(seen, a, b); }
        }
      }
      seen[0] = new MapClass();
      for (var j = 2; j < seen.length; j++) {
        indexedPair(seen, seen[j][0], seen[j][1]);
      }
    }
    if (indexedPair(seen, a, b)) { return true; }
    if (work !== undefined) {
      // The explicit walker now owns this pair until its frame completes or
      // unwinds. No metadata/getter work may happen before ownership is saved.
      work.top = { left: a, right: b, tag: tag, phase: 0, keys: null, index: 0,
        collection: undefined, parent: work.top };
      return true;
    }
    // Only active ancestors break cycles. A failed unordered candidate must
    // not leave "equal" pairs behind for the next candidate or sibling.
    try {
      return equalObject(a, b, tag, seen);
    } finally {
      leaveIndexedPair(seen, a, b);
    }
  }
  function isDeepStrictEqual(a, b) {
    return deepEqual(a, b);
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
    parseEnv: parseEnv,
    styleText: styleText,
    stripVTControlCharacters: stripVTControlCharacters,
    toUSVString: toUSVString,
    types: types,
    isArray: Array.isArray,
    TextEncoder: TextEncoder,
    TextDecoder: TextDecoder
  };
})()
