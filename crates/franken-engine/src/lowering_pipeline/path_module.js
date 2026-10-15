(function () {
  'use strict';
  function join() {
    var joined = '';
    for (var i = 0; i < arguments.length; i++) {
      var segment = arguments[i];
      if (typeof segment !== 'string') {
        __franken_path_normalize(segment);
      }
      if (segment.length > 0) {
        joined = joined.length === 0 ? segment : joined + '/' + segment;
      }
    }
    return joined.length === 0 ? '.' : __franken_path_normalize(joined);
  }
  // The HostCall scans from the last argument and names a bad one by its
  // position, so the argument goes where it was, after empty paths that do
  // not end the scan.
  function invalidResolveArgument(index, value) {
    switch (index) {
      case 0: return __franken_path_resolve(value);
      case 1: return __franken_path_resolve('', value);
      case 2: return __franken_path_resolve('', '', value);
      case 3: return __franken_path_resolve('', '', '', value);
      case 4: return __franken_path_resolve('', '', '', '', value);
      case 5: return __franken_path_resolve('', '', '', '', '', value);
      case 6: return __franken_path_resolve('', '', '', '', '', '', value);
      default: return __franken_path_resolve('', '', '', '', '', '', '', value);
    }
  }
  function resolve() {
    var resolved = '';
    for (var i = arguments.length - 1; i >= 0; i--) {
      var segment = arguments[i];
      if (typeof segment !== 'string') {
        invalidResolveArgument(i, segment);
      }
      if (segment.length === 0) {
        continue;
      }
      resolved = resolved.length === 0 ? segment : segment + '/' + resolved;
      if (segment.charCodeAt(0) === 47) {
        break;
      }
    }
    return __franken_path_resolve(resolved);
  }
  function normalize(path) {
    return __franken_path_normalize(path);
  }
  function isAbsolute(path) {
    return __franken_path_is_absolute(path);
  }
  function relative(from, to) {
    return __franken_path_relative(from, to);
  }
  function toNamespacedPath(path) {
    return path;
  }
  function dirname(path) {
    return __franken_path_dirname(path);
  }
  function basename(path, suffix) {
    return __franken_path_basename(path, suffix);
  }
  function extname(path) {
    return __franken_path_extname(path);
  }
  function format(pathObject) {
    return __franken_path_format(pathObject);
  }
  function parse(path) {
    return __franken_path_parse(path);
  }
  var path = {
    resolve: resolve,
    normalize: normalize,
    isAbsolute: isAbsolute,
    join: join,
    relative: relative,
    toNamespacedPath: toNamespacedPath,
    dirname: dirname,
    basename: basename,
    extname: extname,
    format: format,
    parse: parse,
    sep: '/',
    delimiter: ':',
    posix: undefined
  };
  // One Windows namespace over the existing lexical path HostCalls. The
  // resolver's cwd comes from PathResolve, never process.env or host I/O.
  // This runtime has a POSIX logical cwd; Windows per-drive environment
  // overrides are not imported into it.
  var isArray = Array.isArray;
  function slash(text, index) {
    var code = text.charCodeAt(index);
    return code === 47 || code === 92;
  }
  function winRoot(text) {
    var length = text.length, end = 0, device = '', absolute = false;
    if (slash(text, 0)) {
      absolute = true; end = 1;
      if (slash(text, 1) && !slash(text, 2)) {
        var serverEnd = 2;
        while (serverEnd < length && !slash(text, serverEnd)) serverEnd++;
        var shareStart = serverEnd;
        while (shareStart < length && slash(text, shareStart)) shareStart++;
        var shareEnd = shareStart;
        while (shareEnd < length && !slash(text, shareEnd)) shareEnd++;
        if (serverEnd > 2 && shareEnd > shareStart) {
          device = '\\\\' + text.slice(2, serverEnd) + '\\' + text.slice(shareStart, shareEnd);
          end = shareEnd < length ? shareEnd + 1 : shareEnd;
        }
      }
    } else {
      var letter = text.charCodeAt(0);
      if (text.charCodeAt(1) === 58 && ((letter >= 65 && letter <= 90) || (letter >= 97 && letter <= 122))) {
        device = text.slice(0, 2); end = 2;
        if (slash(text, 2)) { absolute = true; end = 3; }
      }
    }
    return { end: end, device: device, absolute: absolute };
  }
  function winNormalize(value) {
    if (typeof value !== 'string') return __franken_path_normalize(value);
    return __franken_path_win32_join(value);
  }
  function winJoin() {
    var joined = '', first = '';
    for (var i = 0; i < arguments.length; i++) {
      var segment = arguments[i];
      if (typeof segment !== 'string') __franken_path_win32_join(segment);
      if (segment.length !== 0) {
        if (joined.length === 0) { joined = segment; first = segment; }
        else joined += '\\' + segment;
      }
    }
    if (joined.length === 0) return '.';
    // Combining '/' with '/server' must not manufacture a UNC root. A UNC
    // candidate must originate in the first nonempty input, not a join seam.
    if (!(slash(first, 0) && slash(first, 1) && first.length > 2 && !slash(first, 2))) {
      var leading = 0;
      while (leading < joined.length && slash(joined, leading)) leading++;
      if (leading > 1) joined = '\\' + joined.slice(leading);
    }
    return __franken_path_win32_join(joined);
  }
  function winResolve() {
    var device = '', absolute = false, tail = '';
    for (var i = arguments.length - 1; i >= -1; i--) {
      var segment = i === -1 ? __franken_path_resolve('') : arguments[i];
      if (typeof segment !== 'string') invalidResolveArgument(i, segment);
      if (segment.length === 0) continue;
      var root = winRoot(segment);
      if (root.device.length !== 0) {
        if (device.length !== 0 && device.toLowerCase() !== root.device.toLowerCase()) continue;
        if (device.length === 0) device = root.device;
      }
      if (!absolute) {
        tail = segment.slice(root.end) + '\\' + tail;
        absolute = root.absolute;
      }
      if (absolute && device.length !== 0) break;
    }
    var leading = 0;
    while (leading < tail.length && slash(tail, leading)) leading++;
    var output = winNormalize(device + (absolute ? '\\' : '') + tail.slice(leading));
    var minimum = winRoot(output).end;
    while (output.length > minimum && slash(output, output.length - 1)) output = output.slice(0, -1);
    return output;
  }
  function winIsAbsolute(value) { return __franken_path_win32_is_absolute(value); }
  function winBasename(value, suffix) { return __franken_path_win32_basename(value, suffix); }
  function winDirname(value) {
    if (typeof value !== 'string') return __franken_path_dirname(value);
    if (value.length === 0) return '.';
    var root = winRoot(value), end = value.length;
    while (end > root.end && slash(value, end - 1)) end--;
    var start = end;
    while (start > root.end && !slash(value, start - 1)) start--;
    if (start <= root.end) return root.end === 0 ? '.' : value.slice(0, root.end);
    return value.slice(0, start - 1);
  }
  function winParse(value) {
    if (typeof value !== 'string') return __franken_path_parse(value);
    var root = winRoot(value), end = value.length;
    while (end > root.end && slash(value, end - 1)) end--;
    var start = end;
    while (start > root.end && !slash(value, start - 1)) start--;
    var base = value.slice(start, end);
    var ext = __franken_path_extname(base);
    return { root: value.slice(0, root.end),
      dir: start <= root.end ? value.slice(0, root.end) : value.slice(0, start - 1),
      base: base, ext: ext, name: base.slice(0, base.length - ext.length) };
  }
  function winExtname(value) {
    if (typeof value !== 'string') return __franken_path_extname(value);
    return __franken_path_extname(winBasename(value));
  }
  function winFormat(value) {
    if (value === null || typeof value !== 'object' || isArray(value)) return __franken_path_format(value);
    var dir = value.dir || value.root;
    var base = value.base;
    if (!base) {
      // Template coercion happens before the next field is read. Getter and
      // Symbol.toPrimitive effects must not be reordered by field snapshots.
      base = `${value.name || ''}${winFormatExt(value.ext)}`;
    }
    if (!dir) return base;
    var separator = dir === value.root ? '' : '\\';
    return `${dir}${separator}${base}`;
  }
  function winFormatExt(ext) {
    if (!ext) return '';
    return ext[0] === '.' ? `${ext}` : `.${ext}`;
  }
  function winRelative(from, to) {
    if (typeof from !== 'string' || typeof to !== 'string') return __franken_path_relative(from, to);
    if (from === to) return '';
    var first = winResolve(from), second = winResolve(to);
    if (first === second) return '';
    var a = first.toLowerCase(), b = second.toLowerCase();
    if (a === b) return '';
    var startA = 0, startB = 0, endA = a.length, endB = b.length;
    while (startA < endA && slash(a, startA)) startA++;
    while (startB < endB && slash(b, startB)) startB++;
    while (endA > startA && slash(a, endA - 1)) endA--;
    while (endB > startB && slash(b, endB - 1)) endB--;
    var i = startA, j = startB;
    while (i < endA && j < endB) {
      var ae = i, be = j;
      while (ae < endA && !slash(a, ae)) ae++;
      while (be < endB && !slash(b, be)) be++;
      if (a.slice(i, ae) !== b.slice(j, be)) break;
      i = ae < endA ? ae + 1 : ae;
      j = be < endB ? be + 1 : be;
    }
    var partialRoot = false;
    if (i === startA && j === startB && endA > startA && endB > startB) {
      var left = a.slice(startA, endA), right = b.slice(startB, endB);
      var leftPrefix = right.slice(0, left.length) === left;
      var rightPrefix = left.slice(0, right.length) === right;
      if (!leftPrefix && !rightPrefix) return second;
      // Node also applies its two-character device boundary to rooted paths
      // without a drive. Retain those observed edge results rather than
      // silently treating partial first-component prefixes as siblings.
      if (leftPrefix && left.length === 2) return second.slice(startB + 2);
      if (rightPrefix && right.length === 2) {
        var ascent = left.length < 4 ? '' : '..';
        for (var boundary = 4; boundary < left.length; boundary++) {
          if (slash(left, boundary)) ascent += '\\..';
        }
        return ascent;
      } else partialRoot = true;
    }
    var up = '';
    for (var k = i; k < endA; k++) {
      if (k === i || slash(a, k - 1)) up += up.length === 0 ? '..' : '\\..';
    }
    var down = second.slice(j, up.length === 0 && endA > startA ? second.length : endB);
    return up.length === 0 ? down : down.length === 0 ? up : up + (partialRoot ? '' : '\\') + down;
  }
  function winToNamespacedPath(value) {
    if (typeof value !== 'string' || value.length === 0) return value;
    var resolved = winResolve(value);
    if (resolved.length > 2 && slash(resolved, 0) && slash(resolved, 1)) {
      if (resolved[2] !== '?' && resolved[2] !== '.') return '\\\\?\\UNC\\' + resolved.slice(2);
    } else if (resolved.length > 2 && resolved[1] === ':' && slash(resolved, 2)) {
      return '\\\\?\\' + resolved;
    }
    return resolved.length <= 2 ? value : resolved;
  }
  var windows = { resolve: winResolve, normalize: winNormalize, isAbsolute: winIsAbsolute,
    join: winJoin, relative: winRelative, toNamespacedPath: winToNamespacedPath,
    dirname: winDirname, basename: winBasename, extname: winExtname, format: winFormat,
    parse: winParse, sep: '\\', delimiter: ';', posix: path, win32: undefined };
  windows.win32 = windows;
  path.win32 = windows;
  path.posix = path;
  return path;
})()
