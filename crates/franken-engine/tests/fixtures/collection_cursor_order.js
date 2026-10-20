[
  function readOnlyWalks() {
    var map = new Map();
    var set = new Set();
    for (var i = 0; i < 512; i++) { map.set('k' + i, i); set.add(i); }
    var keyCount = 0;
    for (var key of map.keys()) {
      if (key !== 'k' + keyCount) throw new Error('map key order');
      keyCount++;
    }
    var sum = 0;
    for (var value of map.values()) sum += value;
    var entries = 0;
    for (var pair of map.entries()) {
      if (pair[0] !== 'k' + entries || pair[1] !== entries) throw new Error('map entries');
      entries++;
    }
    var callbacks = 0;
    map.forEach(function (value, key, receiver) {
      if (receiver !== map || key !== 'k' + value) throw new Error('map callback');
      callbacks++;
    });
    var setCount = 0;
    set.forEach(function (value, key, receiver) {
      if (receiver !== set || key !== value) throw new Error('set callback');
      setCount++;
    });
    var setSum = 0;
    for (var item of set.values()) setSum += item;
    var copy = set.union(new Set());
    if (keyCount !== 512 || entries !== 512 || callbacks !== 512 || setCount !== 512 ||
        sum !== 130816 || setSum !== sum || copy.size !== 512) throw new Error('walk totals');
    return keyCount + ':' + sum + ':' + copy.size;
  },
  function mapMutation() {
    var map = new Map([['a', 1], ['b', 2], ['c', 3], ['d', 4]]);
    var first = map.keys();
    var second = map.keys();
    var out = [first.next().value, second.next().value, second.next().value];
    map.delete('a');
    map.delete('c');
    map.set('b', 20);
    map.set('a', 10);
    out.push(first.next().value, second.next().value);
    map.clear();
    map.set('z', 26);
    out.push(first.next().value, second.next().value, first.next().done);
    map.set('later', 99);
    out.push(first.next().done, second.next().value, second.next().done);
    return out.join(',');
  },
  function nestedSetWalks() {
    var set = new Set([1, 2, 3]);
    var out = [];
    set.forEach(function (value) {
      out.push('outer' + value);
      if (value === 1) {
        set.forEach(function (inner) {
          out.push('inner' + inner);
          if (inner === 1) { set.delete(1); set.delete(2); set.add(4); }
        });
        set.add(1);
      }
      // Bound the second encounter without hiding it from the outer cursor.
      if (value === 4) set.delete(1);
    });
    return out.join(',') + '|' + Array.from(set).join(',');
  },
  function setAlgebraMutation() {
    var left = new Set([1, 2, 3]);
    var seen = [];
    var other = {
      size: 9,
      has: function (value) {
        seen.push(value);
        if (value === 1) { left.delete(2); left.add(4); }
        return value % 2 === 0;
      },
      keys: function () { throw new Error('wrong size branch'); }
    };
    var intersection = left.intersection(other);
    var live = seen.join(',') + ':' + Array.from(intersection).join(',');
    left = new Set([1, 2, 3]);
    seen = [];
    other.has = function (value) { seen.push(value); left.clear(); return value === 2; };
    var difference = left.difference(other);
    return live + '|' + seen.join(',') + ':' + Array.from(difference).join(',');
  },
  function thrownCallbacks() {
    var map = new Map([['a', 1], ['b', 2], ['c', 3]]);
    var iterator = map.keys();
    var out = [iterator.next().value];
    var caught = false;
    try {
      map.forEach(function (value, key) {
        out.push(key);
        if (key === 'b') { map.delete('a'); map.set('d', 4); throw 0; }
      });
    } catch (error) { caught = error === 0; }
    out.push(caught, iterator.next().value, iterator.next().value, iterator.next().value,
      iterator.next().done);
    return out.join(',');
  },
  function mixedPropertyAndMemberKeys() {
    var object = {};
    object.b = 1; object['10'] = 10; object['2'] = 2;
    object['\ud800'] = 8; object['\ufffd'] = 9; object.a = 3;
    delete object.b; object.b = 4;
    var names = Object.keys(object).map(function (key) {
      return key === '\ud800' ? 'lone' : key === '\ufffd' ? 'replacement' : key;
    }).join(',');
    var token = {};
    var symbol = Symbol('member');
    var map = new Map([[NaN, 1], [-0, 2], [token, 3], [symbol, 4], ['\ud800', 5], ['\ufffd', 6]]);
    map.delete(token); map.set(token, 7); map.set(NaN, 8);
    var values = Array.from(map.values()).join(',');
    if (map.get(token) !== 7 || map.get(symbol) !== 4 || map.get('\ud800') !== 5 ||
        map.get('\ufffd') !== 6 || map.get(NaN) !== 8) throw new Error('member identity');
    var keys = map.keys();
    if (!Number.isNaN(keys.next().value) || !Object.is(keys.next().value, 0)) throw new Error('number keys');
    return names + '|' + values;
  },
  function deletedPrefixAndCompaction() {
    var map = new Map();
    for (var i = 0; i < 256; i++) map.set('k' + i, i);
    var behind = map.values();
    var ahead = map.values();
    behind.next();
    for (var j = 0; j < 129; j++) ahead.next();
    // Leave a deleted prefix spanning multiple order-index words without
    // reaching compaction, then compact while both cursors remain live.
    for (var prefix = 0; prefix < 96; prefix++) map.delete('k' + prefix);
    var out = [behind.next().value, ahead.next().value];
    for (var tail = 160; tail < 256; tail++) map.delete('k' + tail);
    map.set('k0', 1000);
    out.push(behind.next().value, ahead.next().value);
    var behindCount = 0, behindSum = 0;
    for (var value of behind) { behindCount++; behindSum += value; }
    var aheadCount = 0, aheadSum = 0;
    for (var item of ahead) { aheadCount++; aheadSum += item; }
    out.push(behindCount, behindSum, aheadCount, aheadSum, map.size);
    return out.join(':');
  },
  function deletingAcrossOrderWords() {
    var set = new Set();
    for (var i = 0; i < 260; i++) set.add(i);
    var iterator = set.values();
    var initial = iterator.next().value;
    var count = 0, sum = 0;
    set.forEach(function (value) {
      count++; sum += value;
      set.delete(value);
      // Reinsertions append to the live order even when deletion rebuilds
      // the order index. The separate cursor must still see that suffix.
      if (value < 4) set.add(value + 1000);
      if (value === 259) set.delete(1001);
    });
    var empty = iterator.next().done;
    set.add(2000);
    return [initial, count, sum, set.size, empty, iterator.next().done,
      Array.from(set).join(',')].join(':');
  }
]
