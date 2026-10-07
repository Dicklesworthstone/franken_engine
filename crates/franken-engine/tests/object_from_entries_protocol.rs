#![forbid(unsafe_code)]

//! ES2020 19.1.2.7 Object.fromEntries (AddEntriesFromIterable): each
//! entry's key and value are Get(entry, "0") / Get(entry, "1") and the key
//! goes through ToPropertyKey; an entry that is not an object, a throwing
//! getter or a throwing key conversion closes the iterator. The engine read
//! entries as array elements (an accessor entry keyed "[accessor]", an
//! object key "[object#N]", a String object entry undefined) and never
//! closed the iterator (8 Node-passing Test262 tests in the rc-next33
//! merged-tree census).

use frankenengine_engine::HybridRouter;

/// Abrupt entries with the iterator's return counted, a throwing return
/// (the entry's TypeError wins), String object and accessor entries, key
/// conversion (object, number, symbol), short and long entries, a Map, and
/// the result's prototype. Expected lines are Node v22.2.0's output,
/// captured programmatically.
#[test]
fn from_entries_reads_entries_and_closes_the_iterator() {
    let source = r#"function k(f) { try { return JSON.stringify(f()); } catch (e) { return e.constructor.name + (e.message === 'boom' ? ':boom' : ''); } }
function tracked(entries) {
  var log = { closed: 0 };
  var index = 0;
  log.iterable = {};
  log.iterable[Symbol.iterator] = function () {
    return {
      next: function () { return index < entries.length ? { value: entries[index++], done: false } : { value: undefined, done: true }; },
      return: function () { log.closed++; return {}; }
    };
  };
  return log;
}
var nullEntry = tracked([['a', 1], null]);
var stringEntry = tracked(['ab']);
var throwingKey = tracked([{ get 0() { throw new Error('boom'); }, 1: 'v' }]);
var throwingToString = tracked([[{ toString: function () { throw new Error('boom'); } }, 'v']]);
console.log(k(function () { return Object.fromEntries(nullEntry.iterable); }), nullEntry.closed, k(function () { return Object.fromEntries(stringEntry.iterable); }), stringEntry.closed, k(function () { return Object.fromEntries(throwingKey.iterable); }), throwingKey.closed, k(function () { return Object.fromEntries(throwingToString.iterable); }), throwingToString.closed);
console.log(k(function () { return Object.fromEntries([new String('ab'), new String('cd')]); }), k(function () { return Object.fromEntries([[{ toString: function () { return 'key'; } }, 'value'], [1, 'one'], [Symbol.iterator, 's']]); }));
var accessorEntry = { get 0() { return 'g'; }, get 1() { return 'h'; } };
console.log(k(function () { return Object.fromEntries([accessorEntry, ['x', 1, 2], [], ['y']]); }), k(function () { return Object.fromEntries(new Map([['m', 1]])); }), Object.getPrototypeOf(Object.fromEntries([])) === Object.prototype);
var badReturn = tracked([7]);
badReturn.iterable[Symbol.iterator] = (function (make) { return function () { var it = make(); it.return = function () { throw new Error('return'); }; return it; }; })(badReturn.iterable[Symbol.iterator]);
console.log(k(function () { return Object.fromEntries(badReturn.iterable); }));
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "TypeError 1 TypeError 1 Error:boom 1 Error:boom 1",
            "{\"a\":\"b\",\"c\":\"d\"} {\"1\":\"one\",\"key\":\"value\"}",
            "{\"g\":\"h\",\"x\":1} {\"m\":1} true",
            "TypeError",
        ]
    );
}
