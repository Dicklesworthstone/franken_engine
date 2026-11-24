#![forbid(unsafe_code)]

//! DataView construction must convert its arguments once before observing
//! newTarget.prototype, then recheck a buffer changed by guest callbacks.
//! Covers ES2024 25.3.2.1 and the remaining object-argument gap in bd-9vouw.273.
//! Expected console lines were captured with Node v24.22.3.

use frankenengine_engine::HybridRouter;

fn console_lines(source: &str) -> Vec<String> {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

#[test]
fn data_view_converts_object_arguments_once_before_new_target_prototype() {
    let source = r#"
var events = [];
var offsetCalls = 0;
var lengthCalls = 0;
var offset = { [Symbol.toPrimitive]: function (hint) {
  events.push('offset:' + hint); offsetCalls++; return offsetCalls === 1 ? 2 : 100;
} };
var length = { valueOf: function () {
  events.push('length'); lengthCalls++; return lengthCalls === 1 ? 3 : 100;
} };
var proto = Object.create(DataView.prototype);
var target = Object.defineProperty(function () {}.bind(), 'prototype', {
  get: function () { events.push('prototype'); return proto; }
});
var view = Reflect.construct(DataView, [new ArrayBuffer(8), offset, length], target);
console.log(events.join(','), offsetCalls, lengthCalls, view.byteOffset,
            view.byteLength, Object.getPrototypeOf(view) === proto);
"#;
    assert_eq!(
        console_lines(source),
        ["offset:number,length,prototype 1 1 2 3 true"]
    );
}

#[test]
fn data_view_constructor_preserves_argument_error_precedence() {
    let source = r#"
var events = [];
function index(name, value, error) {
  return { valueOf: function () {
    events.push(name); if (error) throw new EvalError(name); return value;
  } };
}
function attempt(buffer, offset, length) {
  events = [];
  var target = Object.defineProperty(function () {}.bind(), 'prototype', {
    get: function () { events.push('prototype'); throw new SyntaxError('prototype'); }
  });
  var result = 'ok';
  try { Reflect.construct(DataView, [buffer, offset, length], target); }
  catch (error) { result = error.constructor.name; }
  console.log(result + ':' + events.join(','));
}
attempt({}, index('offset', 0, true), index('length', 1, false));
attempt(new ArrayBuffer(8), index('offset', 0, true), index('length', 1, false));
attempt(new ArrayBuffer(8), index('offset', -1, false), index('length', 1, false));
attempt(new ArrayBuffer(8), index('offset', 9, false), index('length', 1, true));
attempt(new ArrayBuffer(8), index('offset', 2, false), index('length', 1, true));
attempt(new ArrayBuffer(8), index('offset', 2, false), index('length', 9, false));
attempt(new ArrayBuffer(8), index('offset', 2, false), index('length', 3, false));
var detachedByOffset = new ArrayBuffer(8);
attempt(detachedByOffset, { valueOf: function () {
  events.push('offset'); detachedByOffset.transfer(); return 0;
} }, index('length', 1, false));
var detachedByLength = new ArrayBuffer(8);
attempt(detachedByLength, index('offset', 0, false), { valueOf: function () {
  events.push('length'); detachedByLength.transfer(); return 1;
} });
"#;
    assert_eq!(
        console_lines(source),
        [
            "TypeError:",
            "EvalError:offset",
            "RangeError:offset",
            "RangeError:offset",
            "EvalError:offset,length",
            "RangeError:offset,length",
            "SyntaxError:offset,length,prototype",
            "TypeError:offset",
            "SyntaxError:offset,length,prototype",
        ]
    );
}

#[test]
fn data_view_rechecks_buffer_changes_after_new_target_prototype() {
    let source = r#"
function attempt(change, offset, length) {
  var buffer = new ArrayBuffer(8, { maxByteLength: 16 });
  var events = [];
  var target = Object.defineProperty(function () {}.bind(), 'prototype', {
    get: function () {
      events.push('prototype');
      if (change === 'detach') buffer.transfer(); else buffer.resize(change);
      return DataView.prototype;
    }
  });
  var args = [buffer, { valueOf: function () { events.push('offset'); return offset; } }];
  if (length !== undefined) args.push({ valueOf: function () { events.push('length'); return length; } });
  var result;
  try {
    var view = Reflect.construct(DataView, args, target);
    result = view.byteOffset + '/' + view.byteLength;
    if (change === 12) { buffer.resize(14); result += '/' + view.byteLength; }
  } catch (error) { result = error.constructor.name; }
  console.log(result + ':' + events.join(','));
}
attempt('detach', 2, 3);
attempt(1, 2, undefined);
attempt(4, 2, 3);
attempt(4, 2, undefined);
attempt(2, 2, undefined);
attempt(12, 2, undefined);
attempt(12, 2, 3);
"#;
    assert_eq!(
        console_lines(source),
        [
            "TypeError:offset,length,prototype",
            "RangeError:offset,prototype",
            "RangeError:offset,length,prototype",
            "2/2:offset,prototype",
            "2/0:offset,prototype",
            "2/10/12:offset,prototype",
            "2/3/3:offset,length,prototype",
        ]
    );
}

#[test]
fn data_view_rechecks_direct_construction_after_length_coercion() {
    let source = r#"
function attempt(change, resultLength) {
  var buffer = new ArrayBuffer(8, { maxByteLength: 16 });
  var calls = 0;
  var result;
  try {
    var view = new DataView(buffer, 2, { valueOf: function () {
      calls++;
      if (change === 'detach') buffer.transfer(); else buffer.resize(change);
      return resultLength;
    } });
    result = 'constructed';
  } catch (error) { result = error.constructor.name; }
  if (result === 'constructed') {
    try { result += ':' + view.byteLength; }
    catch (error) { result += ':' + error.constructor.name; }
  }
  console.log(result, calls);
}
attempt('detach', 3);
attempt(1, 0);
attempt(4, 3);
attempt(4, 2);
attempt(12, 8);
attempt(12, 3);
"#;
    assert_eq!(
        console_lines(source),
        [
            "TypeError 1",
            "RangeError 1",
            "RangeError 1",
            "constructed:2 1",
            "RangeError 1",
            "constructed:3 1",
        ]
    );
}
