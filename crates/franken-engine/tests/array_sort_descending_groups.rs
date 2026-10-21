//! Native generic Array sort/toSorted coverage for whole descending groups.
//! Literal expectations were independently executed under Node v22.16.0.
//! The algorithm's work/provenance/refusal checks also have both-profile unit tests.

use frankenengine_engine::HybridRouter;

fn check(source: &str, expected: &[&str]) {
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<_> = outcome.console_output.iter()
        .map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, expected);
}

#[test]
fn generic_sort_and_to_sorted_keep_primitive_ties_and_exact_utf16() {
    let source = r#"
var receiver = { length: 1024 };
for (var i = 0; i < receiver.length; i++) {
  var key = 1000 + Math.floor((receiver.length - 1 - i) / 4);
  receiver[i] = i % 2 === 0 ? key : String(key);
}
var copied = Array.prototype.toSorted.call(receiver);
var originalKept = receiver[0] === 1255 && receiver[1023] === '1000';
var returned = Array.prototype.sort.call(receiver);
var stable = true;
for (var i = 0; i < copied.length; i++) {
  var expected = 1000 + Math.floor(i / 4);
  var value = i % 2 === 0 ? expected : String(expected);
  stable = stable && copied[i] === value && receiver[i] === value;
}
console.log(copied.length + '|' + originalKept + '|' + (returned === receiver) + '|' + stable);
var groups = ['\ufffd', '\ue000', '\udc00', '😀', '\ud800', 'é', 'a'];
var exact = { length: groups.length * 65 };
for (var i = 0; i < exact.length; i++) exact[i] = groups[Math.floor(i / 65)];
var sorted = Array.prototype.toSorted.call(exact);
var units = [];
for (var i = 0; i < groups.length; i++) units.push(sorted[i * 65].charCodeAt(0));
console.log(sorted.length + '|' + units.join(',') + '|' + sorted[195].length + '|' + exact[0].charCodeAt(0));
var sparse = { length: 512 };
for (var i = 0; i < 512; i++) {
  if (i < 32) sparse[i] = undefined;
  else if (i % 16 !== 0) sparse[i] = String(1000 + Math.floor((511 - i) / 4));
}
var denseCopy = Array.prototype.toSorted.call(sparse);
Array.prototype.sort.call(sparse);
var presentUndefined = 0, holes = 0, copyUndefined = 0;
for (var i = 0; i < 512; i++) {
  if (!Object.prototype.hasOwnProperty.call(sparse, String(i))) holes++;
  else if (sparse[i] === undefined) presentUndefined++;
  if (denseCopy[i] === undefined) copyUndefined++;
}
console.log(sparse[0] + '|' + presentUndefined + '|' + holes + '|' + copyUndefined + '|' + Object.keys(sparse).length + '|' + Object.keys(denseCopy).length);
"#;
    check(source, &[
        "1024|true|true|true",
        "455|97,233,55296,55357,56320,57344,65533|2|65533",
        "1000|32|30|62|483|512",
    ]);
}

#[test]
fn generic_sort_preserves_proxy_observations_and_late_throwing_values() {
    let source = r#"
var raw = [];
for (var i = 0; i < 512; i++) raw.push(String(1000 + Math.floor((511 - i) / 4)));
var has = 0, get = 0, set = 0, del = 0;
var receiver = new Proxy(raw, {
  has: function (target, key) { has++; return Reflect.has(target, key); },
  get: function (target, key, receiver) { get++; return Reflect.get(target, key, receiver); },
  set: function (target, key, value) { set++; return Reflect.set(target, key, value); },
  deleteProperty: function (target, key) { del++; return Reflect.deleteProperty(target, key); }
});
var returned = Array.prototype.sort.call(receiver);
console.log((returned === receiver) + '|' + has + '|' + get + '|' + set + '|' + del + '|' + raw[0] + '|' + raw[511]);
var token = {}, conversions = 0;
var late = { length: 300 };
for (var i = 0; i < 299; i++) late[i] = String(1000 + Math.floor((299 - i) / 3));
late[299] = { toString: function () { conversions++; throw token; } };
var original = late[0], caught = false;
try { Array.prototype.sort.call(late); } catch (error) { caught = error === token; }
console.log(caught + '|' + (conversions > 0) + '|' + (late[0] === original));
var symbols = { length: 300 };
for (var i = 0; i < 299; i++) symbols[i] = 'same';
symbols[299] = Symbol('late');
var refused = false;
try { Array.prototype.sort.call(symbols); } catch (error) { refused = error instanceof TypeError; }
console.log(refused + '|' + (typeof symbols[299] === 'symbol'));
"#;
    check(source, &[
        "true|512|513|512|0|1000|1127",
        "true|true|true",
        "true|true",
    ]);
}
