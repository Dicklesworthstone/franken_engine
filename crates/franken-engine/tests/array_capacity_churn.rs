//! Array storage resizing must preserve public values, holes, identities and
//! descriptor failures. Capacity-change complexity is tested in the shared
//! core carrier; these fixtures exercise the production parser and interpreter.

use frankenengine_engine::HybridRouter;

#[test]
fn repeated_append_and_double_pop_preserves_dense_and_holey_arrays() {
    let source = r#"
function run(holey) {
  var marker = { kind: 'owned' };
  var a = [];
  for (var i = 0; i < 512; i++) a.push(i);
  a[0] = marker;
  a[1] = undefined;
  a[2] = '\ud800';
  if (holey) delete a[3];
  var identity = true;
  var sum = 0;
  for (var top = 512; top > 256; top--) {
    a.push(marker);
    identity = identity && a.pop() === marker;
    sum += a.pop();
  }
  var restored = JSON.parse(JSON.stringify(a));
  console.log([holey, a.length, Object.keys(a).length, identity,
    a[0] === marker, 1 in a, 3 in a, a[2].charCodeAt(0),
    restored[1] === null, restored[3], sum, a[255]].join('|'));
  Object.freeze(a);
  var refused = false;
  try { a.pop(); } catch (e) { refused = e instanceof TypeError; }
  console.log([refused, a.length, a[255], a[0] === marker].join('|'));
}
run(false);
run(true);
"#;
    let outcome = HybridRouter::default().eval(source).unwrap();
    let lines: Vec<_> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "false|256|256|true|true|true|true|55296|true|3|98176|255",
            "true|256|255|true",
            "true|256|255|true|true|true|false|55296|true||98176|255",
            "true|256|255|true"
        ]
    );
}

#[test]
fn tail_churn_keeps_inherited_getters_and_locked_length_observable() {
    let source = r#"
var a = [];
for (var i = 0; i < 128; i++) a.push(i);
var trace = [];
var proto = Object.create(Array.prototype);
Object.defineProperty(proto, '63', {
  get: function () { trace.push('get63'); return 'inherited'; },
  configurable: true
});
Object.setPrototypeOf(a, proto);
delete a[63];
for (var top = 128; top > 64; top--) {
  a.push('temporary');
  a.pop();
  a.pop();
}
console.log([a.length, 63 in a, Object.prototype.hasOwnProperty.call(a, '63'),
  a.pop(), a.length, trace.join(',')].join('|'));
var refused = false;
try { a.push(undefined); } catch (e) { refused = e instanceof TypeError; }
console.log([refused, a.length, Object.prototype.hasOwnProperty.call(a, '63')].join('|'));
delete proto[63];
Object.defineProperty(a, 'length', { writable: false });
var locked = false;
try { a.push(1); } catch (e) { locked = e instanceof TypeError; }
console.log([locked, a.length, a[62]].join('|'));
"#;
    let outcome = HybridRouter::default().eval(source).unwrap();
    let lines: Vec<_> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "64|true|false|inherited|63|get63",
            "true|63|false",
            "true|63|62"
        ]
    );
}
