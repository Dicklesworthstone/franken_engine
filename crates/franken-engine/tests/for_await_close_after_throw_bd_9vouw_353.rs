//! bd-9vouw.353: after a `for await` body throws, closing the iterator
//! cannot replace the body's exception (AsyncIteratorClose returns a throw
//! completion before the close's own, ES2022). The desugaring read and
//! called `return` in a `finally`, so a throwing `return` getter, a
//! non-callable `return`, a `return()` that throws and one whose promise
//! rejects each replaced the body's error. After `break` the close's error
//! is still the loop's. The line is Node v22.2.0's (Bun 1.4.2 agrees).

use frankenengine_engine::HybridRouter;

#[test]
fn a_throw_from_the_body_survives_the_iterator_close() {
    let source = r#"
var log = [];
function iterable(returnSlot) {
  var it = { next: function () { return { done: false, value: 1 }; } };
  Object.defineProperty(it, 'return', returnSlot);
  var source = {};
  source[Symbol.asyncIterator] = function () { return it; };
  return source;
}
var cases = [
  ['getter', { get: function () { log.push('get'); throw new Error('getter'); } }],
  ['noncallable', { value: true }],
  ['throws', { value: function () { log.push('call'); throw new Error('return-threw'); } }],
  ['rejects', { value: function () { log.push('call'); return Promise.reject(new Error('return-rejected')); } }],
  ['fine', { value: function () { log.push('call'); return {}; } }],
];
async function main() {
  for (var i = 0; i < cases.length; i++) {
    var name = cases[i][0];
    try {
      for await (var x of iterable(cases[i][1])) { throw new Error('body'); }
    } catch (e) { log.push(name + '-throw:' + e.message); }
    try {
      for await (var y of iterable(cases[i][1])) { break; }
      log.push(name + '-break:ok');
    } catch (e) { log.push(name + '-break:' + (e instanceof TypeError ? 'TypeError' : e.message)); }
  }
  console.log(log.join(' '));
}
main();
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "get getter-throw:body get getter-break:getter noncallable-throw:body noncallable-break:TypeError call throws-throw:body call throws-break:return-threw call rejects-throw:body call rejects-break:return-rejected call fine-throw:body call fine-break:ok"
        ]
    );
}
