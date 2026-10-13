//! bd-9vouw.350: Promise.all and Promise.allSettled settle their result
//! through the Promise Resolve Function, which reads `then` of the values
//! array (ES2020 25.6.1.3.2): a throwing Array.prototype.then getter rejects
//! the result, and an Array.prototype or Object.prototype `then` function
//! makes the array a thenable. The native combinator fulfilled with the
//! array directly. A `then` removed before an input settles is not read.
//! Node v22.2.0 gives this line; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn combinator_results_read_then_of_the_values_array() {
    let source = r#"
var value = {};
Object.defineProperty(Array.prototype, 'then', { get: function () { throw value; }, configurable: true });
var p1 = Promise.all([]);
var p2 = Promise.allSettled([]);
var p3 = Promise.all([1]);
delete Array.prototype.then;
Array.prototype.then = function (resolve) { resolve('thenable'); };
var p4 = Promise.all([]);
var p5 = Promise.allSettled([]);
delete Array.prototype.then;
var p6 = Promise.all([3]);
Object.prototype.then = function (resolve) { resolve('objthen'); };
var p7 = Promise.all([]);
delete Object.prototype.then;
Promise.allSettled([p1, p2, p3, p4, p5, p6, p7]).then(function (rs) {
  console.log(rs.map(function (r) {
    return r.status[0] + (r.reason === value ? 'V' : JSON.stringify(r.status === 'fulfilled' ? r.value : r.reason));
  }).join(' '));
});
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
        ["rV rV f[1] f\"thenable\" f\"thenable\" f[3] f\"objthen\""]
    );
}
