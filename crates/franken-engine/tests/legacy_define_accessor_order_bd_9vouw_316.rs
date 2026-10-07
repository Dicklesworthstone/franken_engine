//! bd-9vouw.316: `__defineGetter__` and `__defineSetter__` reject a
//! non-callable function with a TypeError before ToPropertyKey runs the
//! key's toString (Annex B.2.2.2-3 step 2 before step 4). The key was
//! converted first: ten rejected calls ran it ten times. A callable getter
//! and setter still define the accessors, and the key converts once. Node
//! v22.2.0 gives this value; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn legacy_define_accessor_checks_the_function_before_the_key() {
    let source = r#"
var out = [];
var subject = {};
var count = 0;
var key = { toString: function () { count += 1; return 'k'; } };
[ '', 23, true, Symbol(''), {} ].forEach(function (bad) {
  try { subject.__defineGetter__(key, bad); out.push('no'); } catch (e) { out.push(e.constructor.name); }
  try { subject.__defineSetter__(key, bad); out.push('no'); } catch (e) { out.push(e.constructor.name); }
});
out.push(count);
subject.__defineGetter__(key, function () { return 7; });
subject.__defineSetter__('s', function (v) { this.seen = v; });
subject.s = 5;
out.push(count, subject.k, subject.seen, typeof subject.__lookupGetter__('k'));
out.join(' ');
"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "TypeError TypeError TypeError TypeError TypeError TypeError TypeError TypeError TypeError TypeError 0 1 7 5 function"
    );
}
