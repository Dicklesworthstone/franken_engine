//! bd-9vouw.309: on an ordinary Array, a hole stays a hole. slice, concat
//! and splice create no element for it in their result, and splice,
//! reverse, shift and unshift move it by deleting the target index, as the
//! generic path for array-likes and proxies already did. flat skips holes
//! and reads elements with [[Get]], so an accessor element's getter runs.
//! The element-storage paths read every hole as undefined and wrote it, so
//! Object.keys of each result listed every index, flat's result was too
//! long and flat copied an accessor element as an accessor. The last three
//! values check a push after a hole moved: it appends at `length`. Node
//! v22.2.0 gives this value; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn array_methods_keep_holes_as_holes() {
    let source = r#"
function keys(a) { return Object.keys(a).join('.') + '/' + a.length; }
function mk() { return [1, , 3, , 5]; }
var r = [];
var a = mk(); a.splice(0, 1); r.push(keys(a));
a = mk(); a.splice(1, 0, 'x'); r.push(keys(a));
r.push(keys(mk().splice(1, 3)));
a = mk(); a.reverse(); r.push(keys(a));
a = mk(); a.shift(); r.push(keys(a));
a = mk(); a.unshift(0); r.push(keys(a));
r.push(keys([[1, , 3], , [5]].flat()));
r.push(keys(mk().slice(1)));
r.push(keys(mk().concat(mk())));
var g = []; Object.defineProperty(g, 0, { get: function () { return 7; }, enumerable: true, configurable: true }); g.length = 1;
var fd = Object.getOwnPropertyDescriptor([g].flat(), 0); r.push(fd.value + ':' + typeof fd.get);
var h = [1, , 3]; h.shift(); h.push(9); r.push(keys(h) + ':' + h.join(','));
var k = [1, , 3, ,]; k.reverse(); k.push(8); r.push(keys(k) + ':' + k.join(','));
var d = [1, 2, 3]; d.shift(); d.push(4); d.reverse(); d.unshift(0); d.push(5); r.push(keys(d) + ':' + d.join(''));
r.join(' ');
"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "1.3/4 0.1.3.5/6 1/3 0.2.4/5 1.3/4 0.1.3.5/6 0.1.2/3 1.3/4 0.2.4.5.7.9/10 7:undefined \
         1.2/3:,3,9 1.3.4/5:,3,,1,8 0.1.2.3.4/5:04325"
    );
}
