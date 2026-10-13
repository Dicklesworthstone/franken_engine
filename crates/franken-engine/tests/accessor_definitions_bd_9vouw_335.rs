//! bd-9vouw.335: an accessor definition on an ordinary key charges its own
//! entry's change instead of estimating the whole property map before and
//! after (O(N^2) for N accessors on one object). The program defines 600
//! accessors on a class prototype, accessors over existing data properties
//! and a getter then its setter in an object literal (including a non-ASCII
//! key), and 200 getters through Object.defineProperty, and reads them back.
//! Debug builds assert, at every definition, that the entry's delta equals
//! the whole-map difference. Node v22.2.0 gives this line; Bun 1.4.2 and the
//! land41 gate binary agree.

use frankenengine_engine::HybridRouter;

#[test]
fn many_accessors_define_and_read_back() {
    let source = r#"
var out = [];
var body = '';
for (var i = 0; i < 300; i++) body += 'get g' + i + '() { return ' + i + '; } set g' + i + '(v) { this.s = v + ' + i + '; } ';
var C = Function('return class C { ' + body + ' };')();
var c = new C();
c.g7 = 1;
out.push(c.g299, c.s, Object.getOwnPropertyNames(C.prototype).length);
var o = { a: 1, get a() { return 2; }, b: 3, set b(v) { this.bb = v; }, get b() { return 4; }, 'é': 5, get 'é'() { return 6; } };
o.b = 9;
out.push(o.a, o.b, o.bb, o['é'], Object.keys(o).join(','));
var p = {};
for (var j = 0; j < 200; j++) (function (k) { Object.defineProperty(p, 'p' + k, { enumerable: true, get: function () { return k * 2; } }); })(j);
out.push(p.p199, Object.keys(p).length);
console.log(out.join(' '));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(lines, ["299 8 301 2 4 9 6 a,b,\u{e9},bb 398 200"]);
}
