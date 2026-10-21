//! Public runtime methods must retain exact UTF-16 indices and coercion order.
//! Literal outputs are checked separately against Node; Rust execution is a
//! distinct validation step, never inferred from the reference run.

use frankenengine_engine::HybridRouter;

fn check(source: &str, expected: &[&str]) {
    let outcome = HybridRouter::default().eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<_> = outcome.console_output.iter()
        .map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, expected);
}

#[test]
fn flat_unicode_searches_handle_near_tail_offsets_and_surrogate_halves() {
    let source = r#"
var text = 'é中😀a'.repeat(1024) + 'ENDé😀';
var n = text.length;
var out = [];
var positions = [0, 1, n - 7, n - 3, n - 2, n - 1, n, Infinity];
for (var i = 0; i < positions.length; i++) {
  out.push(text.indexOf('é😀', positions[i]) + ':' + text.lastIndexOf('é😀', positions[i]));
}
console.log(n + '|' + out.join(','));
var s = 'a😀é😀z';
var rows = [];
for (var i = 0; i <= s.length + 1; i++) rows.push(s.indexOf('😀', i) + ':' + s.lastIndexOf('😀', i));
console.log(rows.join(','));
console.log(s.indexOf('\ude00', 0) + ':' + s.lastIndexOf('\ud83d', Infinity) + ':' + s.indexOf('', Infinity) + ':' + s.lastIndexOf('', Infinity));
var exact = '\ud800é\ud800\ufffd';
console.log(exact.indexOf('\ud800', 1) + ':' + exact.lastIndexOf('\ud800', 1) + ':' + exact.indexOf('\ufffd') + ':' + exact.indexOf('\udc00'));
var middle = '😀' + '中'.repeat(1024) + 'é';
console.log(middle.indexOf('中中', 513) + ':' + middle.lastIndexOf('中中', 513) + ':' + middle.lastIndexOf('é', Infinity));
"#;
    check(source, &[
        "5126|5123:-1,5123:-1,5123:-1,5123:5123,-1:5123,-1:5123,-1:5123,-1:5123",
        "1:-1,1:1,4:1,4:1,4:4,-1:4,-1:4,-1:4,-1:4",
        "2:4:7:7",
        "2:0:3:-1",
        "513:513:1026",
    ]);
}

#[test]
fn searches_preserve_observable_conversion_order_and_original_throws() {
    let source = r#"
var trace = [];
var target = { toString: function () { trace.push('T'); return 'é😀é😀'; } };
var needle = { toString: function () { trace.push('N'); return '😀'; } };
var offset = { valueOf: function () { trace.push('P'); return 2; } };
var a = String.prototype.indexOf.call(target, needle, offset);
var b = String.prototype.lastIndexOf.call(target, needle, offset);
console.log(a + ':' + b + ':' + trace.join(''));
var token = {}, caught = false;
trace = [];
var throwing = { toString: function () { trace.push('N'); throw token; } };
try { String.prototype.indexOf.call(target, throwing, offset); } catch (error) { caught = error === token; }
console.log(caught + ':' + trace.join(''));
var pairs = ['a😀a😀', 'ééé', '中a中a', '\ud800a\ud800', ''];
var results = [];
for (var i = 0; i < pairs.length; i++) {
  results.push(pairs[i].indexOf('', -Infinity) + ':' + pairs[i].lastIndexOf('', NaN));
}
console.log(results.join(','));
"#;
    check(source, &[
        "4:1:TNPTNP",
        "true:TN",
        "0:6,0:3,0:4,0:3,0:0",
    ]);
}

#[test]
fn fixed_width_unicode_searches_keep_bounded_reverse_and_overlap_results() {
    let source = r#"
var text = JSON.parse(JSON.stringify('中'.repeat(1024) + '語' + '日'.repeat(1024) + '語' + '文'.repeat(1024)));
var rows = [];
var positions = [0, 1023, 1024, 1025, 2048, 2049, 2050, Infinity];
for (var i = 0; i < positions.length; i++) {
  rows.push(text.indexOf('語', positions[i]) + ':' + text.lastIndexOf('語', positions[i]));
}
console.log(text.length + '|' + rows.join(','));
console.log(text.indexOf('語日') + ':' + text.lastIndexOf('日語') + ':' + text.indexOf('文文', 3072) + ':' + text.lastIndexOf('文文', 3073));
var mixed = ['a中a中', 'é😀é😀', '中😀中', '中\ud800中'];
var out = [];
for (var i = 0; i < mixed.length; i++) {
  out.push(mixed[i].indexOf('中', 1) + ':' + mixed[i].lastIndexOf('中', Infinity));
}
console.log(out.join(','));
"#;
    check(source, &[
        "3074|1024:-1,1024:-1,1024:1024,2049:1024,2049:1024,2049:2049,-1:2049,-1:2049",
        "1024:2048:3072:3072",
        "1:3,-1:-1,3:3,2:2",
    ]);
}
