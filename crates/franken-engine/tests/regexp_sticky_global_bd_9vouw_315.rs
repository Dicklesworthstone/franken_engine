//! bd-9vouw.315: a sticky pattern matches only at lastIndex. A global
//! sticky @@match or @@replace stops at the first exec that fails (the
//! matches are contiguous from 0), and @@search with a sticky pattern finds
//! only a match at 0. The global paths collected every leftmost match, and
//! search ignored the flag. Split, exec, matchAll and an empty-matching
//! sticky replace already agreed and are pinned alongside. Node v22.2.0
//! gives this value; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn sticky_patterns_stop_at_the_first_failed_exec() {
    let source = r#"
var out = [];
out.push(JSON.stringify('aaba'.match(/a/yg)));
var r = /a/gy; out.push(JSON.stringify(r[Symbol.match]('aaba')), r.lastIndex);
out.push('ba'.search(/a/y), /a/y[Symbol.search]('ba'), 'ab'.search(/a/y));
out.push(JSON.stringify('aaba'.replace(/a/gy, 'X')), JSON.stringify('aaba'.replace(/a/g, 'X')));
out.push(JSON.stringify('xxyx'.replace(/x/gy, function (m, i) { return '[' + i + ']'; })));
out.push(JSON.stringify(' a b'.replace(/ ?/gy, '_')));
out.push(JSON.stringify('a,b,c'.split(/,/y)));
var re = /\d+/y; re.lastIndex = 2; out.push(JSON.stringify(re.exec('ab12cd')), re.lastIndex);
out.push(JSON.stringify([...'a1b22'.matchAll(/\d/gy)].map(function (m) { return m[0]; })));
out.join(' ');
"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        r#"["a","a"] ["a","a"] 0 -1 -1 0 "XXba" "XXbX" "[0][1]yx" "__a__b_" ["a","b","c"] ["12"] 4 []"#
    );
}
