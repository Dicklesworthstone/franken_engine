//! bd-9vouw.156: without the `u` flag a quantifier written after a
//! surrogate pair's low half repeats that code unit only. The engine matches
//! a pair as the one character it encodes, so the quantifier applied to the
//! whole character: html-entities' `[\uD800-\uDBFF][\uDC00-\uDFFF]?`
//! matched the empty string at every position. Such a pair now matches the
//! character once, or never when the quantifier demands two or more low
//! halves (a well-formed string has no low surrogate after a pair's low
//! half). Expected strings are Node v22.2.0's output for the same programs.
//!
//! No-claim: a surrogate half is still matched as the whole character
//! (regexp_syntax's known difference), so where JavaScript matches the high
//! half alone (a lazy `??` or `{0}` on the low half, or a lone `\uD83D`) the
//! match here is the character, not half of it.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// The idiom with `?` matches a supplementary character once and nothing in BMP text.
#[test]
fn surrogate_pair_quantifier_idiom_with_optional_low_half() {
    let source = "var re = /[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]?/g;\n\
         var smile = String.fromCodePoint(0x1F600);\n\
         [JSON.stringify(('a' + String.fromCharCode(233) + 'b').match(re)), JSON.stringify(('x' + smile + 'y').match(re)),\n\
          ('x' + smile + 'y').replace(re, '<$&>').length, /^[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]?$/.test(smile), /^[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]?$/.test('')].join(' ');";
    assert_eq!(eval(source), "null [\"😀\"] 6 true false");
}

/// `*`, `+` and braces on the low half.
#[test]
fn surrogate_pair_quantifier_every_quantifier_on_the_idiom() {
    let source = "var smile = String.fromCodePoint(0x1F600), s = 'a' + smile + 'b' + smile + smile;\n\
         function count(re) { var m = s.match(re); return m ? m.length + ':' + m.map(x => x.length).join('') : 'null'; }\n\
         [count(/[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]*/g), count(/[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]+/g), count(/[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]{1}/g),\n\
          count(/[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]{0,3}/g), count(/[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]{1,}?/g), count(/[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]{2}/g)].join(' ');";
    assert_eq!(eval(source), "3:222 3:222 3:222 3:222 3:222 null");
}

/// A pair of escapes, and a high escape followed by a class of lows, quantified on the low half.
#[test]
fn surrogate_pair_quantifier_pair_escape_and_low_class() {
    let source = "var smile = String.fromCodePoint(0x1F600), tone = String.fromCodePoint(0x1F3FC);\n\
         [JSON.stringify(('a' + smile).match(/\\uD83D\\uDE00?/g)), JSON.stringify(('a' + tone).match(/\\uD83C[\\uDFFB-\\uDFFF]?/g)),\n\
          /^\\uD83D\\uDE00+$/.test(smile), /^\\uD83D\\uDE00*$/.test(''), /^(?:\\uD83D\\uDE00)?$/.test(''),\n\
          /^\\uD83C[\\uDFFB-\\uDFFF]{2}$/.test(tone), /\\uD83D\\uDE00?/u.test('a')].join(' ');";
    assert_eq!(eval(source), "[\"😀\"] [\"🏼\"] true false true false true");
}

/// html-entities' nonAsciiPrintable replacer.
#[test]
fn surrogate_pair_quantifier_html_entities_encode_shape() {
    let source = "var re = /[<>'\"&\\x01-\\x08\\x11-\\x15\\x17-\\x1F\\x7f-\\uD7FF\\uE000-\\uFFFF\\uDC00-\\uDFFF]|[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]?/g;\n\
         var s = '<a>' + String.fromCharCode(233) + String.fromCodePoint(0x1F600);\n\
         [s.replace(re, function (c) { var code = c.length > 1 ? c.codePointAt(0) : c.charCodeAt(0); return '&#' + code + ';'; })].join(' ');";
    assert_eq!(eval(source), "&#60;a&#62;&#233;&#128512;");
}
