#![forbid(unsafe_code)]

//! bd-9vouw.247: Intl.Segmenter (ECMA-402 18) was not defined, and
//! `/\p{RGI_Emoji}/v` was rejected at parse time ("Invalid property
//! name"). string-width 8.3 uses both when it loads, so it failed (npm
//! wave 10's string_width probe).
//!
//! PROGRAM checks:
//! - grapheme segmentation: emoji modifiers, flags, combining marks, CRLF;
//! - word segmentation with isWordLike, and sentence segmentation;
//! - containing() inside, at the end, past the end, negative, missing and
//!   string indices;
//! - resolvedOptions, the constructor's length and toStringTag;
//! - a RangeError for an unknown granularity;
//! - string-width's own test of each grapheme with `/^\p{RGI_Emoji}$/v`;
//! - a global `\p{RGI_Emoji}` replace, and empty input.
//!
//! Expected lines are Node v22.2.0's output, captured programmatically.
//!
//! No-claim: UAX #29 without locale tailoring. Word segmentation of
//! Han/Kana/Thai/Lao/Khmer/Myanmar text is refused (ICU uses dictionaries).
//! RGI_Emoji accepts any regional-indicator pair and any ZWJ sequence of
//! emoji elements.

use frankenengine_engine::HybridRouter;

#[test]
fn intl_segmenter_and_rgi_emoji_match_node_bd_9vouw_247() {
    let source = r#"const seg = new Intl.Segmenter();
console.log([...seg.segment('a\u{1F44D}\u{1F3FD}b\u{1F1FA}\u{1F1F8} é\r\n')].map((s) => JSON.stringify(s.segment) + '@' + s.index).join(' '));
const words = new Intl.Segmenter('en', { granularity: 'word' });
console.log([...words.segment("Hello, world! It's 3.14 now.")].map((s) => JSON.stringify(s.segment) + (s.isWordLike ? '*' : '')).join(' '));
const sentences = new Intl.Segmenter('en', { granularity: 'sentence' });
console.log([...sentences.segment('One. Two? Three!')].map((s) => JSON.stringify(s.segment)).join(' '));
const s = seg.segment('xy\u{1F44D}\u{1F3FD}');
console.log(JSON.stringify(s.containing(2)), JSON.stringify(s.containing(5)), s.containing(6), s.containing(-1), JSON.stringify(s.containing()), JSON.stringify(s.containing('1')));
console.log(JSON.stringify(seg.resolvedOptions()), JSON.stringify(words.resolvedOptions()), typeof Intl.Segmenter, Intl.Segmenter.length, Object.prototype.toString.call(seg));
try { new Intl.Segmenter('en', { granularity: 'line' }); } catch (e) { console.log(e.constructor.name); }
const rgi = /^\p{RGI_Emoji}$/v;
console.log([...seg.segment('a\u{1F44D}\u{1F3FD}©️1️⃣\u{1F1FA}\u{1F1F8}x©')].map((x) => (rgi.test(x.segment) ? 2 : 1)).join(''));
console.log('a\u{1F44D}\u{1F3FD}b\u{1F600}'.replace(/\p{RGI_Emoji}/gv, '[E]'), [...words.segment('')].length, [...seg.segment('')].length);"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            r#""a"@0 "👍🏽"@1 "b"@5 "🇺🇸"@6 " "@10 "é"@11 "\r\n"@13"#,
            r#""Hello"* "," " " "world"* "!" " " "It's"* " " "3.14"* " " "now"* ".""#,
            r#""One. " "Two? " "Three!""#,
            r#"{"segment":"👍🏽","index":2,"input":"xy👍🏽"} {"segment":"👍🏽","index":2,"input":"xy👍🏽"} undefined undefined {"segment":"x","index":0,"input":"xy👍🏽"} {"segment":"y","index":1,"input":"xy👍🏽"}"#,
            r#"{"locale":"en-US","granularity":"grapheme"} {"locale":"en","granularity":"word"} function 0 [object Intl.Segmenter]"#,
            r#"RangeError"#,
            r#"1222211"#,
            r#"a[E]b[E] 0 0"#,
        ]
    );
}
