//! bd-9vouw.355: a `v`-flag character class with strings (ES2024 22.2.2
//! ClassSetExpression): `\q{..}` string disjunctions and
//! `\p{Emoji_Keycap_Sequence}` combined by union, `&&` and `--`. `\q{..}`
//! was read as the letter `q` and its contents as class characters, so
//! `[[0-9]--\q{0|2|4|9\uFE0F\u20E3}]` removed `9`; a property of
//! strings inside a class failed to compile ("Invalid property name"). The
//! class's strings now combine as sets and match longest first, then its
//! characters, then the empty string. Lines are Node v22.2.0's.
//!
//! No-claim: the other properties of strings (RGI_Emoji and its parts,
//! Basic_Emoji) inside a class still fail to compile; a negated class with
//! strings (an early error) is not rejected here.

use frankenengine_engine::HybridRouter;

#[test]
fn unicode_sets_class_strings_follow_set_operations() {
    let source = r#"
var K = '9️⃣';
var cases = [
  ['^[[0-9]--\\q{0|2|4|9\\uFE0F\\u20E3}]+$', '9'],
  ['^[[0-9]--\\q{0|2|4|9\\uFE0F\\u20E3}]+$', '0'],
  ['^[\\q{0|2|4|9\\uFE0F\\u20E3}--\\d]+$', K],
  ['^[\\q{0|2|4|9\\uFE0F\\u20E3}--\\d]+$', '2'],
  ['^[\\d--\\p{Emoji_Keycap_Sequence}]+$', '5'],
  ['^[\\p{Emoji_Keycap_Sequence}--\\d]+$', K],
  ['^[\\p{Emoji_Keycap_Sequence}&&\\q{9\\uFE0F\\u20E3}]$', K],
  ['^[\\p{Emoji_Keycap_Sequence}&&\\q{9\\uFE0F\\u20E3}]$', '#️⃣'],
  ['^[_\\p{Emoji_Keycap_Sequence}]+$', '_#️⃣_'],
  ['^[\\q{abc|a|}]$', ''],
  ['^[\\q{abc|a|}]+$', 'abca'],
  ['^[\\q{abc|ab}]$', 'abc'],
  ['^[a-c\\q{xy}]+$', 'bxyc'],
  ['^[[a-z]--[aeiou]]+$', 'bcd'],
];
console.log(cases.map(function (c) { return new RegExp(c[0], 'v').test(c[1]); }).join(','));
console.log('abc9️⃣'.match(/[\q{abc|a}\p{Emoji_Keycap_Sequence}]/gv).join('|'));
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
            "true,false,true,false,true,true,true,false,true,true,true,true,true,true",
            "abc|9️⃣"
        ]
    );
}
