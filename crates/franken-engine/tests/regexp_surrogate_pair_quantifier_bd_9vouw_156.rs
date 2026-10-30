//! bd-9vouw.156 / bd-9vouw.458: without `u`/`v`, a RegExp consumes UTF-16
//! code units, including individual halves of a supplementary character.
//! A quantifier after a surrogate pair repeats only its low half. Both
//! native matchers must preserve this through captures, indices, callbacks,
//! replacement templates, split, and the legacy RegExp statics.
//! The .458 expected results were checked against Node v24.22.1.

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

/// A literal astral character (a surrogate pair in the source) quantified on its low half; the backreference forces the backtracking matcher.
#[test]
fn surrogate_pair_quantifier_literal_astral_character() {
    let source = "var smile = String.fromCodePoint(0x1F600);\n\
         [/^😀?$/.test(''), /^😀?$/.test(smile), /^😀+$/.test(smile), /^😀{2}$/.test(smile + smile),\n\
          JSON.stringify(('a' + smile).match(/😀?/g)), /^(a)😀?\\1$/.test('aa'), /^(a)😀?\\1$/.test('a' + smile + 'a'),\n\
          /^😀?$/u.test('')].join(' ');";
    assert_eq!(
        eval(source),
        "false true true false [\"😀\"] false true true"
    );
}

/// html-entities' nonAsciiPrintable replacer.
#[test]
fn surrogate_pair_quantifier_html_entities_encode_shape() {
    let source = "var re = /[<>'\"&\\x01-\\x08\\x11-\\x15\\x17-\\x1F\\x7f-\\uD7FF\\uE000-\\uFFFF\\uDC00-\\uDFFF]|[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]?/g;\n\
         var s = '<a>' + String.fromCharCode(233) + String.fromCodePoint(0x1F600);\n\
         [s.replace(re, function (c) { var code = c.length > 1 ? c.codePointAt(0) : c.charCodeAt(0); return '&#' + code + ';'; })].join(' ');";
    assert_eq!(eval(source), "&#60;a&#62;&#233;&#128512;");
}

#[test]
fn non_unicode_regexps_match_utf16_units_bd_9vouw_458() {
    let source = r#"
const s = String.fromCodePoint(0x1F600);
[s.replace(/./g, 'x'), s.match(/./g).length, /^..$/.test(s),
 /^.$/.test(s), /^.$/u.test(s), ('a' + s + 'b').split(/(?:)/).length,
 /[😀]/.test(String.fromCharCode(0xD83D)), /\uD83D/.test(s),
 s.search(/\uDE00/), /^[^x]$/.test(s)].join(' ');
"#;
    assert_eq!(eval(source), "xx 2 true false true 4 true true 1 false");
}

#[test]
fn exec_can_start_between_surrogate_halves_bd_9vouw_458() {
    let source = r#"
const s = 'a' + String.fromCodePoint(0x1F600) + 'b';
const re = /./gd;
re.lastIndex = 2;
const m = re.exec(s);
const empty = /(?:)/g;
empty.lastIndex = 2;
const e = empty.exec(s);
[m.index, m[0].charCodeAt(0), m[0].length, re.lastIndex,
 m.indices[0].join(','), e.index, empty.lastIndex,
 [...s.matchAll(/(?:)/g)].map(x => x.index).join(',')].join(' ');
"#;
    assert_eq!(eval(source), "2 56832 1 3 2,3 2 2 0,1,2,3,4");
}

#[test]
fn non_unicode_backtracking_keeps_exact_halves_bd_9vouw_458() {
    let source = r#"
const s = String.fromCodePoint(0x1F600);
const m = /(?<high>.)(?<low>.)(?=a)/d.exec(s + 'a');
[m[0].length, m.groups.high.charCodeAt(0), m.groups.low.charCodeAt(0),
 m.indices.groups.low.join(','), /^(.)\1$/.test(s),
 /^(..)(?:\1)$/.test(s + s), /(?<=\uD83D)\uDE00/.exec(s).index,
 /^(.)(?=\uDE00)\uDE00$/.test(s)].join(' ');
"#;
    assert_eq!(eval(source), "2 55357 56832 1,2 false true 1 true");
}

#[test]
fn quantified_low_halves_are_independent_atoms_bd_9vouw_458() {
    let source = r#"
const s = String.fromCodePoint(0x1F600);
const low = String.fromCharCode(0xDE00);
[s.match(/😀??/)[0].length, s.match(/\uD83D\uDE00{0}/)[0].charCodeAt(0),
 /^\uD83D\uDE00{2}$/.test(s + low), /^😀+$/.test(s + low),
 /^😀+$/u.test(s + s), /^😀+$/u.test(s + low)].join(' ');
"#;
    assert_eq!(eval(source), "1 55357 true true true false");
}

#[test]
fn replacements_and_split_preserve_lone_surrogates_bd_9vouw_458() {
    let source = r#"
const s = String.fromCodePoint(0x1F600);
const swapped = s.replace(/(.)(.)/, '$2$1');
const positions = [];
const replaced = s.replace(/./g, (match, offset, input) => {
    positions.push(offset + ':' + match.charCodeAt(0) + ':' + (input === s));
    return match;
});
const split = s.split(/(?:)/);
[swapped.charCodeAt(0), swapped.charCodeAt(1), replaced === s,
 positions.join(','), split[0].charCodeAt(0), split[1].charCodeAt(0),
 s.replace(/./gu, 'u')].join(' ');
"#;
    assert_eq!(
        eval(source),
        "56832 55357 true 0:55357:true,1:56832:true 55357 56832 u"
    );
}

#[test]
fn lone_surrogates_and_private_use_text_do_not_alias_bd_9vouw_458() {
    let source = r#"
const high = String.fromCharCode(0xD83D), low = String.fromCharCode(0xDE00);
const privateUse = String.fromCodePoint(0xF003D);
[ /\uD83D/.test(high), /\uDE00/.test(low), /\uD83D/.test(low),
 /\uD83D/.test(privateUse), /😀/.test(high + low),
 high.match(/./)[0].charCodeAt(0), privateUse.match(/./g).length,
 /^[\uD7FF-\uE000]$/.test(high), /[^\uD800-\uDFFF]/.test(high)].join(' ');
"#;
    assert_eq!(
        eval(source),
        "true true false false true 55357 2 true false"
    );
}

#[test]
fn legacy_regexp_captures_keep_utf16_units_bd_9vouw_458() {
    let source = r#"
const s = 'a' + String.fromCodePoint(0x1F600) + 'b';
/(\uDE00)/.exec(s);
[RegExp.$1.charCodeAt(0), RegExp.lastMatch.length,
 RegExp.leftContext.length, RegExp.leftContext.charCodeAt(1),
 RegExp.rightContext, RegExp.input === s].join(' ');
"#;
    assert_eq!(eval(source), "56832 1 2 55357 b true");
}

#[test]
fn capture_names_and_identity_escapes_keep_their_roles_bd_9vouw_458() {
    let source = r#"
const s = String.fromCodePoint(0x1F600);
const named = /(?<𝒜>.)(?<low>.)/;
const swapped = s.replace(named, '$<low>$<𝒜>');
let callbackKey = false;
s.replace(named, (whole, high, low, index, input, groups) => {
    callbackKey = groups['𝒜'] === high && groups.low === low;
    return whole;
});
[swapped.charCodeAt(0), swapped.charCodeAt(1), callbackKey,
 /\😀??/.exec(s)[0].length, /[\😀]/.exec(s)[0].length,
 /^(?<𝒜>.)\k<𝒜>$/.test(s),
 /^(?<𝒜>..)\k<𝒜>$/.test(s + s)].join(' ');
"#;
    assert_eq!(eval(source), "56832 55357 true 1 1 false true");
}

#[test]
fn replacement_limits_count_decoded_text_bd_9vouw_458() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{
        InterpreterConfig, InterpreterCore, InterpreterError, Value,
    };
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};

    for (source, fits) in [
        (
            "const s = '😀'.repeat(16); s.replace(/(.)/g, '$1') === s",
            true,
        ),
        (
            "const s = '😀'.repeat(16); s.replace(/\\uDE00/g, '$&') === s",
            true,
        ),
        (
            "const s = '😀'.repeat(16); s.replace(/./g, m => m) === s",
            true,
        ),
        ("const s = '😀'.repeat(16); s.replace(/./g, '$&x')", false),
        ("const s = '😀'.repeat(16); s.replace(/./g, \"$'\")", false),
    ] {
        let tree = CanonicalEs2020Parser
            .parse_with_options(source, ParseGoal::Script, &ParserOptions::default())
            .expect("replacement limit source parses");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "regexp-output-limit.js"),
            &LoweringContext::new("regexp-output-limit", "decision", "policy"),
        )
        .expect("replacement limit source lowers")
        .ir3;
        for mut config in [
            InterpreterConfig::quickjs_defaults(),
            InterpreterConfig::v8_defaults(),
        ] {
            config.max_string_size = 64;
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
            ]
            .into_iter()
            .collect();
            let result = InterpreterCore::new(config, "regexp-output-limit").execute(&module);
            if fits {
                assert_eq!(
                    result
                        .unwrap_or_else(|error| panic!("{source}: {error}"))
                        .value,
                    Value::Bool(true)
                );
            } else {
                assert!(
                    matches!(result, Err(InterpreterError::StringLimitExceeded { .. })),
                    "{source}: {result:?}"
                );
            }
        }
    }
}
