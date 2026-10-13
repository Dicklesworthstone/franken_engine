//! bd-9vouw.407: every WhiteSpace and LineTerminator code point of ES2020
//! 11.2/11.3 may separate tokens, U+FEFF (ZERO WIDTH NO-BREAK SPACE)
//! included. The engine's trimming did not treat U+FEFF as white space, so
//! an assignment with it around the `=` was "assignment requires a target
//! and a value". Each case compiles and runs the assignment through
//! Function(). The lines are Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn every_white_space_code_point_separates_tokens() {
    let source = r#"
var cases=["var x; x\t=\t1;", "var x; x\u000b=\u000b1;", "var x; x\f=\f1;", "var x; x = 1;", "var x; x\u00a0=\u00a01;", "var x; x\ufeff=\ufeff1;", "var x; x\u1680=\u16801;", "var x; x\u2000=\u20001;", "var x; x\u2009=\u20091;", "var x; x\u200a=\u200a1;", "var x; x\u2028=\u20281;", "var x; x\u2029=\u20291;", "var x; x\u202f=\u202f1;", "var x; x\u205f=\u205f1;", "var x; x\u3000=\u30001;"];var names=["U+0009", "U+000B", "U+000C", "U+0020", "U+00A0", "U+FEFF", "U+1680", "U+2000", "U+2009", "U+200A", "U+2028", "U+2029", "U+202F", "U+205F", "U+3000"];
console.log(cases.map(function(s,i){try{Function(s)();return names[i]+':ok'}catch(e){return names[i]+':'+e.name}}).join(' '));
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
            "U+0009:ok U+000B:ok U+000C:ok U+0020:ok U+00A0:ok U+FEFF:ok U+1680:ok U+2000:ok U+2009:ok U+200A:ok U+2028:ok U+2029:ok U+202F:ok U+205F:ok U+3000:ok",
        ]
    );
}
