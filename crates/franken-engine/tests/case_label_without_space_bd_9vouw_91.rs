//! bd-9vouw.91: `case"x":` (no space between `case` and the test) was not a
//! case label, so the switch ran neither that case nor `default`: silent
//! wrong output. Minifiers drop the space before a string, template,
//! parenthesis or sign; dayjs.min.js's format() switch (`case"YY":...`)
//! formatted 'YYYY-MM-DD' as "+0000-+0000-+0000". The same clause scanner
//! also split `o.default` into a label and ended a case test at a `:` inside
//! a string. Expected values are what Node v22.2.0 gives for the same
//! programs (completion value, or the logged value of the same expression).

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

#[test]
fn case_labels_without_a_space_before_the_test() {
    for (source, node) in [
        (
            r#"var t="b",o=[];switch(t){case"a":o.push(1);break;case"b":o.push(2);break;default:o.push(3)}o.join();"#,
            "2",
        ),
        (
            "var t='a',r=0;switch(t){case'a':r=1;break;case'b':r=2}r;",
            "1",
        ),
        ("var r=0;switch(2){case(1+1):r=5;break;default:r=9}r;", "5"),
        ("var r=0;switch(-1){case-1:r=7;break;default:r=9}r;", "7"),
        ("var r=0;switch('t'){case`t`:r=8;break;default:r=9}r;", "8"),
        (
            r#"var r=0;switch("z"){case"a":r=1;break;default:r=3}r;"#,
            "3",
        ),
        (
            r#"function f(t){switch(t){case"YY":return"yy";case"YYYY":return"yyyy";default:return"-"}} [f("YY"),f("YYYY"),f("Q")].join();"#,
            "yy,yyyy,-",
        ),
    ] {
        assert_eq!(eval_to_string(source), node, "{source}");
    }
}

#[test]
fn an_identifier_starting_with_case_is_still_an_identifier() {
    assert_eq!(
        eval_to_string("var caseA=5,r=0;switch(5){case caseA:r=1;break;default:r=2}r;"),
        "1"
    );
}

/// `.default` and `.case` after a dot are property names, not clause labels:
/// the clause splitter cut `r=o.default;` at `default` ("unsupported
/// expression syntax: o."), which broke every bundled
/// `case 0: return e.default(...)` (Babel's ES-module interop).
#[test]
fn default_and_case_after_a_dot_are_property_names() {
    for (source, node) in [
        (
            "var o={default:3},r=0;switch(1){case 1:r=o.default;break}r;",
            "3",
        ),
        (
            "var o={default:3},r=0;switch(1){case 1:r=o.default+1;break;default:r=9}r;",
            "4",
        ),
        (
            "var e={default:function(){return 5}},r=0;switch(0){case 0:r=e.default();break;default:r=9}r;",
            "5",
        ),
        (
            "var o={case:4},r=0;switch(1){case 1:r=o.case;break;default:r=9}r;",
            "4",
        ),
    ] {
        assert_eq!(eval_to_string(source), node, "{source}");
    }
}

/// The case test ends at its own `:`, not at a `:` inside a string or a
/// conditional expression.
#[test]
fn a_case_test_may_hold_a_colon_in_a_string_or_a_conditional() {
    for (source, node) in [
        (
            r#"var r=0;switch("http:"){case "http:":r=1;break;default:r=2}r;"#,
            "1",
        ),
        (
            r#"var r=0;switch("http:"){case"http:":r=1;break;default:r=2}r;"#,
            "1",
        ),
        (
            "var a=1,r=0;switch(2){case a?2:3:r=1;break;default:r=2}r;",
            "1",
        ),
    ] {
        assert_eq!(eval_to_string(source), node, "{source}");
    }
}
