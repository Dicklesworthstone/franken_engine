#![forbid(unsafe_code)]

//! Array.prototype argument handling that differed from Node: fill with an
//! explicit undefined end fills to the length (it filled nothing; a pass-through
//! optional parameter hits this), toSpliced() with no arguments is a copy (it
//! was []), and a string index argument uses StringToNumber, so "0x0003" is 3
//! (indexOf / lastIndexOf / includes / slice / at and every caller of
//! value_as_integer read it through Rust's float parser as 0). Test262
//! fill/coerced-indexes, toSpliced/start-and-deleteCount-missing,
//! indexOf/15.4.4.14-5-19, lastIndexOf/15.4.4.15-5-19.

use frankenengine_engine::HybridRouter;

/// Expected lines are Node v22.2.0's output, captured programmatically from the
/// same source.
#[test]
fn array_index_arguments_match_node() {
    let source = r#"var target = {};
console.log(JSON.stringify([0, 0].fill(1, 0, undefined)), JSON.stringify([0, 0, 0].fill(2, undefined, undefined)), JSON.stringify([0, 0, 0].fill(3, 1)));
console.log(JSON.stringify([1, 2, 3].toSpliced()), JSON.stringify([1, 2, 3].toSpliced(1)), JSON.stringify([1, 2, 3].toSpliced(undefined, undefined, 9)));
console.log([0, 1, target, 3, 4].indexOf(target, "0x0003"), [0, 1, target, 3].indexOf(target, "0b1"), [1, 2, 1].lastIndexOf(1, "0o1"), [5, 6].indexOf(6, " \n1 "), [5, 6].includes(5, "Infinity"), [1, 2, 3].slice("0x1").join(), [1, 2, 3].at("-0b1"));
"#;
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
            "[1,1] [2,2,2] [0,3,3]",
            "[1,2,3] [1] [9,1,2,3]",
            "-1 2 0 1 false 2,3 1",
        ]
    );
}
