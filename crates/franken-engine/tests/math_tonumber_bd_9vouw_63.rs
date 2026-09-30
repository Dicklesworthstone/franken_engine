//! bd-9vouw.63: every `Math.*` function applies ES2020 ToNumber to each
//! argument, in argument order.
//!
//! Before the change most Math arms matched `Int`/`Float` and returned NaN
//! for everything else: `Math.floor('5')`, `Math.sqrt('16')`, `Math.ceil(null)`
//! and `Math.pow('2', 3)` were NaN on `frankenctl run` (Node: 5 4 0 8), some
//! arms hand-rolled a partial conversion (`'  7 '` parsed as NaN), objects
//! with `valueOf` were NaN, and Symbol/BigInt arguments returned NaN instead
//! of throwing TypeError. Each program runs through the real `frankenctl`
//! binary; expected lines were produced by Node v22.2.0 on the identical text.
//! Transcendental results are compared at 12 significant digits so the test
//! checks argument conversion, not last-ulp libm agreement with V8.
//! No-claim: string-to-number edge cases beyond these (hex, exponent forms)
//! belong to StringToNumber itself, and Date-to-number to ToPrimitive(Date).

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// (name, source, Node v22.2.0 output)
const CASES: &[(&str, &str, &str)] = &[
    (
        "unary_strings",
        "const f=['abs','ceil','floor','round','sqrt','trunc','sign','cbrt','fround','log2','log10','clz32','atan','asinh','acosh','exp','log','sin','cos','tan']; console.log(f.map(n => n + '=' + Math[n]('4').toPrecision(12)).join(' '));",
        "abs=4.00000000000 ceil=4.00000000000 floor=4.00000000000 round=4.00000000000 sqrt=2.00000000000 trunc=4.00000000000 sign=1.00000000000 cbrt=1.58740105197 fround=4.00000000000 log2=2.00000000000 log10=0.602059991328 clz32=29.0000000000 atan=1.32581766367 asinh=2.09471254726 acosh=2.06343706890 exp=54.5981500331 log=1.38629436112 sin=-0.756802495308 cos=-0.653643620864 tan=1.15782128235",
    ),
    (
        "primitives",
        "console.log(Math.floor('5'), Math.abs('-3'), Math.sqrt('16'), Math.round(true), Math.ceil(null), Math.trunc('4.7'), Math.pow('2',3), Math.sign('-2'), Math.floor(undefined), Math.floor(''), Math.floor(' 7 '), Math.floor('abc'));",
        "5 3 4 1 0 4 8 -1 NaN 0 7 NaN",
    ),
    (
        "binary",
        "console.log(Math.pow('3','2'), Math.atan2('1','1').toFixed(4), Math.imul('3','4'), Math.hypot('3','4'), Math.hypot('3', 'x'));",
        "9 0.7854 12 5 NaN",
    ),
    (
        "objects",
        "const o = { valueOf(){ return 9 } }; console.log(Math.sqrt(o), Math.floor({ valueOf(){ return 2.5 } }), Math.floor([7]), Math.floor([]), Math.floor({}));",
        "3 2 7 0 NaN",
    ),
    (
        "order",
        "const log = []; const a = { valueOf(){ log.push('a'); return 2 } }; const b = { valueOf(){ log.push('b'); return 5 } }; console.log(Math.pow(a, b), Math.hypot(a, b).toFixed(3), log.join(''));",
        "32 5.385 abab",
    ),
    (
        "symbol_throws",
        "try { Math.floor(Symbol('s')); console.log('no throw') } catch (e) { console.log(e.constructor.name) }",
        "TypeError",
    ),
    (
        "bigint_throws",
        "try { Math.floor(1n); console.log('no throw') } catch (e) { console.log(e.constructor.name) }",
        "TypeError",
    ),
];

fn scratch_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_math63_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[test]
fn math_functions_apply_to_number_like_node() {
    let dir = scratch_dir();
    let mut mismatches = Vec::new();
    for (name, source, node_output) in CASES {
        let input = dir.join(format!("{name}.js"));
        let report = dir.join(format!("{name}.run.json"));
        fs::write(&input, source).expect("program");
        let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args([
                "run",
                "--input",
                input.to_str().expect("utf8"),
                "--extension-id",
                "math63",
                "--instruction-budget",
                "10000000",
                "--out",
                report.to_str().expect("utf8"),
            ])
            .output()
            .expect("frankenctl should execute");
        if !output.status.success() {
            mismatches.push(format!(
                "{name}: run failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
            continue;
        }
        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&report).expect("report")).expect("json");
        let printed: Vec<&str> = parsed["console_output"]
            .as_array()
            .expect("console")
            .iter()
            .map(|entry| entry["message"].as_str().expect("message"))
            .collect();
        if printed != [*node_output] {
            mismatches.push(format!("{name}: got {printed:?}, node {node_output:?}"));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
