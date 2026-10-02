//! bd-9vouw.119: `++` and `--` step a BigInt by `1n`.
//!
//! The parser desugared `++x` to `x -= -1` and `x++` to `(x -= -1) - 1`, a
//! Number unit, so every update of a BigInt threw "cannot mix BigInt and
//! other types": p-queue's `this.#idAssigner++` (its ids start at `1n`) and
//! big-integer's `--b` failed. Updates are now their own operators and lower
//! to IR3 `Inc`/`Dec`: ToNumeric of the old value plus or minus one of its
//! own type. Each program covers one target kind (a local register, a
//! closure-captured binding, a global name, a member, a private field) or a
//! conversion path (valueOf returning a BigInt, getters and computed keys
//! evaluated once), and runs through the real `frankenctl` binary. Expected
//! lines were produced by Node v22.2.0 on the identical text. The Number
//! cases guard the paths that already worked. A postfix expression's value
//! is now ToNumeric of the old value itself: the old desugar recomputed it as
//! `(x + 1) - 1`, so `x = -0.1; x++` was -0.09999999999999998 and `-0` came
//! back as 0 (Test262 S11.3.1_A4_T2 and S11.3.2_A4_T2).

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// (name, source, Node v22.2.0 output)
const CASES: &[(&str, &str, &str)] = &[
    (
        "locals",
        "let b = 10n; b++; ++b; b--; console.log(String(b), typeof b);",
        "11 bigint",
    ),
    (
        "prefix_postfix_values",
        "let x = 5n; const a = x++; const c = ++x; const d = x--; const e = --x; console.log(String(a), String(c), String(d), String(e), String(x), typeof a);",
        "5 7 7 5 5 bigint",
    ),
    (
        "closure_captured",
        "let n = 0n; const inc = () => n++; inc(); inc(); const dec = () => --n; console.log(String(dec()), String(n));",
        "1 1",
    ),
    (
        "globals",
        "var g = 1n; g++; globalThis.h = 3n; h--; console.log(String(g), String(h));",
        "2 2",
    ),
    (
        "members",
        "const o = { k: 1n }; o.k++; ++o['k']; const arr = [1n]; arr[0]--; console.log(String(o.k), String(arr[0]));",
        "3 0",
    ),
    (
        "private_field",
        "class C { #id = 1n; next() { return this.#id++; } } const c = new C(); c.next(); console.log(String(c.next()));",
        "2",
    ),
    (
        "value_of_bigint",
        "let w = { valueOf() { return 7n; } }; w++; let v = { valueOf() { return 7n; } }; const old = v--; console.log(typeof w, String(w), String(old), String(v));",
        "bigint 8 7 6",
    ),
    (
        "numbers_unchanged",
        "let s = '5'; s++; let u; u++; let nn = null; nn--; let f = 1.5; f++; let dt = new Date(0); dt++; let bo = true; ++bo; console.log(s, u, nn, f, dt, bo);",
        "6 NaN -1 2.5 1 2",
    ),
    (
        "mixing_still_throws",
        "const out = []; try { let q = 1n; q += 1; } catch (e) { out.push(e.constructor.name); } try { let sy = Symbol(); sy++; } catch (e) { out.push(e.constructor.name); } console.log(out.join(' '));",
        "TypeError TypeError",
    ),
    (
        "loops",
        "let t = 0; for (let i = 0; i < 1000; i++) t += i; let acc = 0n; for (let i = 0n; i < 100n; i++) acc += i; let k = 10; while (k--) t++; console.log(t, String(acc), k);",
        "499510 4950 -1",
    ),
    (
        "getter_setter_once",
        "let gets = 0, sets = 0; const gs = { get v() { gets++; return 1n; }, set v(x) { sets++; this._v = x; } }; gs.v++; console.log(gets, sets, String(gs._v));",
        "1 1 2",
    ),
    (
        "computed_key_once",
        "let kc = 0; const ko = { a: 1n }; ko[(kc++, 'a')]++; console.log(kc, String(ko.a));",
        "1 2",
    ),
    (
        "postfix_value_is_old_numeric",
        "let x = -0.1; const y = x++; let z = -0; const zr = z++; let n = new Number(1.1); const nr = n--; let big = 2 ** 53; const br = big++; const o = { v: 0.3 }; const or = o.v--; let s = '2.5'; const sr = s++; console.log(y, Object.is(zr, -0), nr, br === 2 ** 53, or, o.v, sr, typeof sr, x);",
        "-0.1 true 1.1 true 0.3 -0.7 2.5 number 0.9",
    ),
    (
        "in_callbacks",
        "const r = [1n, 2n, 3n].map(v => { let w = v; w++; return w; }); let sum = 0n; [1n, 2n].forEach(v => { sum += v; sum++; }); console.log(r.join(','), String(sum));",
        "2,3,4 5",
    ),
];

fn scratch_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_update119_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[test]
fn bigint_updates_step_by_one_n_like_node() {
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
                "update119",
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
