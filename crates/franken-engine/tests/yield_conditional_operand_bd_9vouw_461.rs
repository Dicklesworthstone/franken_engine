//! bd-9vouw.461: a yield with an operand takes a whole conditional as that
//! operand: `yield 1 ? 'y' : 'n'` is `yield (1 ? 'y' : 'n')`. The
//! conditional was split first and the yield refused as its condition ("a
//! `yield` expression cannot be the condition of `?:`"), so the whole
//! program failed to parse; only an operand-less `yield ? a : b` is that
//! error. The program also pins yield placements that already matched
//! Node (nested yields, yields in arrays, arguments, templates, computed
//! keys, yield*, finally, throw). Expected lines are Node v22.2.0's.

use std::process::Command;

const PROGRAM: &str = r#"const out = [];
function run(gen, inputs) { const it = gen(); const seen = []; let r = it.next(); let i = 0; while (!r.done) { seen.push(JSON.stringify(r.value)); r = it.next(inputs[i++]); } seen.push('ret=' + JSON.stringify(r.value)); return seen.join(','); }
out.push(run(function* () { const a = yield 1; const b = yield a + 1; return [a, b]; }, [10, 20]));
out.push(run(function* () { return yield yield 1; }, ['x', 'y']));
out.push(run(function* () { return [yield 1, yield 2]; }, ['a', 'b']));
out.push(run(function* () { function f(...xs) { return xs; } return f(yield 1, 2, yield 3); }, ['p', 'q']));
out.push(run(function* () { const x = (yield) + 1; return x; }, [4]));
out.push(run(function* () { return yield 1 ? 'y' : 'n'; }, ['r']));
out.push(run(function* () { const v = `${yield 'tpl'}!`; return v; }, ['T']));
out.push(run(function* () { const inner = function* () { const z = yield 'in'; return z * 2; }; const res = yield* inner(); return res; }, [21]));
out.push(run(function* () { yield
  1; return 'asi'; }, []));
out.push(run(function* () { let n = 0; while (n < 2) n += yield n; return n; }, [1, 1]));
out.push(run(function* () { try { yield 'try'; } finally { yield 'fin'; } }, []));
out.push(run(function* () { const o = { [yield 'key']: yield 'val' }; return o; }, ['k', 'v']));
const it = (function* () { try { yield 1; } catch (e) { yield 'caught ' + e; } })();
it.next(); out.push(JSON.stringify(it.throw('err')));
console.log(out.join('\n'));
"#;

const EXPECTED: &[&str] = &[
    "1,11,ret=[10,20]",
    "1,\"x\",ret=\"y\"",
    "1,2,ret=[\"a\",\"b\"]",
    "1,3,ret=[\"p\",2,\"q\"]",
    ",ret=5",
    "\"y\",ret=\"r\"",
    "\"tpl\",ret=\"T!\"",
    "\"in\",ret=42",
    ",ret=\"asi\"",
    "0,1,ret=2",
    "\"try\",\"fin\",ret=undefined",
    "\"key\",\"val\",ret={\"k\":\"v\"}",
    "{\"value\":\"caught err\",\"done\":false}",
];

#[test]
fn yield_operands_and_placements_match_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("yield_battery.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "yield-conditional-operand",
            "--out",
            report.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "frankenctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("json");
    let printed: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .flat_map(|message| message.split('\n'))
        .collect();
    assert_eq!(printed, EXPECTED);
}
