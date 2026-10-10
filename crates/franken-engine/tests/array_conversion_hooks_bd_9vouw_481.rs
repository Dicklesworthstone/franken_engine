//! bd-9vouw.481: whether an object has a guest conversion hook no longer depends on
//! whether %Object.prototype% was materialized: an ordinary object's default
//! prototype link reaches the intrinsic's virtual methods either way. This pins
//! Node v22.2.0's output for nested arrays (four conversion forms, 100, 200
//! and 1,000 levels deep and 10,000 levels a RangeError, before and
//! after Object.prototype is touched), matrices, plain, hooked, null-prototype,
//! class and @@toPrimitive objects, a cycle, and a patched
//! Array.prototype.toString, which nested arrays still observe.

use std::process::Command;

const PROGRAM: &str = r#"function nest(depth) { var x = [1]; for (var i = 0; i < depth; i++) x = [x]; return x; }
function forms(x) { return [String(x), x.join(), "" + x, x.toString()].join("|"); }
function deep(depth) { try { return forms(nest(depth)); } catch (e) { return e.constructor.name + ": " + e.message; } }
console.log("deep", deep(200), deep(1000), deep(10000));
console.log("before", forms(nest(100)), forms([[1, 2], [3, [4, 5]]]), [[1, 2], [3, 4]].join(";"));
console.log(String({}), "" + { toString: function () { return "T"; } }, "" + { valueOf: function () { return 7; } }, [{ toString: function () { return "E"; } }, [8]].join());
try { console.log("" + Object.create(null)); } catch (e) { console.log(e.constructor.name); }
class C { toString() { return "C!"; } }
console.log([new C(), [new C()]].join("/"), [{ [Symbol.toPrimitive]: function (h) { return h; } }].join());
var touch = Object.prototype; touch.zz = 1; delete touch.zz;
console.log("deep after", deep(200), deep(1000), deep(10000));
console.log("after", forms(nest(100)), forms([[1, 2], [3, [4, 5]]]));
var a = [1, 2]; a.push(a);
console.log("cycle", a.join(), String([a, [a]]));
Array.prototype.toString = function () { return "P"; };
console.log("patched", [[1], [2]].join(), String([[1], 2]));
"#;

const EXPECTED: &[&str] = &[
    "deep 1|1|1|1 1|1|1|1 RangeError: Maximum call stack size exceeded",
    "before 1|1|1|1 1,2,3,4,5|1,2,3,4,5|1,2,3,4,5|1,2,3,4,5 1,2;3,4",
    "[object Object] T 7 E,8",
    "TypeError",
    "C!/C! string",
    "deep after 1|1|1|1 1|1|1|1 RangeError: Maximum call stack size exceeded",
    "after 1|1|1|1 1,2,3,4,5|1,2,3,4,5|1,2,3,4,5|1,2,3,4,5",
    "cycle 1,2, 1,2,,1,2,",
    "patched P,P P",
];

#[test]
fn array_conversion_hooks_match_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("array_conversion_hooks_bd_9vouw_481.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "array-conversion-hooks",
            "--instruction-budget",
            "2000000000",
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
        .collect();
    assert_eq!(printed, EXPECTED);
}
