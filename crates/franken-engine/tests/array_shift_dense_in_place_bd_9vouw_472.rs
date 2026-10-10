//! bd-9vouw.472: Array.prototype.shift on a dense array moves the values inside
//! the property carrier instead of a generic [[Get]]/[[Set]] per element. This
//! pins what programs observe to Node v22.2.0 on both paths: a 3,000-element
//! queue drained by shift, mixed element values, push and index writes after a
//! shift (the dense cache), named properties, a single element, shift then
//! unshift on a 2,000-element array and a BFS (the fast path); holes, an element
//! inherited from Array.prototype, frozen, sealed and non-writable-length
//! arrays and an array-like receiver (the generic path).

use std::process::Command;

const PROGRAM: &str = r#"var q = [];
for (var i = 0; i < 3000; i++) q.push(i);
var sum = 0, n = 0;
while (q.length) { sum += q.shift(); n++; }
console.log(n, sum, q.length, JSON.stringify(q), q.shift());
var a = [1, "two", { x: 3 }, [4], null, undefined, 7.5];
var out = [];
while (a.length) out.push(String(a.shift()));
console.log(out.join("|"), a.length);
var h = [1, , 3];
console.log(h.shift(), h.length, 0 in h, 1 in h, JSON.stringify(h));
Array.prototype[1] = "proto";
var hp = [1, , 3];
console.log(hp.shift(), hp[0], hp.hasOwnProperty(0), hp.length);
delete Array.prototype[1];
var fz = Object.freeze([1, 2]);
try { fz.shift(); console.log("no error"); } catch (e) { console.log(e.constructor.name, fz.length, fz[0]); }
var sl = Object.seal([1, 2, 3]);
try { sl.shift(); console.log("no error"); } catch (e) { console.log(e.constructor.name, sl.length); }
var nw = [1, 2, 3];
Object.defineProperty(nw, "length", { writable: false });
try { nw.shift(); console.log("no error"); } catch (e) { console.log(e.constructor.name, nw.length); }
var c = [1, 2, 3];
c.shift();
c.push(4);
c[c.length] = 5;
console.log(JSON.stringify(c), c.length, c.indexOf(4), c.lastIndexOf(5));
var np = [1, 2, 3];
np.tag = "x";
console.log(np.shift(), JSON.stringify(np), np.tag, Object.keys(np).join(","));
var al = { 0: "a", 1: "b", length: 2 };
console.log(Array.prototype.shift.call(al), JSON.stringify(al));
var one = ["only"];
console.log(one.shift(), one.length, JSON.stringify(one), one.shift(), one.length);
var big = [];
for (var b = 0; b < 2000; b++) big.push("s" + b);
var taken = [];
for (var t = 0; t < 1000; t++) taken.push(big.shift());
big.unshift("front");
console.log(big.length, big[0], big[1], big[999], big[1000], taken[999], big.slice(-2).join(","));
var adj = {};
for (var v = 0; v < 500; v++) adj[v] = [(v * 2 + 1) % 500, (v * 3 + 2) % 500];
var dist = { 0: 0 };
var queue = [0];
while (queue.length) {
  var u = queue.shift();
  adj[u].forEach(function (w) { if (!(w in dist)) { dist[w] = dist[u] + 1; queue.push(w); } });
}
console.log(Object.keys(dist).length, dist[499], dist[250]);
"#;

const EXPECTED: &[&str] = &[
    "3000 4498500 0 [] undefined",
    "1|two|[object Object]|4|null|undefined|7.5 0",
    "1 2 false true [null,3]",
    "1 proto true 2",
    "TypeError 2 1",
    "TypeError 3",
    "TypeError 3",
    "[2,3,4,5] 4 2 3",
    "1 [2,3] x 0,1,tag",
    "a {\"0\":\"b\",\"length\":1}",
    "only 0 [] undefined 0",
    "1001 front s1000 s1998 s1999 s999 s1998,s1999",
    "300 undefined undefined",
];

#[test]
fn array_shift_matches_node_on_both_paths() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root
        .path()
        .join("array_shift_dense_in_place_bd_9vouw_472.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "array-shift-dense",
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
