//! bd-9vouw.472: Array.prototype.shift, unshift and splice on a dense array move
//! the values inside the property carrier instead of a generic [[Get]]/[[Set]]
//! per element. This pins what programs observe to Node v22.2.0 on both paths.
//! Fast path: a 3,000-element queue drained by shift, mixed element values,
//! push and index writes after a shift, an unshift and a splice (the dense
//! cache), named properties, a single element, shift then unshift on a
//! 2,000-element array, a BFS, 2,000 unshifts, unshift of several items, onto an
//! empty array and of none, a deque mixing unshift, push and shift, 500
//! middle-element splices, splices that grow, shrink and keep the length, splice
//! without a delete count, with a negative start and with no arguments, and a
//! subclass receiver (its removed array comes from @@species). Generic path:
//! holes, an element inherited from Array.prototype, frozen, sealed,
//! non-extensible and non-writable-length arrays and an array-like receiver.
//! Throwing splices follow the spec's step order (bd-9vouw.477): a sealed array
//! throws at its first delete before any item is written, and a non-extensible
//! array keeps the items written into existing indices before the write to a
//! new index throws.

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
var u = [];
for (var ui = 0; ui < 2000; ui++) u.unshift(ui);
console.log(u.length, u[0], u[1999], u.indexOf(1000), u.unshift(), u.length);
var m = [3, 4];
console.log(m.unshift(1, 2), JSON.stringify(m), m.unshift("a", "b", "c"), m.join(""));
var e = [];
console.log(e.unshift("x"), e[0], e.length, JSON.stringify(e));
var up = [2];
up.unshift(1);
up.push(3);
up[up.length] = 4;
console.log(JSON.stringify(up), up.length, up.lastIndexOf(4));
var dq = [];
for (var d = 0; d < 300; d++) { if (d % 3 === 0) dq.unshift(d); else dq.push(d); if (d % 5 === 0) dq.shift(); }
console.log(dq.length, dq[0], dq[dq.length - 1], dq.slice(0, 4).join(","));
var nx = Object.preventExtensions([1]);
try { nx.unshift(0); console.log("no error"); } catch (err) { console.log(err.constructor.name, nx.length, nx[0]); }
var su = Object.seal([1, 2]);
try { su.unshift(0); console.log("no error"); } catch (err) { console.log(err.constructor.name, su.length); }
var fu = Object.freeze([1]);
try { fu.unshift(0); console.log("no error"); } catch (err) { console.log(err.constructor.name, fu.length); }
var hu = [1, , 3];
console.log(hu.unshift(0), hu.length, 2 in hu, JSON.stringify(hu));
var sp = [];
for (var si = 0; si < 1000; si++) sp.push(si);
var got = [];
while (sp.length > 500) got.push(sp.splice(sp.length >> 1, 1)[0]);
console.log(sp.length, got.length, got[0], got[499], sp[0], sp[499], sp[250]);
var r = [1, 2, 3, 4, 5];
console.log(JSON.stringify(r.splice(1, 2, "a", "b", "c")), JSON.stringify(r), r.length);
var r2 = [1, 2, 3, 4, 5, 6];
console.log(JSON.stringify(r2.splice(1, 4, "x")), JSON.stringify(r2), r2.length);
var r3 = [1, 2, 3];
console.log(JSON.stringify(r3.splice(1)), JSON.stringify(r3), JSON.stringify([1, 2, 3, 4].splice(-2, 1)), JSON.stringify([1, 2].splice()));
class MyArr extends Array {}
var ma = MyArr.from([1, 2, 3]);
var res = ma.splice(0, 1);
console.log(res instanceof MyArr, res.length, ma.length, ma[0]);
var sq = [1, 2, 3];
sq.splice(1, 1);
sq.push(9);
sq[sq.length] = 10;
console.log(JSON.stringify(sq), sq.length);
var hs = [1, , 3, 4];
console.log(JSON.stringify(hs.splice(0, 1)), JSON.stringify(hs), 0 in hs, hs.length);
var fs = Object.freeze([1, 2]);
try { fs.splice(0, 1); console.log("no error"); } catch (err) { console.log(err.constructor.name, fs.length); }
var ns = Object.preventExtensions([1, 2, 3]);
console.log(JSON.stringify(ns.splice(0, 1)), JSON.stringify(ns));
try { ns.splice(0, 0, "grow"); console.log("no error"); } catch (err) { console.log(err.constructor.name, ns.length); }
var ss = Object.seal([1.5, 1.5]);
try { ss.splice(0, 190, 136); console.log("no error"); } catch (err) { console.log(err.constructor.name, JSON.stringify(ss)); }
var ng = Object.preventExtensions(["s2", "s3"]);
try { ng.splice(1, 2, 197, 143); console.log("no error"); } catch (err) { console.log(err.constructor.name, JSON.stringify(ng)); }
var nt = Object.preventExtensions([1, 2, 3, 4]);
try { nt.splice(1, 1, "a", "b"); console.log("no error"); } catch (err) { console.log(err.constructor.name, JSON.stringify(nt)); }
var ne2 = Object.preventExtensions([1, 2, 3]);
console.log(JSON.stringify(ne2.splice(1, 1, "x")), JSON.stringify(ne2));
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
    "2000 1999 0 999 2000 2000",
    "4 [1,2,3,4] 7 abc1234",
    "1 x 1 [\"x\"]",
    "[1,2,3,4] 4 3",
    "240 297 299 297,291,282,276",
    "TypeError 1 1",
    "TypeError 2",
    "TypeError 1",
    "4 4 false [0,1,null,3]",
    "500 500 500 250 0 999 750",
    "[2,3] [1,\"a\",\"b\",\"c\",4,5] 6",
    "[2,3,4,5] [1,\"x\",6] 3",
    "[2,3] [1] [3] []",
    "true 1 2 2",
    "[1,3,9,10] 4",
    "[1] [null,3,4] false 3",
    "TypeError 2",
    "[1] [2,3]",
    "TypeError 2",
    "TypeError [1.5,1.5]",
    "TypeError [\"s2\",197]",
    "TypeError [1,2,3,4]",
    "[2] [1,\"x\",3]",
];

#[test]
fn array_shift_unshift_and_splice_match_node_on_both_paths() {
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
