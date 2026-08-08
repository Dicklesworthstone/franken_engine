#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(name: &str, ext: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    path.push(format!("{name}_{}_{}.{}", std::process::id(), nonce, ext));
    path
}

fn backend<'a>(report: &'a serde_json::Value, backend: &str) -> &'a serde_json::Value {
    report["backends"]
        .as_array()
        .expect("backends should be an array")
        .iter()
        .find(|receipt| receipt["backend"].as_str() == Some(backend))
        .unwrap_or_else(|| panic!("missing backend receipt `{backend}`"))
}

#[test]
fn frankenctl_differential_oracle_run_emits_four_backend_receipts() {
    let source_path = temp_path("differential_oracle_fixture", "js");
    let report_path = temp_path("differential_oracle_report", "json");
    fs::write(&source_path, "1 + 1;\n").expect("fixture should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "differential-oracle",
            "run",
            "--input",
            source_path
                .to_str()
                .expect("temp source path should be utf8"),
            "--case-id",
            "integration-basic-arithmetic",
            "--timeout-ms",
            "1000",
            "--out",
            report_path
                .to_str()
                .expect("temp report path should be utf8"),
        ])
        .output()
        .expect("frankenctl differential-oracle should execute");

    let stdout_report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should contain JSON report");
    let file_report: serde_json::Value = serde_json::from_slice(
        fs::read(&report_path)
            .expect("report file should exist")
            .as_slice(),
    )
    .expect("report file should contain JSON");

    assert_eq!(
        stdout_report["schema_version"].as_str(),
        Some("franken-engine.differential-oracle.v1")
    );
    assert_eq!(
        stdout_report["case_id"].as_str(),
        Some("integration-basic-arithmetic")
    );
    assert_eq!(stdout_report["backends"].as_array().unwrap().len(), 4);
    assert_eq!(
        stdout_report["canonicalization"]["schema_version"].as_str(),
        Some("franken-engine.differential-oracle.canonicalization.v2")
    );
    assert_eq!(
        stdout_report["canonicalization"]["observations"]
            .as_array()
            .expect("canonical observations should be an array")
            .len(),
        4
    );
    assert!(
        stdout_report["canonicalization"]["comparisons"]
            .as_array()
            .expect("canonical comparisons should be an array")
            .iter()
            .any(|comparison| comparison["mode"].as_str() == Some("structured_value"))
    );
    assert_eq!(
        stdout_report["divergence_taxonomy"]["schema_version"].as_str(),
        Some("franken-engine.differential-oracle.divergence-taxonomy.v2")
    );
    assert!(
        stdout_report["divergence_taxonomy"]["findings"]
            .as_array()
            .is_some()
    );
    assert_eq!(
        file_report["schema_version"],
        stdout_report["schema_version"]
    );
    let expected_exit = match stdout_report["canonicalization"]["semantic_verdict"].as_str() {
        Some("consensus") => 0,
        Some("divergence") => 3,
        Some("insufficient_data") => 4,
        other => panic!("unexpected semantic verdict: {other:?}"),
    };
    assert_eq!(
        output.status.code(),
        Some(expected_exit),
        "legacy differential-oracle surface must propagate the report verdict: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let node = backend(&stdout_report, "node_lts");
    assert!(matches!(
        node["status"].as_str(),
        Some("completed" | "failed" | "unavailable" | "timeout" | "degraded")
    ));
    assert!(node["command"].as_array().is_some());

    let bun = backend(&stdout_report, "bun_stable");
    assert!(matches!(
        bun["status"].as_str(),
        Some("completed" | "failed" | "unavailable" | "timeout" | "degraded")
    ));
    assert!(bun["command"].as_array().is_some());

    let franken_engine = backend(&stdout_report, "franken_engine");
    assert_eq!(franken_engine["status"].as_str(), Some("completed"));
    assert_eq!(franken_engine["value"].as_str(), Some("2"));
    assert_eq!(franken_engine["exit_code"].as_i64(), Some(0));

    let franken_core = backend(&stdout_report, "franken_core");
    assert_eq!(franken_core["status"].as_str(), Some("completed"));
    assert_eq!(franken_core["value"].as_str(), Some("2"));
    assert_eq!(franken_core["exit_code"].as_i64(), Some(0));
    assert!(
        franken_core["command"]
            .as_array()
            .expect("franken-core command should be an array")
            .iter()
            .any(|entry| entry
                .as_str()
                .unwrap_or_default()
                .contains("frankenengine_core::baseline_interpreter::QuickJsLane::execute"))
    );
    assert!(
        franken_core["diagnostics"]
            .as_array()
            .expect("franken-core diagnostics should be an array")
            .iter()
            .any(|entry| entry
                .as_str()
                .unwrap_or_default()
                .contains("frankenengine-core path dependency executed"))
    );
}

// =========================================================================
// bd-n8eta.4.5: executable Symbol own-key donor matrix
// =========================================================================

/// Run one matrix case through the real differential oracle and return the
/// parsed report. `node` is resolved with `/usr/bin` prefixed onto PATH so
/// the probe reaches real Node rather than a bun-provided shim.
fn run_symbol_matrix_case(case_id: &str, source: &str) -> serde_json::Value {
    let source_path = temp_path(&format!("sym_matrix_{case_id}"), "js");
    let report_path = temp_path(&format!("sym_matrix_{case_id}_report"), "json");
    fs::write(&source_path, source).expect("matrix source should write");

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .env("PATH", format!("/usr/bin:{inherited_path}"))
        .args([
            "differential-oracle",
            "run",
            "--input",
            source_path.to_str().expect("source path should be utf8"),
            "--case-id",
            case_id,
            "--timeout-ms",
            "15000",
            "--out",
            report_path.to_str().expect("report path should be utf8"),
        ])
        .output()
        .expect("differential-oracle run should execute");
    // The CLI exit code reflects the OVERALL verdict across every comparison
    // mode (0 consensus / 3 divergence / 4 insufficient data). A matrix case
    // asserts specific per-mode agreement below, so any report-emitting exit
    // is acceptable here; only usage/io failures (1, 2) abort.
    assert!(
        matches!(output.status.code(), Some(0 | 3 | 4)),
        "oracle run failed for {case_id} (exit {:?}): {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(
        fs::read(&report_path)
            .expect("oracle report should exist")
            .as_slice(),
    )
    .expect("oracle report should parse");
    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(report_path);
    report
}

fn matrix_backend<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    report["backends"]
        .as_array()
        .expect("backends should be an array")
        .iter()
        .find(|entry| entry["backend"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("report should carry a {name} receipt"))
}

/// Donor-observing case: real Node, real Bun, and the engine lane must all
/// print exactly `expected` (console is the shared observable), and the
/// oracle's `exact_stdout` canonicalization must place all three in a single
/// agreement group.
fn assert_donor_consensus(case_id: &str, source: &str, expected: &str) {
    let report = run_symbol_matrix_case(case_id, source);
    for backend in ["node_lts", "bun_stable", "franken_engine"] {
        let receipt = matrix_backend(&report, backend);
        assert_eq!(
            receipt["status"].as_str(),
            Some("completed"),
            "{case_id}: {backend} must complete (diagnostics: {:?}, stderr: {:?})",
            receipt["diagnostics"],
            receipt["stderr"]
        );
        assert_eq!(
            receipt["stdout"].as_str(),
            Some(format!("{expected}\n").as_str()),
            "{case_id}: {backend} stdout mismatch"
        );
    }
    let comparisons = report["canonicalization"]["comparisons"]
        .as_array()
        .expect("comparisons should be an array");
    let exact_stdout = comparisons
        .iter()
        .find(|comparison| comparison["mode"].as_str() == Some("exact_stdout"))
        .expect("exact_stdout comparison should exist");
    let engine_group = exact_stdout["groups"]
        .as_array()
        .expect("groups should be an array")
        .iter()
        .find(|group| {
            group["backends"]
                .as_array()
                .is_some_and(|backends| backends.iter().any(|b| b == "franken_engine"))
        })
        .expect("engine should appear in an exact_stdout group");
    for donor in ["node_lts", "bun_stable"] {
        assert!(
            engine_group["backends"]
                .as_array()
                .is_some_and(|backends| backends.iter().any(|b| b == donor)),
            "{case_id}: {donor} must share the engine's exact_stdout group"
        );
    }
}

/// Engine/core lockstep case: both in-process lanes must complete with the
/// same completion value, and the oracle's `structured_value` canonicalization
/// must place them in a single agreement group.
fn assert_engine_core_lockstep(case_id: &str, source: &str, expected: &str) {
    let report = run_symbol_matrix_case(case_id, source);
    for backend in ["franken_engine", "franken_core"] {
        let receipt = matrix_backend(&report, backend);
        assert_eq!(
            receipt["status"].as_str(),
            Some("completed"),
            "{case_id}: {backend} must complete (diagnostics: {:?}, stderr: {:?})",
            receipt["diagnostics"],
            receipt["stderr"]
        );
        assert_eq!(
            receipt["value"].as_str(),
            Some(expected),
            "{case_id}: {backend} completion value mismatch"
        );
    }
    let comparisons = report["canonicalization"]["comparisons"]
        .as_array()
        .expect("comparisons should be an array");
    let structured = comparisons
        .iter()
        .find(|comparison| comparison["mode"].as_str() == Some("structured_value"))
        .expect("structured_value comparison should exist");
    let engine_group = structured["groups"]
        .as_array()
        .expect("groups should be an array")
        .iter()
        .find(|group| {
            group["backends"]
                .as_array()
                .is_some_and(|backends| backends.iter().any(|b| b == "franken_engine"))
        })
        .expect("engine should appear in a structured_value group");
    assert!(
        engine_group["backends"]
            .as_array()
            .is_some_and(|backends| backends.iter().any(|b| b == "franken_core")),
        "{case_id}: franken_core must share the engine's structured_value group"
    );
}

/// bd-n8eta.4.5: the executable Node/Bun/engine/core Symbol own-key donor
/// matrix. Donor-observing cases prove Node + Bun + engine parity through the
/// shared console observable; the console-free twins prove engine/core
/// lockstep on the same semantics via completion values (franken-core cannot
/// lower `console.*` source yet, and it has no executable Proxy or
/// `Object.defineProperty`, so the Proxy and accessor-conversion rows are
/// donor+engine only — see ECMA262_DISCREPANCIES.md DISC-013 for the pinned
/// scope).
#[test]
fn symbol_own_key_donor_matrix_bd_n8eta_4_5() {
    // Row 1: ES2020 own-key order (integer-like ascending, then strings and
    // Symbols in insertion order); keys/getOwnPropertyNames/for-in exclude
    // Symbols; getOwnPropertySymbols preserves creation order (observed via
    // values); same-description Symbols stay distinct; Reflect.ownKeys
    // counts the complete mixed set.
    assert_donor_consensus(
        "sym-order-donor",
        r##"const s1 = Symbol("alpha");
const s2 = Symbol("alpha");
const o = { b: 1 };
o[s1] = 2;
o["10"] = 3;
o.a = 4;
o[s2] = 5;
o["2"] = 6;
const keys = Object.keys(o).join("|");
const names = Object.getOwnPropertyNames(o).join("|");
const forin = [];
for (const k in o) { forin.push(k); }
const syms = Object.getOwnPropertySymbols(o);
const symVals = [];
for (const s of syms) { symVals.push(o[s]); }
const distinct = syms[0] !== syms[1];
const total = Reflect.ownKeys(o).length;
console.log(keys + "#" + names + "#" + forin.join("|") + "#" + symVals.join("|") + "#" + distinct + "#" + total);
"##,
        "2|10|b|a#2|10|b|a#2|10|b|a#2|5#true#6",
    );
    assert_engine_core_lockstep(
        "sym-order-core",
        r##"const s1 = Symbol("alpha");
const s2 = Symbol("alpha");
const o = { b: 1 };
o[s1] = 2;
o["10"] = 3;
o.a = 4;
o[s2] = 5;
o["2"] = 6;
const keys = Object.keys(o);
let acc = "";
let i = 0;
while (i < keys.length) { acc = acc + "|" + keys[i]; i = i + 1; }
const names = Object.getOwnPropertyNames(o);
acc = acc + "#";
i = 0;
while (i < names.length) { acc = acc + "|" + names[i]; i = i + 1; }
let forin = "";
for (const k in o) { forin = forin + "|" + k; }
const syms = Object.getOwnPropertySymbols(o);
let symVals = "";
i = 0;
while (i < syms.length) { symVals = symVals + "|" + o[syms[i]]; i = i + 1; }
acc + "#" + forin + "#" + symVals + "#" + (syms[0] !== syms[1]) + "#" + Reflect.ownKeys(o).length;
"##,
        "|2|10|b|a#|2|10|b|a#|2|10|b|a#|2|5#true#6",
    );
    // Row 2: updates retain own-key position; string and Symbol delete +
    // re-add both append to the tail of their respective segments.
    assert_donor_consensus(
        "sym-delete-readd-donor",
        r##"const sk = Symbol("k");
const st = Symbol("t");
const o = {};
o.x = 1;
o[sk] = 2;
o.y = 3;
o.x = 10;
const before = Object.keys(o).join("|");
delete o.x;
o.x = 11;
const after = Object.keys(o).join("|");
o[st] = 1;
delete o[sk];
o[sk] = 9;
const syms = Object.getOwnPropertySymbols(o);
const symVals = [];
for (const s of syms) { symVals.push(o[s]); }
console.log(before + "#" + after + "#" + symVals.join("|") + "#" + o.x + "#" + o[sk]);
"##,
        "x|y#y|x#1|9#11#9",
    );
    assert_engine_core_lockstep(
        "sym-delete-readd-core",
        r##"const sk = Symbol("k");
const st = Symbol("t");
const o = {};
o.x = 1;
o[sk] = 2;
o.y = 3;
o.x = 10;
const keysBefore = Object.keys(o);
let before = "";
let i = 0;
while (i < keysBefore.length) { before = before + "|" + keysBefore[i]; i = i + 1; }
delete o.x;
o.x = 11;
const keysAfter = Object.keys(o);
let after = "";
i = 0;
while (i < keysAfter.length) { after = after + "|" + keysAfter[i]; i = i + 1; }
o[st] = 1;
delete o[sk];
o[sk] = 9;
const syms = Object.getOwnPropertySymbols(o);
let symVals = "";
i = 0;
while (i < syms.length) { symVals = symVals + "|" + o[syms[i]]; i = i + 1; }
before + "#" + after + "#" + symVals + "#" + o.x + "#" + o[sk];
"##,
        "|x|y#|y|x#|1|9#11#9",
    );
    // Row 3: JSON.stringify / Object.values / Object.entries exclude Symbol
    // keys; object spread and Object.assign include enumerable Symbol keys.
    assert_donor_consensus(
        "sym-exclusion-inclusion-donor",
        r##"const s = Symbol("s");
const src = { a: 1, b: 3 };
src[s] = 2;
const j = JSON.stringify(src);
const vals = Object.values(src).join("|");
const ents = [];
for (const e of Object.entries(src)) { ents.push(e[0] + ":" + e[1]); }
const spread = { ...src };
const assigned = Object.assign({}, src);
console.log(j + "#" + vals + "#" + ents.join("|") + "#" + (spread[s] === 2) + "#" + (assigned[s] === 2));
"##,
        "{\"a\":1,\"b\":3}#1|3#a:1|b:3#true#true",
    );
    assert_engine_core_lockstep(
        "sym-exclusion-inclusion-core",
        r##"const s = Symbol("s");
const src = { a: 1, b: 3 };
src[s] = 2;
const j = JSON.stringify(src);
const vals = Object.values(src);
let acc = "";
let i = 0;
while (i < vals.length) { acc = acc + "|" + vals[i]; i = i + 1; }
const spread = { ...src };
const assigned = Object.assign({}, src);
j + "#" + acc + "#" + (spread[s] === 2) + "#" + (assigned[s] === 2);
"##,
        "{\"a\":1,\"b\":3}#|1|3#true#true",
    );
    // Row 4 (donor + engine only; franken-core has no executable Proxy):
    // Proxy ownKeys preserves typed identity — a string alias like
    // "Symbol(14)" stays a string, trap-returned Symbols keep their exact
    // identity, same-description Symbols stay distinct — and duplicate
    // identical keys in the trap result are rejected with a TypeError.
    assert_donor_consensus(
        "sym-proxy-identity-donor",
        r##"const p1 = Symbol("p");
const p2 = Symbol("p");
const target = {};
target[p1] = 1;
target.q = 2;
const handler = { ownKeys() { return ["q", "Symbol(14)", p1, p2]; } };
const p = new Proxy(target, handler);
const ks = Reflect.ownKeys(p);
let dup = "no";
try { Reflect.ownKeys(new Proxy({}, { ownKeys() { return [p1, p1]; } })); } catch (e) { dup = "TypeError"; }
console.log((typeof ks[1]) + "#" + (typeof ks[2]) + "#" + (ks[2] === p1) + "#" + (ks[3] === p2) + "#" + (ks[2] === ks[3]) + "#" + ks.length + "#" + dup);
"##,
        "string#symbol#true#true#false#4#TypeError",
    );
    // Row 5 (donor + engine only; franken-core has no executable
    // Object.defineProperty): converting a data property to an accessor
    // via defineProperty retains the key's own-key position for string and
    // Symbol keys, and the accessor is invoked on read.
    assert_donor_consensus(
        "sym-accessor-conversion-donor",
        r##"const sa = Symbol("acc");
const o = {};
o.a = 1;
o[sa] = 2;
o.b = 3;
Object.defineProperty(o, "a", { get() { return 42; }, enumerable: true, configurable: true });
Object.defineProperty(o, sa, { get() { return 43; }, enumerable: true, configurable: true });
const syms = Object.getOwnPropertySymbols(o);
console.log(Object.keys(o).join("|") + "#" + syms.length + "#" + (syms[0] === sa) + "#" + o.a + "#" + o[sa]);
"##,
        "a|b#1#true#42#43",
    );
}
