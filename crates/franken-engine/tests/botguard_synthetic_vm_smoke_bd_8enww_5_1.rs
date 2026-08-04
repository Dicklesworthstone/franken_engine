#![forbid(unsafe_code)]

//! bd-8enww.5.1 (YTBG-E1): synthetic BotGuard-like VM smoke fixture.
//!
//! This is the bridge between the isolated language-feature conformance vectors
//! (typed arrays — bd-8enww.2.*, Function constructor — bd-8enww.3.*, try/catch/
//! finally — bd-8enww.4.*) and the obfuscated VM *shape* a real BotGuard payload
//! takes. It does NOT clone BotGuard; it is a compact, deterministic adversarial
//! fixture that stresses the same three runtime dimensions **together in one
//! program** run through the public `HybridRouter::eval` surface:
//!
//!   1. memory setup — a bytecode program in a `Uint8Array`, checksummed.
//!   2. generated dispatch — opcode handlers built with the `Function` constructor, driven over the bytecode.
//!   3. register I/O — the accumulator stored/read back through a `DataView` over an `ArrayBuffer` (LE uint32).
//!   4. exception probe — a deliberate native `TypeError` (null property access) caught by `try`/`catch`.
//!   5. finally cleanup — a `finally` side effect that must run.
//!
//! A final token-like digest is stitched from every stage.
//!
//! Each stage is ALSO exercised as its own `JsConformanceVector` through the
//! bd-8enww.1.4 structured-log runner (`_support::js_conformance`), so if any
//! primitive regresses the per-vector `JsConformanceLog` (vector id, category,
//! expected vs actual, `sha256:` source hash) localizes the failure to the exact
//! stage rather than only flipping the opaque combined digest (AC#3). The
//! combined fixture's digest is frozen and asserted byte-for-byte, and is
//! verified to be reproducible across independent evaluations (AC#1, AC#4).
//!
//! Every snippet is composed only from primitives already proven green by the
//! typed-array / Function-constructor / exception conformance suites, and avoids
//! the documented fail-closed gaps (TypedArray `.map`, `new` on a generated
//! function, nested codegen, ambient authority).
//!
//! Run with the structured log:
//!   cargo test -p frankenengine-engine --test botguard_synthetic_vm_smoke_bd_8enww_5_1 -- --nocapture

mod _support;

use _support::js_conformance::{
    JsConformanceReport, JsConformanceVector, assert_js_conformance_vectors,
    run_js_conformance_vectors,
};

const CAT_MEMORY: &str = "botguard-vm/memory-setup";
const CAT_DISPATCH: &str = "botguard-vm/generated-dispatch";
const CAT_REGISTER: &str = "botguard-vm/register-io";
const CAT_PROBE: &str = "botguard-vm/exception-probe";
const CAT_FINALLY: &str = "botguard-vm/finally-cleanup";
const CAT_DIGEST: &str = "botguard-vm/token-digest";

/// The full synthetic VM program. A 3-instruction bytecode `(operand, opcode)`
/// stream drives Function-constructor opcode handlers, the accumulator round-trips
/// through a DataView register, a tamper probe raises and catches a native
/// `TypeError`, and a `finally` performs cleanup before the digest is assembled.
///
/// Deterministic trace:
///   code = [10,1, 20,2, 30,1]          memChecksum = 10+1+20+2+30+1 = 64
///   acc: 0 +10 =10, 10 -20 =-10, -10 +30 =20   -> acc = 20
///   DataView setUint32(20) / getUint32 -> readback = 20
///   null.op -> caught TypeError -> probe = "TypeError"
///   readback === 20 -> no throw -> finally -> cleanup = "cleaned"
///   token = "mem=64;acc=20;rb=20;probe=TypeError;fin=cleaned"
const VM_FIXTURE_SOURCE: &str = r#"
var code = new Uint8Array([10, 1, 20, 2, 30, 1]);
var memChecksum = 0;
for (var i = 0; i < code.length; i = i + 1) { memChecksum = memChecksum + code[i]; }
var add = new Function("a", "v", "return a + v;");
var sub = new Function("a", "v", "return a - v;");
var acc = 0;
for (var p = 0; p < code.length; p = p + 2) {
    var operand = code[p];
    var op = code[p + 1];
    if (op === 1) { acc = add(acc, operand); }
    if (op === 2) { acc = sub(acc, operand); }
}
var buf = new ArrayBuffer(4);
var dv = new DataView(buf);
dv.setUint32(0, acc, true);
var readback = dv.getUint32(0, true);
var probe = "tampered";
try { var z = null; z.op; probe = "no-throw"; } catch (e) { probe = e.name; }
var cleanup = "dirty";
try { if (readback !== 20) { throw "corrupt"; } } finally { cleanup = "cleaned"; }
var token = "mem=" + memChecksum + ";acc=" + acc + ";rb=" + readback + ";probe=" + probe + ";fin=" + cleanup;
token;
"#;

const VM_FIXTURE_DIGEST: &str = "mem=64;acc=20;rb=20;probe=TypeError;fin=cleaned";

/// Per-stage + combined vectors. The per-stage vectors are self-contained so a
/// regression in any single primitive flips exactly one structured log.
fn botguard_vm_vectors() -> Vec<JsConformanceVector> {
    vec![
        // Stage 1: typed-array VM memory + checksum.
        JsConformanceVector::value(
            "vm-stage1-memory-checksum",
            CAT_MEMORY,
            r#"var code = new Uint8Array([10, 1, 20, 2, 30, 1]); var s = 0; for (var i = 0; i < code.length; i = i + 1) { s = s + code[i]; } s;"#,
            "64",
        ),
        // Stage 2: Function-constructor opcode handlers dispatched over the bytecode.
        JsConformanceVector::value(
            "vm-stage2-generated-dispatch",
            CAT_DISPATCH,
            r#"var code = new Uint8Array([10, 1, 20, 2, 30, 1]); var add = new Function("a", "v", "return a + v;"); var sub = new Function("a", "v", "return a - v;"); var acc = 0; for (var p = 0; p < code.length; p = p + 2) { var operand = code[p]; var op = code[p + 1]; if (op === 1) { acc = add(acc, operand); } if (op === 2) { acc = sub(acc, operand); } } acc;"#,
            "20",
        ),
        // Stage 3: accumulator round-trips through a DataView register (LE uint32).
        JsConformanceVector::value(
            "vm-stage3-dataview-register-readback",
            CAT_REGISTER,
            r#"var buf = new ArrayBuffer(4); var dv = new DataView(buf); dv.setUint32(0, 20, true); dv.getUint32(0, true);"#,
            "20",
        ),
        // Stage 4: deliberate native TypeError caught by the anti-tamper probe.
        JsConformanceVector::value(
            "vm-stage4-exception-probe",
            CAT_PROBE,
            r#"var probe = "tampered"; try { var z = null; z.op; probe = "no-throw"; } catch (e) { probe = e.name; } probe;"#,
            "TypeError",
        ),
        // Stage 5: finally cleanup side effect must run.
        JsConformanceVector::value(
            "vm-stage5-finally-cleanup",
            CAT_FINALLY,
            r#"var cleanup = "dirty"; try { var ok = 20; if (ok !== 20) { throw "corrupt"; } } finally { cleanup = "cleaned"; } cleanup;"#,
            "cleaned",
        ),
        // Combined: the whole VM in one program -> the stable token digest.
        JsConformanceVector::value(
            "vm-combined-token-digest",
            CAT_DIGEST,
            VM_FIXTURE_SOURCE,
            VM_FIXTURE_DIGEST,
        ),
    ]
}

/// AC#1/#2/#3: the synthetic VM exercises typed arrays + Function constructor +
/// try/catch/finally together; every stage is represented and passes, and the
/// structured per-stage log localizes any regression.
#[test]
fn synthetic_botguard_vm_smoke_passes_all_stages() {
    let vectors = botguard_vm_vectors();
    let report = assert_js_conformance_vectors(&vectors);
    render_report(&report);

    assert_eq!(report.total_vectors as usize, vectors.len());
    assert_eq!(report.failed, 0);

    for category in [
        CAT_MEMORY,
        CAT_DISPATCH,
        CAT_REGISTER,
        CAT_PROBE,
        CAT_FINALLY,
        CAT_DIGEST,
    ] {
        assert!(
            report.logs.iter().any(|log| log.category == category),
            "the synthetic VM must exercise stage '{category}'"
        );
    }

    // Every per-stage log carries a content hash of its source for traceability.
    for log in &report.logs {
        assert!(
            log.source_hash.starts_with("sha256:"),
            "stage '{}' must carry a source hash, got {}",
            log.vector_id,
            log.source_hash
        );
    }
}

/// AC#1/#4: the combined fixture returns the frozen digest and is deterministic —
/// two independent evaluations produce byte-identical output with no network or
/// browser dependency.
#[test]
fn synthetic_botguard_vm_digest_is_stable_and_deterministic() {
    let fixture = JsConformanceVector::value(
        "vm-combined-token-digest",
        CAT_DIGEST,
        VM_FIXTURE_SOURCE,
        VM_FIXTURE_DIGEST,
    );

    let first = run_js_conformance_vectors(std::slice::from_ref(&fixture));
    let second = run_js_conformance_vectors(std::slice::from_ref(&fixture));

    let first_log = &first.logs[0];
    let second_log = &second.logs[0];

    assert!(first_log.passed, "fixture must return the frozen digest");
    assert_eq!(first_log.actual_result, VM_FIXTURE_DIGEST);
    assert_eq!(
        first_log.actual_result, second_log.actual_result,
        "the synthetic VM digest must be deterministic across evaluations"
    );
    assert_eq!(
        first_log.source_hash, second_log.source_hash,
        "a fixed fixture source must hash identically across evaluations"
    );
}

/// Render the structured report as pretty JSON so `--nocapture` runs emit the
/// e2e log artifact (per-stage vector id, source hash, expected/actual).
fn render_report(report: &JsConformanceReport) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => eprintln!("[bd-8enww.5.1] synthetic-botguard-vm report:\n{json}"),
        Err(err) => eprintln!("[bd-8enww.5.1] failed to render report: {err}"),
    }
}
