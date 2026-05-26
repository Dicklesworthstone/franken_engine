#![forbid(unsafe_code)]

//! PERF-H3.6 integration test (bd-o4cbn.2.6).
//!
//! PERF-H3 (bd-o4cbn.2) rewrote [`EngineObjectId::to_hex`] and its `Display`
//! impl to a zero-allocation hex encoder. A zero-alloc rewrite is exactly the
//! kind of change that can silently regress: an off-by-one into the scratch
//! buffer, a swapped nibble, an uppercased digit, or a truncated tail. This
//! integration test pins the externally observable contract of that hex path.
//!
//! ## What "evidence emission" surfaces today
//!
//! The bead sketch assumed `frankenctl run` would emit `"id":"<hex>"` fields
//! that wrap an [`EngineObjectId`]. In the current evidence schema it does not:
//! `frankenctl run`'s report uses counter-style ids (`frankenctl-run:0`),
//! human ids (`default-policy`), and **prefixed** content hashes
//! (`sha256:…`, `content:…`) — none are a bare 64-hex `EngineObjectId`
//! display string. So this test takes the path the bead explicitly allows
//! ("…or call the library API directly") for the round-trip assertions, and
//! still drives the real `frankenctl run` binary to prove the evidence
//! pipeline executes, emits well-formed deterministic JSON, and never leaks a
//! malformed bare 64-hex id (a forward guard for the day the schema does
//! surface one).
//!
//! Acceptance (bd-o4cbn.2.6): test compiles and passes, runtime <= 5 s.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};

/// `true` iff `s` is exactly 64 lowercase hex characters — the shape of an
/// `EngineObjectId` rendered through `to_hex()` / `Display`.
fn is_engine_object_id_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Assert the full `to_hex` / `Display` / `from_hex` contract for one id.
fn assert_hex_contract(id: &EngineObjectId, label: &str) {
    let hex = id.to_hex();

    assert_eq!(hex.len(), 64, "{label}: to_hex must be exactly 64 chars");
    assert!(
        is_engine_object_id_hex(&hex),
        "{label}: to_hex must be lowercase hex only, got {hex:?}"
    );
    // The two presentation paths the H3 rewrite touched must agree.
    assert_eq!(
        id.to_string(),
        hex,
        "{label}: Display must match to_hex byte-for-byte"
    );
    // Round-trip back to the identical id.
    let recovered = EngineObjectId::from_hex(&hex)
        .unwrap_or_else(|e| panic!("{label}: from_hex({hex}) must succeed, got {e:?}"));
    assert_eq!(&recovered, id, "{label}: hex round-trip must be lossless");
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("perf_h3")
}

/// Run the real `frankenctl run` binary on the fixture and return stdout.
fn run_frankenctl() -> String {
    let dir = fixtures_dir();
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .current_dir(&dir)
        .args([
            "run",
            "--input",
            "input.js",
            "--extension-id",
            "perf-h3-fixture",
            "--goal",
            "script",
        ])
        .output()
        .expect("frankenctl run must spawn");

    assert!(
        output.status.success(),
        "frankenctl run failed (status {:?}):\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("frankenctl stdout must be valid UTF-8")
}

/// Visit every JSON string scalar, recursively.
fn for_each_string(value: &serde_json::Value, visit: &mut impl FnMut(&str)) {
    match value {
        serde_json::Value::String(s) => visit(s),
        serde_json::Value::Array(items) => {
            for item in items {
                for_each_string(item, visit);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                for_each_string(v, visit);
            }
        }
        _ => {}
    }
}

#[test]
fn engine_object_id_display_roundtrips_in_evidence_emission() {
    let start = Instant::now();

    // -- Part 1: the real EngineObjectId hex-emission path ------------------
    //
    // `derive_id(...).to_hex()` is the exact call production evidence code
    // uses (e.g. recovery_artifact.rs, quarantine_propagation.rs). Drive it
    // across every ObjectDomain so domain separation is exercised too.
    let schema = SchemaId::from_definition(b"perf-h3-6-integration-schema-v1");
    let zone = "perf-h3-6-zone";
    let payload = b"perf-h3-6-canonical-payload";

    let mut emitted: BTreeSet<String> = BTreeSet::new();
    for domain in ObjectDomain::ALL {
        let id = derive_id(*domain, zone, &schema, payload)
            .expect("derive_id must succeed for non-empty canonical bytes");
        assert_hex_contract(&id, &format!("domain {domain}"));

        // Determinism: re-deriving the same inputs yields the same hex.
        let again = derive_id(*domain, zone, &schema, payload).expect("re-derive");
        assert_eq!(
            again.to_hex(),
            id.to_hex(),
            "domain {domain}: identical inputs must yield identical hex"
        );

        emitted.insert(id.to_hex());
    }
    assert_eq!(
        emitted.len(),
        ObjectDomain::ALL.len(),
        "every domain must emit a distinct hex id (domain separation)"
    );

    // -- Part 2: drive frankenctl's evidence emission -----------------------
    //
    // Prove the pipeline runs, emits parseable deterministic JSON, and that
    // any bare 64-hex id it ever surfaces obeys the same contract as Part 1.
    let stdout = run_frankenctl();
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("frankenctl run must emit valid JSON");

    let second = run_frankenctl();
    assert_eq!(
        stdout, second,
        "frankenctl run evidence output must be byte-deterministic"
    );

    let mut surfaced_hex_ids = 0usize;
    for_each_string(&report, &mut |s| {
        if is_engine_object_id_hex(s) {
            let id = EngineObjectId::from_hex(s)
                .unwrap_or_else(|e| panic!("emitted bare id {s:?} must from_hex, got {e:?}"));
            assert_eq!(
                id.to_hex(),
                s,
                "emitted bare id must round-trip through the H3 hex path"
            );
            surfaced_hex_ids += 1;
        }
    });
    // No assertion on `surfaced_hex_ids > 0`: the current schema surfaces none,
    // and Part 1 carries the non-vacuous round-trip coverage. This loop is the
    // regression guard for if/when the report schema emits a bare id.
    let _ = surfaced_hex_ids;

    assert!(
        start.elapsed().as_secs() < 5,
        "H3.6 acceptance: runtime must be <= 5 s (was {:?})",
        start.elapsed()
    );
}
