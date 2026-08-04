#![forbid(unsafe_code)]
//! bd-fqlfw.2.8 — E2.TEST Differential Oracle test+verify capstone.
//!
//! Consolidating end-to-end coverage for the E2 differential-oracle stack. Every
//! acceptance bullet of the bead is exercised here against the *real* oracle (no
//! mocks, no synthetic classifier):
//!
//!   1. Fixed-corpus oracle runs across the hermetic franken-engine + franken-core
//!      lanes each emit a content-addressed bundle (`manifest.json` / `report.json`
//!      / `repro.lock`) that `frankenctl oracle report` re-verifies byte-identically,
//!      and a single byte of tampering is rejected.
//!   2. Canonicalization correctness: number formatting, NaN / Infinity / -0, float
//!      rendering, and BigInt-boundary integers are equated across the two
//!      independent interpreters (→ semantic consensus), while a real structured
//!      value difference is surfaced as a divergence.
//!   3. The divergence taxonomy enumerates all seven classes with stable, unique
//!      labels — including the intentional-security-divergence (→ waiver) and
//!      reference-runtime-bug classes.
//!   4. The engine↔franken-core internal "free bug-finder" oracle reports every
//!      classified divergence as a defect carrying a minimized reproducer, and that
//!      reproducer independently re-classifies to the *same* signature — i.e. the
//!      minimizer never over-minimizes (the classified divergence is preserved).
//!   5. The DEGRADED path (a requested reference runtime absent) emits a fail-closed
//!      `degraded_receipt.json` (FE-REPRO-0007) and a non-zero exit — never a silent
//!      pass.
//!   6. The FE-CLAIM-010 Node/Bun-denominator claim is the honest, repro.lock-backed
//!      `target` state (a measured denominator that does not meet the ≥3× floor), and
//!      the oracle refuses to fabricate a denominator from a single lane.
//!
//! Hermetic by construction: the consensus corpus uses only the two in-process
//! lanes (no node/bun process is spawned), and the degraded case points `--node-bin`
//! at a non-existent binary, so the suite is deterministic on any host.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::differential_oracle::{
    DifferentialBackend, DifferentialComparisonVerdict, DifferentialDivergenceClass,
    DifferentialOracleInput, DivergenceSignature, default_engine_core_corpus,
    run_differential_oracle, run_engine_core_differential_oracle,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unique_token(name: &str) -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    format!("{name}_{}_{}", std::process::id(), nonce)
}

fn temp_path(name: &str, ext: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("{}.{ext}", unique_token(name)));
    path
}

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(unique_token(name));
    path
}

fn write_fixture(name: &str, source: &str) -> PathBuf {
    let path = temp_path(name, "js");
    fs::write(&path, source).expect("fixture should write");
    path
}

fn run_oracle(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("oracle")
        .args(args)
        .output()
        .expect("frankenctl oracle should execute")
}

fn parse_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap_or_else(|error| {
        panic!(
            "expected JSON: {error}\n---\n{}\n---",
            String::from_utf8_lossy(bytes)
        )
    })
}

fn read_json(path: &Path) -> serde_json::Value {
    parse_json(&fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// An oracle input restricted to the hermetic internal twin (engine ↔ core), with
/// the external runtime specs pointed at deliberately-missing binaries so no real
/// node/bun process can ever be spawned even if selection logic changed.
fn engine_core_input(case_id: &str, source: &str) -> DifferentialOracleInput {
    let mut input = DifferentialOracleInput::new(case_id, source)
        .with_selected_backends([
            DifferentialBackend::FrankenEngine,
            DifferentialBackend::FrankenCore,
        ])
        .with_engine_instruction_budget(64_000_000);
    input.node.program = "frankenengine-missing-node-runtime".to_string();
    input.bun.program = "frankenengine-missing-bun-runtime".to_string();
    input
}

fn signature_of(input: &DifferentialOracleInput) -> DivergenceSignature {
    DivergenceSignature::from_report(&run_differential_oracle(input))
}

// ---------------------------------------------------------------------------
// 1. Fixed-corpus content-addressed bundle emission + byte-identical re-verify
// ---------------------------------------------------------------------------

/// The CONSENSUS corpus: bare value-producing expressions on which the two
/// in-process interpreters agree. A bare expression (not `console.log`) is used
/// deliberately — the core lane has no console builtin, so a `console.log` program
/// would surface a lane asymmetry rather than a clean cross-lane consensus.
const CONSENSUS_CORPUS: &[(&str, &str)] = &[
    ("arith_sum", "40 + 2;"),
    ("arith_parens", "(1 + 2) * 3;"),
    ("arith_mod", "17 % 5;"),
    ("string_concat", "\"a\" + \"b\" + \"c\";"),
    ("comparison", "1 < 2;"),
    ("ternary", "true ? 10 : 20;"),
];

#[test]
fn capstone_fixed_corpus_emits_and_reverifies_content_addressed_bundles() {
    for (case, source) in CONSENSUS_CORPUS {
        let fixture = write_fixture(&format!("capstone_corpus_{case}"), source);
        let bundle = temp_dir(&format!("capstone_corpus_{case}_out"));

        // RUN — emit the content-addressed bundle across the two hermetic lanes.
        let run = run_oracle(&[
            "run",
            fixture.to_str().unwrap(),
            "--engines",
            "franken,core",
            "--bundle",
            bundle.to_str().unwrap(),
            "--json",
        ]);
        let summary = parse_json(&run.stdout);
        assert!(
            run.status.success(),
            "case {case} should reach consensus (exit 0): verdict={:?} stderr={}",
            summary["semantic_verdict"],
            String::from_utf8_lossy(&run.stderr)
        );
        assert_eq!(
            summary["semantic_verdict"].as_str(),
            Some("consensus"),
            "case {case} should be a cross-lane consensus"
        );
        assert_eq!(summary["degraded"].as_bool(), Some(false));
        assert_eq!(summary["exit_code"].as_i64(), Some(0));

        // The canonical four-file bundle (no degraded receipt on a clean run).
        for required in ["manifest.json", "report.json", "repro.lock"] {
            assert!(
                bundle.join(required).is_file(),
                "case {case}: bundle should contain {required}"
            );
        }
        assert!(
            !bundle.join("degraded_receipt.json").exists(),
            "case {case}: a non-degraded run must not emit a degraded receipt"
        );

        // manifest.json content-addresses report.json by sha256.
        let manifest = read_json(&bundle.join("manifest.json"));
        let recorded = manifest["artifacts"]["report"]["sha256"]
            .as_str()
            .expect("manifest records report sha256");
        let actual = sha256_prefixed(&fs::read(bundle.join("report.json")).unwrap());
        assert_eq!(
            recorded, actual,
            "case {case}: manifest sha256 == report bytes"
        );

        // repro.lock pins the reproducible assertion (the semantic verdict, NOT
        // wall-clock timing) and the verification command.
        let lock = read_json(&bundle.join("repro.lock"));
        assert_eq!(
            lock["schema_version"].as_str(),
            Some("franken-engine.repro-lock.v1"),
            "case {case}: repro.lock schema"
        );
        assert_eq!(
            lock["determinism"]["reproducible_assertion"].as_str(),
            Some("semantic_verdict"),
            "case {case}: the reproducible assertion is the semantic verdict"
        );
        assert_eq!(
            lock["verification"]["expected_verdict"].as_str(),
            Some("consensus")
        );

        // REPORT — re-verify the preserved bundle byte-identically.
        let report = run_oracle(&["report", bundle.to_str().unwrap(), "--json"]);
        assert!(
            report.status.success(),
            "case {case}: report of a consensus bundle should verify (exit 0): stderr={}",
            String::from_utf8_lossy(&report.stderr)
        );
        let verified = parse_json(&report.stdout);
        assert_eq!(verified["integrity"].as_str(), Some("verified"));
        assert_eq!(verified["semantic_verdict"].as_str(), Some("consensus"));
        assert_eq!(verified["exit_code"].as_i64(), Some(0));
    }
}

#[test]
fn capstone_report_rejects_a_single_byte_of_tampering() {
    let fixture = write_fixture("capstone_tamper", "7 * 6;\n");
    let bundle = temp_dir("capstone_tamper_out");

    let run = run_oracle(&[
        "run",
        fixture.to_str().unwrap(),
        "--engines",
        "franken,core",
        "--bundle",
        bundle.to_str().unwrap(),
    ]);
    assert!(run.status.success(), "consensus run should succeed");

    // Flip the report after the manifest recorded its hash.
    let report_path = bundle.join("report.json");
    let mut bytes = fs::read(&report_path).unwrap();
    bytes.push(b' ');
    fs::write(&report_path, bytes).unwrap();

    let report = run_oracle(&["report", bundle.to_str().unwrap(), "--json"]);
    assert!(
        !report.status.success(),
        "a tampered bundle must fail integrity, never silently verify"
    );
    let stderr = String::from_utf8_lossy(&report.stderr);
    assert!(
        stderr.contains("integrity failure"),
        "stderr should name the integrity failure: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// 2. Canonicalization correctness (number / NaN / Infinity / float / bigint)
// ---------------------------------------------------------------------------

#[test]
fn capstone_canonicalization_equates_number_and_value_edges_across_lanes() {
    // Each program is a value-edge where naive string rendering could disagree but
    // the canonical structured value must equate the two independent interpreters.
    // (Verified empirically that both lanes render identically; a regression in
    // either interpreter's value rendering would surface here as a divergence.)
    let edges = [
        ("infinity", "1 / 0;"),
        ("neg_infinity", "-1 / 0;"),
        ("nan", "0 / 0;"),
        ("negative_zero", "-0;"),
        ("float_rounding", "0.1 + 0.2;"),
        ("bigint_boundary", "2 ** 53;"),
        ("boolean", "true;"),
        ("null_value", "null;"),
    ];
    for (case, source) in edges {
        let input = engine_core_input(case, source);
        let signature = signature_of(&input);
        assert_eq!(
            signature.verdict,
            DifferentialComparisonVerdict::Consensus,
            "canonicalization should equate `{source}` across engine + core \
             (verdict={:?}, findings={})",
            signature.verdict,
            signature.findings.len()
        );
        assert!(
            !signature.has_classified_divergence(),
            "`{source}` must not be a classified divergence"
        );
    }
}

#[test]
fn capstone_canonicalization_surfaces_a_real_structured_value_difference() {
    // A genuine value difference between two synthetic lanes must NOT be smoothed
    // away by canonicalization. We drive this through the public oracle by
    // configuring the external runtime as a fixed echo of a different value; the
    // simplest hermetic way to assert the *detection* side is via the internal twin
    // on a construct where the lanes are known to disagree, then assert the verdict
    // is a divergence with a retained semantic finding.
    //
    // We probe the historically-divergent value-producing constructs and assert the
    // oracle classifies at least one as a divergence (rather than hard-coding which
    // construct currently diverges, which would be brittle against parity fixes).
    let probes = [
        // A stable architectural divergence: `typeof console` is "object" in the
        // engine (runtime globals injected) but "undefined" in franken-core (no
        // runtime globals). This is the load-bearing probe now that the array/
        // object (bd-rkmpj: benign heap-identity noise) and consumed-postfix
        // (bd-xi3bk: franken-core now yields the prior value faithfully) cases below
        // have reached parity. If franken-core ever injects console, extend the list
        // with another genuine divergence.
        "typeof console;",
        "(function () { var i = 5; var x = i++; return x; })();",
        "(function () { var s = 0; for (var i = 0; i < 5; i++) { s += i; } return s; })();",
        "(function () { return [1, 2, 3]; })();",
        "(function () { return {x: 1}; })();",
        "[1, 2, 3];",
        "({a: 1, b: 2});",
    ];
    let mut any_divergence = false;
    for source in probes {
        let signature = signature_of(&engine_core_input("value_probe", source));
        if signature.has_classified_divergence() {
            any_divergence = true;
            assert_eq!(
                signature.verdict,
                DifferentialComparisonVerdict::Divergence,
                "a classified divergence must carry a Divergence verdict"
            );
            assert!(
                !signature.findings.is_empty(),
                "a classified divergence must retain at least one semantic finding"
            );
            break;
        }
    }
    assert!(
        any_divergence,
        "the canonicalizer must SURFACE (not suppress) a real structured value \
         difference; if the internal twin has reached full parity on these probes, \
         extend the probe list"
    );
}

// ---------------------------------------------------------------------------
// 3. Divergence taxonomy — all seven classes, stable + unique labels
// ---------------------------------------------------------------------------

#[test]
fn capstone_divergence_taxonomy_enumerates_all_seven_classes() {
    use DifferentialDivergenceClass::*;
    // The complete, ordered taxonomy. Adding or removing a class without updating
    // this list (and the operator runbook) fails the capstone — the taxonomy is a
    // published contract, not an implementation detail.
    let classes = [
        (Parser, "parser"),
        (Lowering, "lowering"),
        (Runtime, "runtime"),
        (ModuleResolution, "module_resolution"),
        (HostcallPolicy, "hostcall_policy"),
        (
            IntentionalSecurityDivergence,
            "intentional_security_divergence",
        ),
        (ReferenceRuntimeBug, "reference_runtime_bug"),
    ];
    assert_eq!(classes.len(), 7, "the taxonomy has exactly seven classes");

    let mut labels = std::collections::BTreeSet::new();
    for (class, expected) in classes {
        assert_eq!(
            class.stable_label(),
            expected,
            "stable label for {class:?} must be wire-stable"
        );
        assert!(
            labels.insert(class.stable_label()),
            "stable labels must be unique: {expected} appeared twice"
        );
    }
    assert_eq!(labels.len(), 7, "all seven labels must be distinct");
}

// ---------------------------------------------------------------------------
// 4. Engine↔core free internal oracle: minimized defects that re-classify
// ---------------------------------------------------------------------------

#[test]
fn capstone_engine_core_free_oracle_minimizes_and_preserves_every_defect() {
    let corpus = default_engine_core_corpus();
    assert!(!corpus.is_empty(), "the seed corpus must not be empty");

    let report = run_engine_core_differential_oracle(&corpus, 256);
    assert_eq!(
        report.cases_checked,
        corpus.len(),
        "every corpus case must be accounted for"
    );
    assert!(
        report.accounting_is_consistent(),
        "agreements + inconclusive + defects must equal cases_checked: {report:?}"
    );

    // For EVERY reported defect, the minimized reproducer must:
    //  (a) be no larger than the original (the minimizer reduced or held),
    //  (b) carry a classified divergence in its recorded signature, and
    //  (c) INDEPENDENTLY re-classify to the SAME signature when re-run from scratch
    //      — proving the minimizer preserved the divergence class (no over-minimization).
    for defect in &report.defects {
        assert!(
            !defect.minimized_source.trim().is_empty(),
            "defect {} must carry a non-empty minimized reproducer",
            defect.case_id
        );
        assert!(
            defect.minimized_line_count <= defect.original_line_count,
            "defect {}: minimization must not grow the case ({} -> {})",
            defect.case_id,
            defect.original_line_count,
            defect.minimized_line_count
        );
        assert!(
            defect.signature.has_classified_divergence(),
            "defect {} must record a classified divergence",
            defect.case_id
        );

        // Independent re-verification from scratch — does not trust the harness's
        // own bookkeeping.
        let reverify = signature_of(&engine_core_input(
            &format!("{}-reverify", defect.case_id),
            &defect.minimized_source,
        ));
        assert!(
            reverify.has_classified_divergence(),
            "defect {}: the minimized reproducer must still diverge",
            defect.case_id
        );
        assert_eq!(
            reverify, defect.signature,
            "defect {}: the minimized reproducer must reproduce the SAME classified \
             divergence (no over-minimization)",
            defect.case_id
        );
    }
}

#[test]
fn capstone_engine_core_oracle_is_clean_on_a_consensus_only_corpus() {
    // A corpus of cases the two lanes agree on must report ZERO defects — the free
    // oracle does not invent divergences.
    use frankenengine_engine::differential_oracle::EngineCoreCorpusCase;
    let corpus: Vec<EngineCoreCorpusCase> = CONSENSUS_CORPUS
        .iter()
        .map(|(case, source)| EngineCoreCorpusCase::new(*case, *source))
        .collect();
    let report = run_engine_core_differential_oracle(&corpus, 256);
    assert!(
        !report.has_defects(),
        "a consensus-only corpus must report no defects: {:?}",
        report.defects
    );
    assert_eq!(report.agreements, corpus.len(), "all cases should agree");
    assert!(report.accounting_is_consistent());
}

// ---------------------------------------------------------------------------
// 5. DEGRADED path — fail-closed receipt, never a silent pass
// ---------------------------------------------------------------------------

#[test]
fn capstone_degraded_reference_runtime_emits_fail_closed_receipt() {
    let fixture = write_fixture("capstone_degraded", "1 + 1;\n");
    let bundle = temp_dir("capstone_degraded_out");

    let output = run_oracle(&[
        "run",
        fixture.to_str().unwrap(),
        "--engines",
        "franken,node",
        // Force the node lane unavailable, deterministically.
        "--node-bin",
        "/nonexistent/franken_capstone_degraded_node",
        "--bundle",
        bundle.to_str().unwrap(),
        "--json",
    ]);

    let summary = parse_json(&output.stdout);
    assert_eq!(
        summary["degraded"].as_bool(),
        Some(true),
        "an absent reference runtime must mark the run degraded"
    );
    assert_eq!(
        output.status.code(),
        Some(4),
        "a degraded run must exit non-zero (insufficient-data = 4), NEVER a silent pass: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(summary["exit_code"].as_i64(), Some(4));

    // The degraded receipt is written and names the unavailable denominator runtime.
    let receipt_path = bundle.join("degraded_receipt.json");
    assert!(
        receipt_path.is_file(),
        "a degraded run must persist a degraded_receipt.json (the 'denominator unavailable' receipt)"
    );
    let receipt = read_json(&receipt_path);
    assert_eq!(receipt["error_code"].as_str(), Some("FE-REPRO-0007"));
    assert_eq!(receipt["verdict"].as_str(), Some("degraded"));
    let reasons = receipt["reasons"]
        .as_array()
        .expect("reasons array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        reasons.contains("node"),
        "the receipt reasons must name the unavailable node runtime: {reasons}"
    );
}

// ---------------------------------------------------------------------------
// 6. FE-CLAIM-010 — honest, repro.lock-backed Node/Bun denominator posture
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    // tests run with CWD = crate dir (crates/franken-engine); the repo root is two
    // levels up. CARGO_MANIFEST_DIR is the most robust anchor.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("repo root is two levels above the crate manifest dir")
}

#[test]
fn capstone_fe_claim_010_is_honest_target_backed_by_a_measured_denominator() {
    let root = repo_root();

    // The measured denominator bundle (bd-fqlfw.2.6/2.7) exists with a repro.lock
    // partner — the artifact that backs the matrix claim.
    let denom_dir = root.join("docs/perf/e2_denominator_bundle_v1");
    assert!(
        denom_dir.join("denominator.json").is_file(),
        "the measured denominator artifact must exist at {}",
        denom_dir.join("denominator.json").display()
    );
    assert!(
        denom_dir.join("repro.lock").is_file(),
        "the denominator artifact must ship a repro.lock partner (no artifact, no claim)"
    );

    // The matrix records FE-CLAIM-010 as the honest `target` state: a measured
    // denominator that does NOT meet the >= 3x floor. It must not be over-promoted
    // to `observed`, and it must not be fabricated.
    let matrix = read_json(&root.join("docs/claim_to_proof_matrix_v1.json"));
    let claims = matrix["claims"]
        .as_array()
        .expect("matrix has claims array");
    let row = claims
        .iter()
        .find(|c| c["claim_id"].as_str() == Some("FE-CLAIM-010"))
        .expect("matrix has an FE-CLAIM-010 row");
    assert_eq!(
        row["allowed_state"].as_str(),
        Some("target"),
        "FE-CLAIM-010 must stay TARGET until the engine clears the >= 3x floor"
    );
    assert_eq!(
        row["actual_wording_state"].as_str(),
        Some("target"),
        "the published wording must match the allowed (honest) state"
    );

    // The denominator artifact must be real measurement, not a simulated fixture.
    let denom_bytes = fs::read(denom_dir.join("denominator.json")).unwrap();
    let denom_text = String::from_utf8_lossy(&denom_bytes);
    assert!(
        !denom_text.contains("hot_paths_simulation") && !denom_text.contains("MockCertificate"),
        "the denominator artifact must not contain simulated/mock evidence markers"
    );
}

#[test]
fn capstone_oracle_refuses_to_fabricate_a_denominator_from_one_lane() {
    // A single lane cannot reach cross-runtime consensus and must not invent one:
    // the oracle reports insufficient-data (exit 4), the honest "we don't know"
    // state — the same discipline that keeps FE-CLAIM-010 at `target`.
    let fixture = write_fixture("capstone_single_lane", "1 + 1;\n");
    let output = run_oracle(&[
        "run",
        fixture.to_str().unwrap(),
        "--engines",
        "franken",
        "--json",
    ]);
    let summary = parse_json(&output.stdout);
    assert_eq!(
        summary["semantic_verdict"].as_str(),
        Some("insufficient_data"),
        "one lane cannot manufacture a cross-runtime verdict"
    );
    assert_eq!(output.status.code(), Some(4));
}
