//! Integration coverage for `frankenctl differential-oracle perf` (E2.T4,
//! bd-fqlfw.2.4): the measured Node/Bun denominator arm.
//!
//! External-runtime availability is environmental, so these tests assert the
//! HONEST handling contract rather than specific ratios: when Node/Bun are
//! present the lanes must carry real per-iteration samples; when absent the
//! receipt must be degraded with recorded reasons — never a fabricated number.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{name}_{}_{}", std::process::id(), nonce));
    fs::create_dir_all(dir.join("programs")).expect("temp corpus dir should create");
    dir
}

fn write_corpus(dir: &Path, cases: &[(&str, &str)]) -> PathBuf {
    let mut manifest_cases = Vec::new();
    for (id, source) in cases {
        let file = format!("programs/{id}.js");
        fs::write(dir.join(&file), source).expect("program should write");
        manifest_cases.push(format!(
            "{{\"benchmark_id\":\"{id}\",\"program_path\":\"{file}\"}}"
        ));
    }
    let manifest = dir.join("manifest.json");
    fs::write(
        &manifest,
        format!("{{\"cases\":[{}]}}", manifest_cases.join(",")),
    )
    .expect("manifest should write");
    manifest
}

fn run_perf(manifest: &Path, report_path: &Path, events_path: &Path) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "differential-oracle",
            "perf",
            "--manifest",
            manifest.to_str().expect("manifest path should be utf8"),
            "--out",
            report_path.to_str().expect("report path should be utf8"),
            "--events",
            events_path.to_str().expect("events path should be utf8"),
            "--warmup",
            "1",
            "--samples",
            "10",
            "--case-timeout-ms",
            "30000",
        ])
        .output()
        .expect("frankenctl differential-oracle perf should execute");
    assert!(
        output.status.success(),
        "frankenctl should succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout should contain JSON summary")
}

#[test]
fn perf_arm_emits_report_events_and_honest_denominators() {
    let dir = temp_dir("diffperf_corpus");
    let manifest = write_corpus(
        &dir,
        &[(
            "tiny_sum",
            "var sum = 0;\nfor (var i = 0; i < 1000; i = i + 1) { sum = sum + i; }\nconsole.log(sum);\n",
        )],
    );
    let report_path = dir.join("report.json");
    let events_path = dir.join("events.jsonl");

    let summary = run_perf(&manifest, &report_path, &events_path);

    // Full report on disk.
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("report file should exist"))
            .expect("report should parse");
    assert_eq!(
        report["schema_version"].as_str(),
        Some("franken-engine.differential-oracle-perf.v3")
    );
    let cases = report["cases"].as_array().expect("cases array");
    assert_eq!(cases.len(), 1);
    let case = &cases[0];

    // Engine lane is in-process and must always carry real samples.
    assert_eq!(case["engine"]["status"].as_str(), Some("measured"));
    assert!(case["engine"]["preparation_ns"].as_u64().is_some());
    assert_eq!(
        case["engine"]["engine_kind"].as_str(),
        Some("baseline_deterministic_profile")
    );
    assert_eq!(
        case["engine"]["route_reason"].as_str(),
        Some("default_deterministic_profile")
    );
    assert_eq!(
        case["engine"]["measured_ns"]
            .as_array()
            .expect("engine samples")
            .len(),
        10
    );
    assert_eq!(
        case["engine"]["measured_observation_sha256"]
            .as_array()
            .expect("engine observation digests")
            .len(),
        10
    );
    assert_eq!(
        case["engine"]["observations_complete"].as_bool(),
        Some(true)
    );

    // The environment manifest must record the corpus and iteration protocol.
    let environment = &report["environment"];
    assert_eq!(environment["warmup_iterations"].as_u64(), Some(1));
    assert_eq!(environment["measured_iterations"].as_u64(), Some(10));
    assert_eq!(environment["max_cv_millionths"].as_u64(), Some(150_000));
    assert_eq!(environment["corpus_case_count"].as_u64(), Some(1));
    assert_eq!(
        environment["engine_execution_lifecycle"].as_str(),
        Some("prepare_once_fresh_router_and_interpreter_core_per_iteration")
    );
    assert_eq!(
        environment["external_execution_lifecycle"].as_str(),
        Some("new_function_once_single_process_shared_realm_and_jit_state")
    );
    assert_eq!(
        environment["corpus_sha256"]
            .as_str()
            .expect("corpus sha")
            .len(),
        64
    );

    // Honest handling per external lane: real samples when measured,
    // diagnostics when not.
    for lane in ["node", "bun"] {
        let status = case[lane]["status"].as_str().expect("lane status");
        if status == "measured" {
            assert!(
                case[lane]["preparation_ns"].as_u64().is_some(),
                "{lane} lane should record one-time compilation cost"
            );
            assert_eq!(
                case[lane]["measured_ns"]
                    .as_array()
                    .expect("lane samples")
                    .len(),
                10,
                "{lane} lane should carry 10 measured samples"
            );
            assert_eq!(
                case[lane]["measured_observation_sha256"]
                    .as_array()
                    .expect("lane observation digests")
                    .len(),
                10,
                "{lane} lane should carry 10 measured observation digests"
            );
            assert_eq!(
                case[lane]["observations_complete"].as_bool(),
                Some(true),
                "{lane} measured the governed undefined-return corpus but did not retain complete observations"
            );
        } else {
            assert!(
                case[lane]["diagnostics"]
                    .as_array()
                    .is_some_and(|d| !d.is_empty()),
                "{lane} lane status `{status}` must carry diagnostics"
            );
        }
    }
    if ["node", "bun"]
        .iter()
        .all(|lane| case[*lane]["status"].as_str() == Some("measured"))
    {
        assert_eq!(
            case["measured_lifecycle_equivalent"].as_bool(),
            Some(true),
            "all three measured lanes must agree on the stable primitive-output/undefined-return observation"
        );
    }

    assert_eq!(report["fairness"]["compliant"].as_bool(), Some(false));
    assert!(
        report["fairness"]["violations"]
            .as_array()
            .is_some_and(|violations| violations.iter().any(|violation| violation
                .as_str()
                .is_some_and(|text| text.contains("execution lifecycle is not symmetric"))))
    );

    // V3 deliberately keeps the fresh-engine/shared-realm lifecycle
    // diagnostic-only. Neither denominator may expose a publishable ratio.
    for denominator_key in ["node_denominator", "bun_denominator"] {
        let denominator = &summary[denominator_key];
        assert_eq!(denominator["status"].as_str(), Some("degraded"));
        assert!(denominator["geomean_speedup_millionths"].is_null());
        assert!(denominator["meets_3x_floor"].is_null());
        assert!(
            denominator["degraded_reasons"]
                .as_array()
                .is_some_and(|r| !r.is_empty()),
            "{denominator_key} degraded without reasons"
        );
    }

    // Raw phase events stream: engine contributes 1 preparation + 1 warmup +
    // 10 measured lines; external lanes contribute when measured.
    let events_text = fs::read_to_string(&events_path).expect("events file should exist");
    let engine_lines = events_text
        .lines()
        .filter(|line| line.contains("\"franken_engine\""))
        .count();
    assert_eq!(
        engine_lines, 12,
        "engine should log 1 preparation + 1 warmup + 10 measured"
    );
    for line in events_text.lines() {
        let event: serde_json::Value = serde_json::from_str(line).expect("event line should parse");
        assert_eq!(event["event"].as_str(), Some("diffperf.iteration"));
        assert!(event["duration_ns"].as_u64().is_some());
    }
}

#[test]
fn perf_arm_case_filter_rejects_unknown_ids() {
    let dir = temp_dir("diffperf_filter");
    let manifest = write_corpus(&dir, &[("tiny", "1 + 1;\n")]);

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "differential-oracle",
            "perf",
            "--manifest",
            manifest.to_str().expect("manifest path should be utf8"),
            "--case",
            "no-such-case",
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        !output.status.success(),
        "unknown --case filter should fail closed"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("matched no corpus case"),
        "stderr should explain the empty filter"
    );
}
