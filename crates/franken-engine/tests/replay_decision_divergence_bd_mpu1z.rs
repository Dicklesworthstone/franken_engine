//! bd-mpu1z (first slice): strict replay re-derives a run report's decisions.
//!
//! Reality check 2026-09-27 (clean main 3a690ee62): forging a run report's
//! evidence entry `chosen_action` (allow -> quarantine) or its top-level
//! `containment_action` left `frankenctl replay run --mode strict` at exit 0
//! with divergence_count 0. Replay compared only the IR3 hash, the unsigned
//! execution content and the randomness transcript. Re-execution is
//! deterministic, so every decision can be re-derived and compared without
//! trusting any key the report carries. Explicitly authenticated replay also
//! verifies the exact signed batch against a separately pinned runtime trust
//! snapshot before it executes any source. Trust enrollment remains external.

use frankenengine_engine::evidence_ledger::{
    EvidenceTrustSnapshot, LabEvidenceAuthority, RuntimeEvidenceAuthority,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn scratch_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_mpu1z_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn run_report(dir: &Path) -> PathBuf {
    let input = dir.join("program.js");
    let report = dir.join("program.report.json");
    let trust = dir.join("public-trust.json");
    fs::write(&input, "const answer = 40 + 2;\nconsole.log(answer);\n").expect("program");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8"),
            "--extension-id",
            "replay-decisions",
            "--out",
            report.to_str().expect("utf8"),
            "--emit-evidence-trust",
            trust.to_str().expect("utf8"),
        ])
        .output()
        .expect("frankenctl run should execute");
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    report
}

fn replay(report: &Path, mode: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            report.to_str().expect("utf8"),
            "--mode",
            mode,
        ])
        .output()
        .expect("frankenctl replay should execute")
}

fn read_trust(dir: &Path) -> (PathBuf, EvidenceTrustSnapshot, String) {
    let path = dir.join("public-trust.json");
    let snapshot: EvidenceTrustSnapshot =
        serde_json::from_slice(&fs::read(&path).expect("public trust")).expect("trust snapshot");
    let digest = snapshot
        .canonical_digest()
        .expect("valid public trust")
        .to_hex();
    (path, snapshot, digest)
}

fn authenticated_replay(report: &Path, trust: &Path, digest: &str, mode: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            report.to_str().expect("utf8"),
            "--mode",
            mode,
            "--trust-snapshot",
            trust.to_str().expect("utf8"),
            "--expected-trust-digest",
            digest,
        ])
        .output()
        .expect("authenticated replay should execute")
}

fn tamper(report: &Path, edit: impl FnOnce(&mut serde_json::Value)) -> PathBuf {
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(report).expect("report")).expect("json");
    edit(&mut value);
    let forged = report.with_extension("forged.json");
    fs::write(&forged, serde_json::to_vec_pretty(&value).expect("json")).expect("forged report");
    forged
}

fn other_action(action: &str) -> &'static str {
    if action == "quarantine" {
        "allow"
    } else {
        "quarantine"
    }
}

#[test]
fn untampered_report_replays_with_matching_decisions() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let output = replay(&report, "strict");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(summary["decisions_match"], true);
    assert_eq!(summary["divergence_count"], 0);
    assert_eq!(summary["evidence_authenticated"], false);
    assert!(summary.get("evidence_trust_snapshot_digest").is_none());
}

#[test]
fn forged_evidence_decision_is_a_strict_divergence() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let forged = tamper(&report, |value| {
        let chosen = &mut value["evidence_chain_artifact"]["entries"][0]["chosen_action"];
        let original = chosen["action_name"]
            .as_str()
            .expect("action name")
            .to_string();
        chosen["action_name"] = serde_json::Value::from(other_action(&original));
    });
    let output = replay(&forged, "strict");
    assert!(
        !output.status.success(),
        "a forged decision must not replay"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("strict re-execution divergence: evidence entry 0"),
        "{stderr}"
    );
}

#[test]
fn forged_containment_action_is_a_strict_divergence() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let forged = tamper(&report, |value| {
        let original = value["containment_action"]
            .as_str()
            .expect("containment action")
            .to_string();
        value["containment_action"] = serde_json::Value::from(other_action(&original));
    });
    let output = replay(&forged, "strict");
    assert!(
        !output.status.success(),
        "a forged containment action must not replay"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("re-executed containment action"),
        "{stderr}"
    );
}

#[test]
fn best_effort_replay_reports_the_decision_divergence() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let forged = tamper(&report, |value| {
        let chosen = &mut value["evidence_chain_artifact"]["entries"][0]["chosen_action"];
        chosen["expected_loss_millionths"] = serde_json::Value::from(123_456_789_i64);
    });
    let output = replay(&forged, "best-effort");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(summary["decisions_match"], false);
    assert_eq!(summary["complete"], false);
    assert!(summary["divergence_count"].as_u64().expect("count") >= 1);
}

#[test]
fn exported_runtime_trust_authenticates_a_cross_process_replay() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let (trust, snapshot, digest) = read_trust(&dir);
    let recorded: serde_json::Value =
        serde_json::from_slice(&fs::read(&report).expect("run report")).expect("report json");
    assert_eq!(recorded["evidence_trust_snapshot_digest"], digest);
    assert_eq!(snapshot.identities.len(), 1);
    let exported = fs::read_to_string(&trust).expect("public export");
    assert!(
        !exported.contains("signing_key"),
        "private keys must not be exported"
    );
    for mode in ["strict", "best-effort", "validate"] {
        let output = authenticated_replay(&report, &trust, &digest, mode);
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: serde_json::Value = serde_json::from_slice(&output.stdout).expect("summary");
        assert_eq!(summary["evidence_authenticated"], true);
        assert_eq!(summary["evidence_trust_snapshot_digest"], digest);
        assert_eq!(summary["decisions_match"], true);
        assert_eq!(summary["complete"], true);
        assert_eq!(summary["divergence_count"], 0);
    }
}

#[test]
fn authenticated_replay_rejects_exact_artifact_tampering_before_source_execution() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let (trust, _, digest) = read_trust(&dir);
    type Mutation = (&'static str, fn(&mut serde_json::Value));
    let mutations: &[Mutation] = &[
        ("entry signature", |v| {
            let byte = &mut v["evidence_chain_artifact"]["entries"][0]["signed_envelope"]["signature"]
                ["lower"][0];
            *byte = (byte.as_u64().expect("signature byte") ^ 1).into();
        }),
        ("receipt signature", |v| {
            let byte = &mut v["evidence_chain_artifact"]["receipt"]["signed_envelope"]["signature"]
                ["upper"][0];
            *byte = (byte.as_u64().expect("signature byte") ^ 1).into();
        }),
        ("replay input signature", |v| {
            let byte = &mut v["replay_input_signature"]["signature"]["lower"][0];
            *byte = (byte.as_u64().expect("signature byte") ^ 1).into();
        }),
        ("source code", |v| {
            v["replay_input"]["source"] = "while (".into();
        }),
        ("source location", |v| {
            v["replay_input"]["source_label"] = "another.js".into();
        }),
        ("module root", |v| {
            v["replay_input"]["module_root"] = "/".into();
        }),
        ("instruction budget", |v| {
            v["replay_input"]["instruction_budget"] = 9_000_000.into();
        }),
        ("heap budget", |v| {
            v["replay_input"]["max_heap_bytes"] = 999_999_999.into();
        }),
        ("module authority", |v| {
            v["replay_input"]["commonjs_entry"] = true.into();
        }),
        ("chain sequence", |v| {
            v["evidence_chain_artifact"]["receipt"]["links"][0]["sequence"] = 9.into();
        }),
        ("chain predecessor", |v| {
            v["evidence_chain_artifact"]["receipt"]["links"][0]["previous_chain_hash"] =
                "00".repeat(32).into();
        }),
        ("missing entry", |v| {
            v["evidence_chain_artifact"]["entries"]
                .as_array_mut()
                .expect("entries")
                .pop();
        }),
        ("duplicated entry", |v| {
            let entries = v["evidence_chain_artifact"]["entries"]
                .as_array_mut()
                .expect("entries");
            entries.push(entries[0].clone());
        }),
        ("signed metadata", |v| {
            v["evidence_chain_artifact"]["entries"][0]["metadata"]["extension_id"] =
                "forged".into();
        }),
        ("run coordinate", |v| {
            v["trace_id"] = "another-run".into();
        }),
        ("decision coordinate", |v| {
            v["decision_id"] = "another-decision".into();
        }),
        ("ledger coordinate", |v| {
            v["evidence_ledger_id"] = "another-ledger".into();
        }),
        ("instance coordinate", |v| {
            v["evidence_chain_instance_id"] = "another-instance".into();
        }),
        ("reported chain head", |v| {
            v["evidence_chain_head"] = "00".repeat(32).into();
        }),
        ("policy epoch", |v| {
            v["replay_input"]["policy_epoch"] = 2.into();
        }),
        ("policy id", |v| {
            v["policy_id"] = "other-policy".into();
            v["replay_input"]["policy_id"] = "other-policy".into();
        }),
        ("IR4 commitment", |v| {
            v["ir4_witness_hash"] = "00".repeat(32).into();
        }),
    ];
    for (name, edit) in mutations {
        let forged = tamper(&report, edit);
        for mode in ["strict", "best-effort", "validate"] {
            let output = authenticated_replay(&forged, &trust, &digest, mode);
            assert!(!output.status.success(), "{name} must fail in {mode}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("run evidence authentication failed before re-execution"),
                "{name}/{mode}: {stderr}"
            );
        }
    }
}

#[test]
fn older_reports_do_not_silently_downgrade_authenticated_replay() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let (trust, _, digest) = read_trust(&dir);
    let older = tamper(&report, |value| {
        value
            .as_object_mut()
            .expect("report")
            .remove("replay_input_signature");
    });
    let output = replay(&older, "strict");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).expect("summary");
    assert_eq!(summary["evidence_authenticated"], false);
    let output = authenticated_replay(&older, &trust, &digest, "strict");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires a signed replay input"));
}

#[test]
fn authenticated_replay_does_not_trust_a_replacement_key_or_report_supplied_pin() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let (trust, _, digest) = read_trust(&dir);
    let wrong_pin = "00".repeat(32);
    let forged_pin = tamper(&report, |value| {
        value["evidence_trust_snapshot_digest"] = wrong_pin.clone().into();
    });
    let output = authenticated_replay(&forged_pin, &trust, &wrong_pin, "strict");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("operator's independent pin"));
    // The original independently held pin remains sufficient even if an
    // untrusted report changes the informational export digest.
    let output = authenticated_replay(&forged_pin, &trust, &digest, "strict");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let other_dir = scratch_dir();
    run_report(&other_dir);
    let (other_trust, _, other_digest) = read_trust(&other_dir);
    let output = authenticated_replay(&report, &other_trust, &other_digest, "strict");
    assert!(
        !output.status.success(),
        "another runtime's key must not authenticate this report"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("unauthorized evidence producer/key"));
}

#[test]
fn authenticated_replay_enforces_external_rotation_and_epoch_windows() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let (_, original, _) = read_trust(&dir);
    let identity = original.identities[0].clone();
    let epoch = original.current_epoch.as_u64();
    assert!(epoch > 0, "fixture needs an earlier verifier epoch");

    let mut stale = original.clone();
    stale.current_epoch = SecurityEpoch::from_raw(epoch - 1);
    let stale_digest = stale
        .canonical_digest()
        .expect("valid old snapshot")
        .to_hex();
    let stale_path = dir.join("stale-trust.json");
    fs::write(&stale_path, serde_json::to_vec(&stale).expect("snapshot")).expect("stale trust");
    let output = authenticated_replay(&report, &stale_path, &stale_digest, "strict");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("after registry epoch"));

    for (activation, allowed) in [(epoch, false), (epoch + 1, true)] {
        let successor = RuntimeEvidenceAuthority::generate_runtime_owned(
            identity.producer_id.clone(),
            SecurityEpoch::from_raw(activation),
            2,
            Some(identity.key_provenance.key_id.clone()),
        )
        .expect("successor identity");
        let rotated = EvidenceTrustSnapshot::from_runtime_identities(
            SecurityEpoch::from_raw(epoch + 1),
            [identity.clone(), successor.verification_identity()],
        )
        .expect("external complete lineage");
        let path = dir.join(format!("rotated-{activation}.json"));
        fs::write(&path, serde_json::to_vec(&rotated).expect("snapshot")).expect("rotated trust");
        let digest = rotated.canonical_digest().expect("digest").to_hex();
        let output = authenticated_replay(&report, &path, &digest, "strict");
        assert_eq!(
            output.status.success(),
            allowed,
            "activation {activation}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if !allowed {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("retired at successor activation")
            );
        }
    }
}

#[test]
fn authenticated_replay_rejects_malformed_or_nonruntime_external_trust() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let (_, snapshot, digest) = read_trust(&dir);
    let lab = LabEvidenceAuthority::deterministic_fixture(
        "replay-lab-producer",
        "replay-lab-fixture",
        snapshot.current_epoch,
    )
    .expect("lab fixture");
    let mut unsupported = snapshot.clone();
    unsupported.format_version = 0;
    let mut duplicated = snapshot.clone();
    duplicated.identities.push(duplicated.identities[0].clone());
    let mut incomplete = snapshot.clone();
    incomplete.producer_lineage_tips.clear();
    let mut nonruntime = snapshot;
    nonruntime.identities = vec![lab.verification_identity()];
    nonruntime.producer_lineage_tips = [(
        lab.producer_id().to_string(),
        lab.key_provenance().key_id.clone(),
    )]
    .into();
    for (name, invalid) in [
        ("unsupported", unsupported),
        ("duplicate", duplicated),
        ("incomplete", incomplete),
        ("lab", nonruntime),
    ] {
        let path = dir.join(format!("invalid-{name}.json"));
        fs::write(&path, serde_json::to_vec(&invalid).expect("snapshot")).expect("invalid trust");
        let output = authenticated_replay(&report, &path, &digest, "strict");
        assert!(!output.status.success(), "{name} snapshot must fail");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("invalid runtime trust snapshot"),
            "{name}: {stderr}"
        );
    }
}

#[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
mod configured_runtime_identity {
    use super::*;
    use frankenengine_engine::signature_preimage::SigningKey;
    use std::os::unix::fs::PermissionsExt;

    fn provision(dir: &Path) -> (PathBuf, PathBuf, String) {
        let key = dir.join("runtime.seed");
        let trust = dir.join("runtime.public.json");
        let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args([
                "evidence",
                "init",
                "--producer-id",
                "stable-runtime",
                "--key-out",
            ])
            .arg(&key)
            .arg("--trust-out")
            .arg(&trust)
            .args(["--epoch", "7"])
            .output()
            .expect("identity initialization CLI");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let initialized: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("public initialization output");
        assert_eq!(initialized["producer_id"], "stable-runtime");
        assert_eq!(initialized["epoch"], 7);
        assert_eq!(fs::metadata(&key).expect("private key").len(), 32);
        assert_eq!(
            fs::metadata(&key)
                .expect("private permissions")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        let digest = initialized["evidence_trust_snapshot_digest"]
            .as_str()
            .expect("digest")
            .to_string();
        (key, trust, digest)
    }

    fn configured_run(
        input: &Path,
        report: &Path,
        key: &Path,
        trust: &Path,
        digest: &str,
        export: &Path,
    ) -> Output {
        Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args(["run", "--input"])
            .arg(input)
            .args(["--extension-id", "configured-replay", "--out"])
            .arg(report)
            .arg("--evidence-key-file")
            .arg(key)
            .args([
                "--evidence-producer-id",
                "stable-runtime",
                "--trust-snapshot",
            ])
            .arg(trust)
            .args(["--expected-trust-digest", digest, "--emit-evidence-trust"])
            .arg(export)
            .output()
            .expect("configured run CLI")
    }

    #[test]
    fn initialized_identity_authenticates_independent_runs_under_one_preexisting_pin() {
        let dir = scratch_dir();
        let (key, trust, digest) = provision(&dir);
        let initial: EvidenceTrustSnapshot =
            serde_json::from_slice(&fs::read(&trust).expect("trust")).expect("snapshot");
        let input = dir.join("program.js");
        fs::write(&input, "console.log(40 + 2);\n").expect("program");
        let mut previous_instance = None;
        for invocation in 0..2 {
            let report = dir.join(format!("run-{invocation}.json"));
            let export = dir.join(format!("trust-{invocation}.json"));
            let output = configured_run(&input, &report, &key, &trust, &digest, &export);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let recorded: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("run output");
            assert_eq!(recorded["replay_input"]["policy_epoch"], 7);
            assert_eq!(recorded["evidence_trust_snapshot_digest"], digest);
            assert_eq!(
                recorded["replay_input_signature"]["producer_id"],
                "stable-runtime"
            );
            assert_eq!(
                recorded["replay_input_signature"]["key_provenance"]["key_id"],
                initial.identities[0].key_provenance.key_id
            );
            let instance = recorded["evidence_chain_instance_id"]
                .as_str()
                .expect("instance")
                .to_string();
            assert_ne!(previous_instance.as_ref(), Some(&instance));
            previous_instance = Some(instance);
            let exported: EvidenceTrustSnapshot =
                serde_json::from_slice(&fs::read(export).expect("export")).expect("snapshot");
            assert_eq!(exported, initial);
            let replay = authenticated_replay(&report, &trust, &digest, "strict");
            assert!(
                replay.status.success(),
                "{}",
                String::from_utf8_lossy(&replay.stderr)
            );
            let result: serde_json::Value =
                serde_json::from_slice(&replay.stdout).expect("replay output");
            assert_eq!(result["evidence_authenticated"], true);
            assert_eq!(result["complete"], true);
        }
    }

    #[test]
    fn configured_rotation_preserves_complete_trust_and_rejects_retired_private_keys() {
        let dir = scratch_dir();
        let (old_key, initial_path, _) = provision(&dir);
        let initial: EvidenceTrustSnapshot =
            serde_json::from_slice(&fs::read(&initial_path).expect("initial trust"))
                .expect("snapshot");
        let successor = RuntimeEvidenceAuthority::from_signing_key(
            "stable-runtime",
            SigningKey::from_bytes([0x64; 32]).expect("successor seed"),
            SecurityEpoch::from_raw(8),
            2,
            Some(initial.identities[0].key_provenance.key_id.clone()),
        )
        .expect("successor");
        let complete = EvidenceTrustSnapshot::from_runtime_identities(
            SecurityEpoch::from_raw(8),
            [
                initial.identities[0].clone(),
                successor.verification_identity(),
            ],
        )
        .expect("complete rotated registry");
        let trust = dir.join("rotated.public.json");
        fs::write(&trust, serde_json::to_vec(&complete).expect("snapshot"))
            .expect("public rotation");
        let digest = complete
            .canonical_digest()
            .expect("independent new pin")
            .to_hex();
        let key = dir.join("successor.seed");
        fs::write(&key, [0x64; 32]).expect("successor private file");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("private permissions");
        let input = dir.join("program.js");
        fs::write(&input, "console.log(42);\n").expect("program");
        let report = dir.join("rotated-run.json");
        let export = dir.join("retained-trust.json");
        let output = configured_run(&input, &report, &key, &trust, &digest, &export);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let exported: EvidenceTrustSnapshot =
            serde_json::from_slice(&fs::read(&export).expect("export")).expect("snapshot");
        assert_eq!(exported, complete);
        assert_eq!(exported.identities.len(), 2);
        let replay = authenticated_replay(&report, &trust, &digest, "strict");
        assert!(
            replay.status.success(),
            "{}",
            String::from_utf8_lossy(&replay.stderr)
        );

        let denied = configured_run(
            &dir.join("missing-source.js"),
            &dir.join("denied.json"),
            &old_key,
            &trust,
            &digest,
            &dir.join("denied-trust.json"),
        );
        assert!(!denied.status.success());
        let stderr = String::from_utf8_lossy(&denied.stderr);
        assert!(
            stderr.contains("configured runtime evidence authority rejected before execution"),
            "{stderr}"
        );
        assert!(
            stderr.contains("retired at successor activation"),
            "{stderr}"
        );
        assert!(!dir.join("denied.json").exists());
        assert!(!dir.join("denied-trust.json").exists());
    }
}
