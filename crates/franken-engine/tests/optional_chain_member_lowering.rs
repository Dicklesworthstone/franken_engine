use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(prefix: &str, ext: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let unique = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}_{nanos}_{unique}.{ext}"))
}

fn write_source(path: &PathBuf, source: &str) {
    fs::write(path, source).expect("source fixture should write");
}

fn parse_stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout should be valid json")
}

fn json_contains_object_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(map) => {
            map.contains_key(key)
                || map
                    .values()
                    .any(|nested| json_contains_object_key(nested, key))
        }
        Value::Array(items) => items
            .iter()
            .any(|nested| json_contains_object_key(nested, key)),
        _ => false,
    }
}

#[test]
fn library_lowering_emits_typed_nullish_guards_for_optional_member_paths() {
    let parser = CanonicalEs2020Parser;
    let ctx = LoweringContext::new(
        "trace-optional-chain-member-lowering",
        "decision-optional-chain-member-lowering",
        "policy-optional-chain-member-lowering",
    );

    for (source_label, source, expected_nullish_guards) in [
        ("member", "const obj = { value: 7 }; obj?.value;", 1usize),
        (
            "computed",
            "const key = \"value\"; const obj = { value: 7 }; obj?.[key];",
            1usize,
        ),
        (
            "nested",
            "const obj = { nested: { value: 7 } }; obj?.nested?.value;",
            2usize,
        ),
        (
            "grouped",
            "const obj = { nested: { value: 7 } }; (obj?.nested).value;",
            1usize,
        ),
    ] {
        let tree = parser
            .parse_with_options(source, ParseGoal::Script, &ParserOptions::default())
            .expect("source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("optional-chain-{source_label}.js"));
        let lowering = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

        let jump_count = lowering
            .ir3
            .instructions
            .iter()
            .filter(|instr| matches!(instr, Ir3Instruction::JumpIfNullish { .. }))
            .count();
        assert_eq!(
            jump_count, expected_nullish_guards,
            "unexpected JumpIfNullish count for specimen `{source_label}`"
        );
        assert!(
            lowering
                .ir3
                .instructions
                .iter()
                .any(|instr| matches!(instr, Ir3Instruction::GetProperty { .. })),
            "specimen `{source_label}` should still lower into real property reads"
        );
    }
}

#[test]
fn frankenctl_compile_accepts_optional_member_and_computed_member_sources() {
    for (specimen_id, source) in [
        ("member", "const obj = { value: 7 }; obj?.value;\n"),
        (
            "computed",
            "const key = \"value\"; const obj = { value: 7 }; obj?.[key];\n",
        ),
        (
            "nested",
            "const obj = { nested: { value: 7 } }; obj?.nested?.value;\n",
        ),
        (
            "grouped",
            "const obj = { nested: { value: 7 } }; (obj?.nested).value;\n",
        ),
    ] {
        let source_path = temp_path(&format!("optional_chain_{specimen_id}_source"), "js");
        let artifact_path = temp_path(&format!("optional_chain_{specimen_id}_artifact"), "json");
        write_source(&source_path, source);

        let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args([
                "compile",
                "--input",
                source_path
                    .to_str()
                    .expect("source path should be valid utf8"),
                "--out",
                artifact_path
                    .to_str()
                    .expect("artifact path should be valid utf8"),
                "--goal",
                "script",
                "--trace-id",
                &format!("trace-{specimen_id}"),
                "--decision-id",
                &format!("decision-{specimen_id}"),
                "--policy-id",
                "policy-optional-chain-member-lowering",
            ])
            .output()
            .expect("compile command should execute");

        assert!(
            output.status.success(),
            "frankenctl compile failed for `{specimen_id}` with stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout_json = parse_stdout_json(&output);
        assert_eq!(stdout_json["parse_goal"].as_str(), Some("script"));
        assert_eq!(
            stdout_json["artifact_path"].as_str(),
            artifact_path.to_str(),
            "compile output should reference the emitted artifact path"
        );

        let artifact_json: Value = serde_json::from_slice(
            &fs::read(&artifact_path).expect("compile artifact should be readable"),
        )
        .expect("compile artifact should parse as json");
        assert!(
            json_contains_object_key(&artifact_json, "JumpIfNullish"),
            "compile artifact for `{specimen_id}` should include typed nullish-guard IR"
        );

        let _ = fs::remove_file(source_path);
        let _ = fs::remove_file(artifact_path);
    }
}

#[test]
fn frankenctl_run_executes_optional_member_and_computed_member_sources() {
    for (specimen_id, source, expected_execution_value) in [
        (
            "nullish_member",
            "let obj = null; obj?.value;\n",
            "undefined",
        ),
        (
            "live_computed",
            "let key = \"value\"; let obj = { value: 7 }; obj?.[key];\n",
            "7",
        ),
        (
            "skipped_key_side_effect",
            "let probe = 0; let obj = null; obj?.[(probe = 1)]; probe;\n",
            "0",
        ),
    ] {
        let source_path = temp_path(&format!("optional_chain_{specimen_id}_run_source"), "js");
        let report_path = temp_path(&format!("optional_chain_{specimen_id}_run_report"), "json");
        write_source(&source_path, source);

        let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args([
                "run",
                "--input",
                source_path
                    .to_str()
                    .expect("source path should be valid utf8"),
                "--extension-id",
                &format!("ext-{specimen_id}"),
                "--out",
                report_path
                    .to_str()
                    .expect("report path should be valid utf8"),
            ])
            .output()
            .expect("run command should execute");

        assert!(
            output.status.success(),
            "frankenctl run failed for `{specimen_id}` with stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout_json = parse_stdout_json(&output);
        assert!(stdout_json["lane"].as_str().is_some());
        assert!(stdout_json["containment_action"].as_str().is_some());
        assert_eq!(
            stdout_json["execution_value"].as_str(),
            Some(expected_execution_value),
            "stdout execution value mismatch for `{specimen_id}`"
        );

        let report_json: Value =
            serde_json::from_slice(&fs::read(&report_path).expect("run report should be readable"))
                .expect("run report should parse as json");
        assert_eq!(
            report_json["extension_id"].as_str(),
            Some(format!("ext-{specimen_id}").as_str()),
            "run report should preserve the extension id"
        );
        assert_eq!(
            report_json["execution_value"].as_str(),
            Some(expected_execution_value),
            "report execution value mismatch for `{specimen_id}`"
        );

        let _ = fs::remove_file(source_path);
        let _ = fs::remove_file(report_path);
    }
}

#[test]
fn frankenctl_run_preserves_grouped_optional_chain_scope() {
    let source_path = temp_path("optional_chain_grouped_scope_source", "js");
    write_source(&source_path, "let obj = null; (obj?.nested).value;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            source_path
                .to_str()
                .expect("grouped scope source path should be valid utf8"),
            "--extension-id",
            "ext-grouped-scope",
        ])
        .output()
        .expect("run command should execute");

    assert!(
        !output.status.success(),
        "grouped optional chain should fail once the follow-on plain member reads from undefined"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("type error: expected object, got undefined"),
        "grouped scope failure should surface the shipped TypeError; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_file(source_path);
}
