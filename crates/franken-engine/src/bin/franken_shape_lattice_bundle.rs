#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::bytecode_vm::{BytecodeVm, Instruction, Program, Register, Value};
use frankenengine_engine::shape_transition_algebra::{
    COMPONENT, ShapeLatticeBundle, emit_shape_lattice_bundle,
};
use serde::Serialize;

const OUTPUT_SCHEMA_VERSION: &str = "frankenengine.shape-lattice.bundle-output.v1";
const TRACE_ID: &str = "trace-rgc-606a-shape-lattice";
const DECISION_ID: &str = "decision-rgc-606a-shape-lattice";
const POLICY_ID: &str = "policy-rgc-606a-shape-lattice";

enum CliAction {
    Help,
    Run { out_dir: PathBuf },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    component: String,
    out_dir: String,
    shape_lattice_manifest: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    trace_ids: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    state_hash: String,
    result_kind: String,
    shape_count: usize,
    transition_count: usize,
    receipt_count: usize,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let out_dir = match parse_args(&args[1..])? {
        CliAction::Help => {
            println!("{}", help_text());
            return Ok(());
        }
        CliAction::Run { out_dir } => out_dir,
    };

    fs::create_dir_all(&out_dir)
        .map_err(|error| format!("failed to create output directory: {error}"))?;

    let report = run_scenario()?;
    let commands = bundle_command_lines(&args, &out_dir);
    let bundle = ShapeLatticeBundle {
        manifest: report.shape_lattice.clone(),
        trace_events: report.shape_trace.clone(),
        trace_ids: vec![TRACE_ID.to_string()],
        decision_ids: vec![DECISION_ID.to_string()],
        policy_ids: vec![POLICY_ID.to_string()],
        commands,
    };
    let emitted = emit_shape_lattice_bundle(&out_dir, &bundle)
        .map_err(|error| format!("failed to emit shape lattice bundle: {error}"))?;

    let output = CommandOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        out_dir: out_dir.display().to_string(),
        shape_lattice_manifest: emitted.shape_lattice_manifest_path.display().to_string(),
        run_manifest: emitted.run_manifest_path.display().to_string(),
        events_jsonl: emitted.events_path.display().to_string(),
        commands_txt: emitted.commands_path.display().to_string(),
        trace_ids: emitted.trace_ids_path.display().to_string(),
        trace_id: TRACE_ID.to_string(),
        decision_id: DECISION_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        state_hash: report.state_hash,
        result_kind: value_kind(&report.result).to_string(),
        shape_count: report.shape_lattice.shapes.len(),
        transition_count: report.shape_lattice.transitions.len(),
        receipt_count: report.shape_trace.len(),
    };

    let rendered = serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}

fn parse_args(args: &[String]) -> Result<CliAction, String> {
    if args.is_empty() {
        return Err(help_text());
    }

    let mut out_dir: Option<PathBuf> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => return Ok(CliAction::Help),
            "--out-dir" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("--out-dir requires a path".to_string());
                };
                out_dir = Some(PathBuf::from(value));
                index += 2;
            }
            other => {
                return Err(format!(
                    "unrecognized argument `{other}`\n\n{}",
                    help_text()
                ));
            }
        }
    }

    out_dir
        .map(|out_dir| CliAction::Run { out_dir })
        .ok_or_else(|| format!("missing required --out-dir\n\n{}", help_text()))
}

fn help_text() -> String {
    "Usage: franken_shape_lattice_bundle --out-dir <DIR>".to_string()
}

fn bundle_command_lines(args: &[String], out_dir: &Path) -> Vec<String> {
    let replay_run_dir = shell_escape_arg(&out_dir.display().to_string());
    vec![
        render_command_transcript(args),
        replay_command_for_bundle(),
        format!(
            "cat {}",
            shell_escape_arg(
                &out_dir
                    .join("shape_lattice_manifest.json")
                    .display()
                    .to_string()
            )
        ),
        format!(
            "cat {}",
            shell_escape_arg(&out_dir.join("run_manifest.json").display().to_string())
        ),
        format!(
            "cat {}",
            shell_escape_arg(&out_dir.join("trace_ids.json").display().to_string())
        ),
        format!(
            "jq '.transitions[].transition_kind' {}",
            shell_escape_arg(
                &out_dir
                    .join("shape_lattice_manifest.json")
                    .display()
                    .to_string()
            )
        ),
        format!(
            "RGC_SHAPE_TRANSITION_LATTICE_REPLAY_RUN_DIR={replay_run_dir} ./scripts/e2e/rgc_shape_transition_lattice_replay.sh"
        ),
    ]
}

fn render_command_transcript(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_escape_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_escape_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }

    if arg.bytes().all(|byte| {
        matches!(
            byte,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'/'
                | b'.'
                | b'_'
                | b':'
                | b'-'
                | b'='
                | b'+'
        )
    }) {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\"'\"'"))
}

fn replay_command_for_bundle() -> String {
    "rch exec -- cargo run -p frankenengine-engine --bin franken_shape_lattice_bundle -- --out-dir <DIR>"
        .to_string()
}

fn run_scenario() -> Result<frankenengine_engine::bytecode_vm::ExecutionReport, String> {
    let program = Program {
        constants: vec![Value::Int(10), Value::Int(20), Value::Int(30)],
        property_pool: vec!["alpha".to_string(), "beta".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 1,
                value: r(1),
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 2,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadPropCached {
                dst: r(3),
                object: r(0),
                property_index: 1,
            },
            Instruction::Return { src: r(3) },
        ],
    };

    let mut vm = BytecodeVm::new(TRACE_ID, 8, 64);
    vm.execute(&program)
        .map_err(|error| format!("shape lattice scenario failed: {error:?}"))
}

fn r(index: u16) -> Register {
    Register(index)
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Undefined => "undefined",
        Value::Bool(_) => "bool",
        Value::Int(_) => "int",
        Value::Object(_) => "object",
    }
}
