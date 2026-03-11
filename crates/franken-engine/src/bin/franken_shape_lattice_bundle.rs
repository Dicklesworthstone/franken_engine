#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;

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
    let commands = vec![
        format!(
            "franken_shape_lattice_bundle --out-dir {}",
            out_dir.display()
        ),
        format!("cat {}/shape_lattice_manifest.json", out_dir.display()),
        format!("cat {}/run_manifest.json", out_dir.display()),
        format!("cat {}/trace_ids.json", out_dir.display()),
        format!(
            "jq '.transitions[].transition_kind' {}/shape_lattice_manifest.json",
            out_dir.display()
        ),
        "./scripts/e2e/rgc_shape_transition_lattice_replay.sh ci".to_string(),
    ];
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
