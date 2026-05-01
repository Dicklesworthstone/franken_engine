#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Error as IoError, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::deterministic_sim_scheduler::{
    SchedulerPolicy, SimEventKind, SimPriority, SimScheduler, SIM_SCHEDULER_BEAD_ID,
    SIM_SCHEDULER_SCHEMA_VERSION,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::Serialize;
use serde_json::{json, Value};

type DynError = Box<dyn Error>;

#[derive(Debug)]
struct Cli {
    out_dir: PathBuf,
    seed: u64,
    trials: u64,
}

#[derive(Clone, Debug)]
struct ScenarioEvent {
    kind: SimEventKind,
    priority: SimPriority,
    delay_ticks: u64,
    source: &'static str,
    seed_offset: u64,
}

#[derive(Clone, Debug)]
struct Scenario {
    id: &'static str,
    description: &'static str,
    policy: SchedulerPolicy,
    events: Vec<ScenarioEvent>,
}

#[derive(Debug, Serialize)]
struct ArtifactDescriptor {
    kind: String,
    path: String,
    sha256: String,
    bytes: usize,
}

fn invalid_input(message: impl Into<String>) -> IoError {
    IoError::new(ErrorKind::InvalidInput, message.into())
}

fn default_out_dir() -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    PathBuf::from("artifacts")
        .join("deterministic_sim_scheduler")
        .join(format!("run-{now}-{}", std::process::id()))
}

fn parse_args() -> Result<Cli, DynError> {
    let mut out_dir = None;
    let mut seed = 803_u64;
    let mut trials = 3_u64;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--out-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("--out-dir requires a value"))?;
                out_dir = Some(PathBuf::from(value));
            }
            "--seed" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("--seed requires a value"))?;
                seed = value.parse::<u64>()?;
            }
            "--trials" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("--trials requires a value"))?;
                trials = value.parse::<u64>()?;
            }
            _ if arg.starts_with("--out-dir=") => {
                out_dir = Some(PathBuf::from(
                    arg.strip_prefix("--out-dir=").expect("prefix checked"),
                ));
            }
            _ if arg.starts_with("--seed=") => {
                seed = arg
                    .strip_prefix("--seed=")
                    .expect("prefix checked")
                    .parse::<u64>()?;
            }
            _ if arg.starts_with("--trials=") => {
                trials = arg
                    .strip_prefix("--trials=")
                    .expect("prefix checked")
                    .parse::<u64>()?;
            }
            _ => return Err(invalid_input(format!("unknown argument: {arg}")).into()),
        }
    }

    if trials == 0 {
        return Err(invalid_input("--trials must be greater than zero").into());
    }

    Ok(Cli {
        out_dir: out_dir.unwrap_or_else(default_out_dir),
        seed,
        trials,
    })
}

fn print_help() {
    println!(
        "franken_deterministic_sim_scheduler_artifacts\n\
         \n\
         Emits deterministic simulation scheduler proof artifacts.\n\
         \n\
         Options:\n\
           --out-dir <path>   Output directory; default artifacts/deterministic_sim_scheduler/run-<epoch>-<pid>\n\
           --seed <u64>       Base deterministic seed; default 803\n\
           --trials <u64>     Repeated replay trials for nondeterminism detection; default 3"
    );
}

fn scenarios(base_seed: u64) -> Vec<Scenario> {
    let mut sparse_policy = SchedulerPolicy {
        max_ticks: 32,
        max_events_per_tick: 16,
        gc_interval_ticks: 0,
        ..SchedulerPolicy::default()
    };

    let constrained_policy = SchedulerPolicy {
        max_ticks: 32,
        max_events_per_tick: 2,
        gc_interval_ticks: 0,
        ..SchedulerPolicy::default()
    };

    sparse_policy.enable_timer_coalescing = true;

    vec![
        Scenario {
            id: "event_module_cache_controller",
            description:
                "mixed event-loop, module, cache, timer, hostcall, and controller interactions",
            policy: sparse_policy,
            events: vec![
                ScenarioEvent {
                    kind: SimEventKind::PromiseSettle,
                    priority: SimPriority::Microtask,
                    delay_ticks: 0,
                    source: "promise-settle",
                    seed_offset: base_seed,
                },
                ScenarioEvent {
                    kind: SimEventKind::ModuleLoad,
                    priority: SimPriority::HighPriority,
                    delay_ticks: 0,
                    source: "module-load",
                    seed_offset: base_seed + 1,
                },
                ScenarioEvent {
                    kind: SimEventKind::CacheMiss,
                    priority: SimPriority::Normal,
                    delay_ticks: 1,
                    source: "cache-miss",
                    seed_offset: base_seed + 2,
                },
                ScenarioEvent {
                    kind: SimEventKind::TimerFire,
                    priority: SimPriority::Normal,
                    delay_ticks: 2,
                    source: "timer-fire",
                    seed_offset: base_seed + 3,
                },
                ScenarioEvent {
                    kind: SimEventKind::ControllerDecision,
                    priority: SimPriority::HighPriority,
                    delay_ticks: 2,
                    source: "controller-decision",
                    seed_offset: base_seed + 4,
                },
                ScenarioEvent {
                    kind: SimEventKind::CacheEvict,
                    priority: SimPriority::LowPriority,
                    delay_ticks: 3,
                    source: "cache-evict",
                    seed_offset: base_seed + 5,
                },
                ScenarioEvent {
                    kind: SimEventKind::HostcallInvoke,
                    priority: SimPriority::Idle,
                    delay_ticks: 4,
                    source: "hostcall",
                    seed_offset: base_seed + 6,
                },
            ],
        },
        Scenario {
            id: "budget_spillover_requeue",
            description: "per-tick dispatch budget forces deterministic spillover into later ticks",
            policy: constrained_policy,
            events: vec![
                ScenarioEvent {
                    kind: SimEventKind::CacheHit,
                    priority: SimPriority::Normal,
                    delay_ticks: 0,
                    source: "cache-hit-a",
                    seed_offset: base_seed + 100,
                },
                ScenarioEvent {
                    kind: SimEventKind::CacheMiss,
                    priority: SimPriority::Normal,
                    delay_ticks: 0,
                    source: "cache-miss-b",
                    seed_offset: base_seed + 101,
                },
                ScenarioEvent {
                    kind: SimEventKind::ModuleResolve,
                    priority: SimPriority::HighPriority,
                    delay_ticks: 0,
                    source: "module-resolve-c",
                    seed_offset: base_seed + 102,
                },
                ScenarioEvent {
                    kind: SimEventKind::MicrotaskDrain,
                    priority: SimPriority::Microtask,
                    delay_ticks: 0,
                    source: "microtask-d",
                    seed_offset: base_seed + 103,
                },
                ScenarioEvent {
                    kind: SimEventKind::ControllerDecision,
                    priority: SimPriority::HighPriority,
                    delay_ticks: 0,
                    source: "controller-e",
                    seed_offset: base_seed + 104,
                },
            ],
        },
    ]
}

fn run_scenario(scenario: &Scenario) -> (SimScheduler, Value) {
    let mut scheduler = SimScheduler::new(scenario.policy.clone(), SecurityEpoch::from_raw(803));

    for event in &scenario.events {
        scheduler.schedule(
            event.kind,
            event.priority,
            event.delay_ticks,
            event.source,
            event.seed_offset,
        );
    }

    let summary = scheduler.run_to_completion();
    let replay_hash = scheduler.replay_log.content_hash();
    let dispatch_log = scheduler
        .dispatch_log
        .iter()
        .map(|outcome| {
            json!({
                "tick": outcome.tick,
                "events_dispatched": outcome.events_dispatched,
                "microtasks_drained": outcome.microtasks_drained,
                "pending_count": outcome.pending_count,
            })
        })
        .collect::<Vec<_>>();

    let scenario_report = json!({
        "scenario_id": scenario.id,
        "description": scenario.description,
        "total_ticks": summary.total_ticks,
        "total_events": summary.total_events,
        "events_by_kind": summary.events_by_kind,
        "events_by_priority": summary.events_by_priority,
        "dispatch_content_hash": summary.content_hash.to_hex(),
        "replay_content_hash": replay_hash.to_hex(),
        "pending_after_completion": scheduler.pending_count(),
        "dispatch_log": dispatch_log,
    });

    (scheduler, scenario_report)
}

fn artifact_path(out_dir: &Path, name: &str) -> PathBuf {
    out_dir.join(name)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<ArtifactDescriptor, DynError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    Ok(ArtifactDescriptor {
        kind: path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("artifact")
            .to_string(),
        path: path.display().to_string(),
        sha256: ContentHash::compute(bytes).to_hex(),
        bytes: bytes.len(),
    })
}

fn write_json<T: Serialize>(
    out_dir: &Path,
    name: &str,
    value: &T,
) -> Result<ArtifactDescriptor, DynError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_new(&artifact_path(out_dir, name), &bytes)
}

fn write_text(out_dir: &Path, name: &str, content: &str) -> Result<ArtifactDescriptor, DynError> {
    write_new(&artifact_path(out_dir, name), content.as_bytes())
}

fn write_jsonl(
    out_dir: &Path,
    name: &str,
    values: &[Value],
) -> Result<ArtifactDescriptor, DynError> {
    let mut content = String::new();
    for value in values {
        content.push_str(&serde_json::to_string(value)?);
        content.push('\n');
    }
    write_text(out_dir, name, &content)
}

fn scenario_catalog(scenarios: &[Scenario]) -> Value {
    let scenario_values = scenarios
        .iter()
        .map(|scenario| {
            let events = scenario
                .events
                .iter()
                .map(|event| {
                    json!({
                        "kind": event.kind.as_str(),
                        "priority": event.priority.as_str(),
                        "delay_ticks": event.delay_ticks,
                        "source": event.source,
                        "deterministic_seed": event.seed_offset,
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "scenario_id": scenario.id,
                "description": scenario.description,
                "policy": scenario.policy,
                "events": events,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "schema_version": "franken-engine.simulation-schedule-catalog.v1",
        "scheduler_schema_version": SIM_SCHEDULER_SCHEMA_VERSION,
        "bead_id": SIM_SCHEDULER_BEAD_ID,
        "scenario_count": scenario_values.len(),
        "stable_corpus_version": "rgc-803c-sim-scheduler-corpus-v1",
        "scenarios": scenario_values,
    })
}

fn oracle_matrix(scenario_reports: &[Value], trials: u64, nondeterminism_detected: bool) -> Value {
    let invariants = scenario_reports
        .iter()
        .map(|report| {
            let scenario_id = report
                .get("scenario_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let pending = report
                .get("pending_after_completion")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX);
            let total_events = report
                .get("total_events")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            json!({
                "scenario_id": scenario_id,
                "checks": [
                    {
                        "name": "all_reachable_events_dispatched",
                        "expected": 0,
                        "actual_pending": pending,
                        "outcome": if pending == 0 { "pass" } else { "fail" }
                    },
                    {
                        "name": "nonempty_scenario_dispatch",
                        "expected": "total_events > 0",
                        "actual_total_events": total_events,
                        "outcome": if total_events > 0 { "pass" } else { "fail" }
                    }
                ]
            })
        })
        .collect::<Vec<_>>();

    json!({
        "schema_version": "franken-engine.simulation-oracle-matrix.v1",
        "bead_id": SIM_SCHEDULER_BEAD_ID,
        "trials": trials,
        "nondeterminism_detected": nondeterminism_detected,
        "overall_outcome": if nondeterminism_detected { "fail" } else { "pass" },
        "invariants": invariants,
    })
}

fn build_nondeterminism_trace(scenarios: &[Scenario], trials: u64) -> (Vec<Value>, bool) {
    let mut rows = Vec::new();
    let mut hashes_by_scenario: BTreeMap<&str, String> = BTreeMap::new();
    let mut nondeterminism_detected = false;

    for trial in 0..trials {
        for scenario in scenarios {
            let (scheduler, report) = run_scenario(scenario);
            let replay_hash = scheduler.replay_log.content_hash().to_hex();
            let dispatch_hash = report
                .get("dispatch_content_hash")
                .and_then(Value::as_str)
                .unwrap_or("missing")
                .to_string();
            let prior = hashes_by_scenario
                .entry(scenario.id)
                .or_insert_with(|| replay_hash.clone());
            let outcome = if *prior == replay_hash {
                "pass"
            } else {
                nondeterminism_detected = true;
                "fail"
            };

            rows.push(json!({
                "schema_version": "franken-engine.simulated-nondeterminism-trace.v1",
                "trial": trial,
                "scenario_id": scenario.id,
                "dispatch_content_hash": dispatch_hash,
                "replay_content_hash": replay_hash,
                "outcome": outcome,
            }));
        }
    }

    (rows, nondeterminism_detected)
}

fn environment_snapshot() -> Value {
    json!({
        "schema_version": "franken-engine.deterministic-sim-env.v1",
        "package_version": env!("CARGO_PKG_VERSION"),
        "current_dir": env::current_dir()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
        "argv": env::args().collect::<Vec<_>>(),
    })
}

fn main() -> Result<(), DynError> {
    let cli = parse_args()?;
    fs::create_dir_all(&cli.out_dir)?;

    let scenarios = scenarios(cli.seed);
    let scenario_reports = scenarios
        .iter()
        .map(|scenario| run_scenario(scenario).1)
        .collect::<Vec<_>>();
    let (nondeterminism_rows, nondeterminism_detected) =
        build_nondeterminism_trace(&scenarios, cli.trials);
    let status = if nondeterminism_detected {
        "fail"
    } else {
        "pass"
    };

    let mut artifacts = Vec::new();
    artifacts.push(write_json(
        &cli.out_dir,
        "simulation_schedule_catalog.json",
        &scenario_catalog(&scenarios),
    )?);
    artifacts.push(write_jsonl(
        &cli.out_dir,
        "simulated_nondeterminism_trace.jsonl",
        &nondeterminism_rows,
    )?);
    artifacts.push(write_json(
        &cli.out_dir,
        "simulation_oracle_matrix.json",
        &oracle_matrix(&scenario_reports, cli.trials, nondeterminism_detected),
    )?);
    artifacts.push(write_json(
        &cli.out_dir,
        "trace_ids.json",
        &json!({
            "schema_version": "franken-engine.trace-ids.v1",
            "trace_id": format!("trace-rgc-803c-{}", cli.seed),
            "decision_id": format!("decision-rgc-803c-{}", cli.seed),
            "policy_id": "policy-rgc-803c-scheduler-v1",
            "bead_id": SIM_SCHEDULER_BEAD_ID,
        }),
    )?);
    artifacts.push(write_json(
        &cli.out_dir,
        "env.json",
        &environment_snapshot(),
    )?);

    let command_text = format!("{}\n", env::args().collect::<Vec<_>>().join(" "));
    artifacts.push(write_text(&cli.out_dir, "commands.txt", &command_text)?);

    let report = json!({
        "schema_version": "franken-engine.deterministic-simulation-report.v1",
        "scheduler_schema_version": SIM_SCHEDULER_SCHEMA_VERSION,
        "bead_id": SIM_SCHEDULER_BEAD_ID,
        "status": status,
        "seed": cli.seed,
        "trials": cli.trials,
        "scenario_reports": scenario_reports,
        "nondeterminism_detected": nondeterminism_detected,
        "fail_closed_checks": {
            "seed_provenance_present": true,
            "schedule_catalog_present": true,
            "oracle_matrix_present": true,
            "nondeterminism_trace_present": true,
            "missing_metadata_policy": "fail_closed"
        },
        "artifact_files": artifacts,
    });
    let report_artifact = write_json(
        &cli.out_dir,
        "deterministic_simulation_report.json",
        &report,
    )?;

    let events = vec![
        json!({
            "schema_version": "franken-engine.scheduler-event.v1",
            "trace_id": format!("trace-rgc-803c-{}", cli.seed),
            "decision_id": format!("decision-rgc-803c-{}", cli.seed),
            "policy_id": "policy-rgc-803c-scheduler-v1",
            "component": "deterministic_sim_scheduler",
            "event": "artifact_bundle_emitted",
            "outcome": status,
            "error_code": Value::Null,
            "artifact": report_artifact.path,
        }),
        json!({
            "schema_version": "franken-engine.scheduler-event.v1",
            "trace_id": format!("trace-rgc-803c-{}", cli.seed),
            "decision_id": format!("decision-rgc-803c-{}", cli.seed),
            "policy_id": "policy-rgc-803c-scheduler-v1",
            "component": "deterministic_sim_scheduler",
            "event": "nondeterminism_oracle_checked",
            "outcome": status,
            "error_code": if nondeterminism_detected {
                json!("ERR_SIM_NONDETERMINISM_DETECTED")
            } else {
                Value::Null
            },
        }),
    ];
    let events_artifact = write_jsonl(&cli.out_dir, "events.jsonl", &events)?;

    let manifest = json!({
        "schema_version": "franken-engine.deterministic-sim-manifest.v1",
        "bead_id": SIM_SCHEDULER_BEAD_ID,
        "status": status,
        "artifacts": artifacts
            .iter()
            .chain(std::iter::once(&report_artifact))
            .chain(std::iter::once(&events_artifact))
            .collect::<Vec<_>>(),
    });
    let manifest_artifact = write_json(&cli.out_dir, "manifest.json", &manifest)?;

    let run_manifest = json!({
        "schema_version": "franken-engine.deterministic-sim-run-manifest.v1",
        "bead_id": SIM_SCHEDULER_BEAD_ID,
        "status": status,
        "out_dir": cli.out_dir.display().to_string(),
        "command": env::args().collect::<Vec<_>>(),
        "required_outputs": [
            "deterministic_simulation_report.json",
            "simulation_schedule_catalog.json",
            "simulated_nondeterminism_trace.jsonl",
            "simulation_oracle_matrix.json",
            "events.jsonl",
            "commands.txt",
            "trace_ids.json",
            "env.json",
            "manifest.json",
            "repro.lock"
        ],
        "manifest": manifest_artifact,
    });
    let run_manifest_artifact = write_json(&cli.out_dir, "run_manifest.json", &run_manifest)?;

    let repro_lock = json!({
        "schema_version": "franken-engine.deterministic-sim-repro-lock.v1",
        "bead_id": SIM_SCHEDULER_BEAD_ID,
        "status": status,
        "replay_command": command_text.trim(),
        "artifacts": [
            report_artifact,
            events_artifact,
            run_manifest_artifact,
        ],
    });
    write_json(&cli.out_dir, "repro.lock", &repro_lock)?;

    println!(
        "deterministic simulation scheduler artifacts: status={status} out_dir={}",
        cli.out_dir.display()
    );

    if nondeterminism_detected {
        return Err(invalid_input("deterministic scheduler nondeterminism detected").into());
    }

    Ok(())
}
