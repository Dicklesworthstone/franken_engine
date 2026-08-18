//! Live wiring tests for the [`TelemetryRecorder`] inside
//! [`InterpreterCore`] (bd-qi3hs).
//!
//! Drives real JavaScript source through the full pipeline
//! (parse -> IR0 -> IR1 -> IR2 -> IR3 -> interpreter execution), plus focused
//! public-IR dispatch probes for capability paths intentionally rejected by
//! source lowering, and asserts that hostcall dispatch sites feed the recorder
//! with schema-valid, deterministic, replay-aligned records.
//!
//! These tests guard against the failure mode the recorder shipped with for
//! months (cf. closed bd-ygbaj): the schema existed but no production code
//! ever called `TelemetryRecorder::record`, and `forensic_replayer`'s
//! `telemetry_log` was always empty. Each test below would be silently green
//! before the wiring landed.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::forensic_replayer::{IncidentMetadata, IncidentTrace};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hostcall_telemetry::{
    HostcallResult, HostcallTelemetryRecord, HostcallType,
};
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion,
    RegRange, WitnessEventKind,
};
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

fn make_core(trace_id: &str) -> InterpreterCore {
    make_core_with_capabilities(trace_id, &[])
}

fn make_core_with_capabilities(
    trace_id: &str,
    additional_capabilities: &[RuntimeCapability],
) -> InterpreterCore {
    InterpreterCore::new(interpreter_config(additional_capabilities), trace_id)
}

fn interpreter_config(additional_capabilities: &[RuntimeCapability]) -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    config
        .granted_capabilities
        .insert(RuntimeCapability::Builtin);
    config
        .granted_capabilities
        .insert(RuntimeCapability::Console);
    config.granted_capabilities.insert(RuntimeCapability::Timer);
    config
        .granted_capabilities
        .extend(additional_capabilities.iter().copied());
    config
}

fn temp_module_root(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("franken_engine_{prefix}_{nanos}"))
}

/// Drive real JS source through the full lowering + execution pipeline and
/// return the interpreter for direct inspection of its recorder state.
fn run_to_core(trace_id: &str, source: &str) -> InterpreterCore {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "hostcall-telemetry-wiring");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("ir0 -> ir1 should lower");
    let ir2 = lower_ir1_to_ir2(&ir1.module).expect("ir1 -> ir2 should lower");
    let ir3 = lower_ir2_to_ir3(&ir2.module).expect("ir2 -> ir3 should lower");

    let mut core = make_core(trace_id);
    let _ = core
        .execute(&ir3.module)
        .expect("source should execute cleanly");
    core
}

#[test]
fn console_log_drives_recorder_with_console_record() {
    let core = run_to_core("trace-console", "console.log('hello-bd-qi3hs');");
    let records = core.hostcall_telemetry().records();
    assert!(
        !records.is_empty(),
        "console.log should produce at least one telemetry record (bd-qi3hs)"
    );
    let console_records: Vec<_> = records
        .iter()
        .filter(|r| matches!(r.hostcall_type, HostcallType::Console))
        .collect();
    assert!(
        !console_records.is_empty(),
        "at least one record must carry hostcall_type=Console, got: {:?}",
        records.iter().map(|r| r.hostcall_type).collect::<Vec<_>>()
    );
    let rec = console_records[0];
    assert_eq!(
        rec.capability_used,
        RuntimeCapability::Console,
        "console hostcall must be tagged with the Console capability"
    );
    assert!(
        matches!(rec.result_status, HostcallResult::Success),
        "successful console.log must record HostcallResult::Success, got {:?}",
        rec.result_status
    );
    assert_eq!(
        rec.extension_id, "trace-console",
        "the trace id should flow into extension_id on each record"
    );
    assert!(
        rec.verify_integrity(),
        "every emitted record must satisfy its own integrity check"
    );
}

#[test]
fn record_ids_and_timestamps_are_monotonic() {
    let source = concat!(
        "console.log('one');\n",
        "console.log('two');\n",
        "console.log('three');\n",
    );
    let core = run_to_core("trace-monotonic", source);
    let records: Vec<_> = core
        .hostcall_telemetry()
        .records()
        .iter()
        .filter(|r| matches!(r.hostcall_type, HostcallType::Console))
        .collect();
    assert!(
        records.len() >= 3,
        "three console.log statements should produce >=3 console records, got {}",
        records.len()
    );
    for window in records.windows(2) {
        let (a, b) = (window[0], window[1]);
        assert!(
            b.record_id > a.record_id,
            "record_id must be strictly increasing: {} -> {}",
            a.record_id,
            b.record_id
        );
        assert!(
            b.timestamp_ns >= a.timestamp_ns,
            "timestamp_ns must be monotonically non-decreasing: {} -> {}",
            a.timestamp_ns,
            b.timestamp_ns
        );
    }
}

#[test]
fn two_runs_of_same_source_produce_identical_record_sequences() {
    // Replay determinism: the recorder uses the interpreter's instruction
    // counter as its timestamp source, so two executions of the same source
    // must produce byte-identical record sequences.
    let source = "console.log('determinism-check', 42, true);";
    let core_a = run_to_core("trace-determinism", source);
    let core_b = run_to_core("trace-determinism", source);
    let records_a = core_a.hostcall_telemetry().records();
    let records_b = core_b.hostcall_telemetry().records();
    assert_eq!(
        records_a.len(),
        records_b.len(),
        "two runs of the same source must produce the same number of records"
    );
    for (i, (a, b)) in records_a.iter().zip(records_b.iter()).enumerate() {
        assert_eq!(
            a.record_id, b.record_id,
            "record_id mismatch at index {i}: {} vs {}",
            a.record_id, b.record_id
        );
        assert_eq!(
            a.timestamp_ns, b.timestamp_ns,
            "timestamp_ns mismatch at index {i} (deterministic source violated)"
        );
        assert_eq!(
            a.arguments_hash, b.arguments_hash,
            "arguments_hash mismatch at index {i} (canonical encoding broken)"
        );
        assert_eq!(
            a.hostcall_type, b.hostcall_type,
            "hostcall_type mismatch at index {i}"
        );
        assert_eq!(
            a.capability_used, b.capability_used,
            "capability_used mismatch at index {i}"
        );
        assert_eq!(
            a.content_hash, b.content_hash,
            "content_hash mismatch at index {i} (overall record drift)"
        );
    }
    assert_eq!(
        core_a.hostcall_telemetry().rolling_hash(),
        core_b.hostcall_telemetry().rolling_hash(),
        "rolling_hash must match between identical replays"
    );
}

#[test]
fn fresh_interpreter_has_empty_recorder() {
    // The recorder is per-interpreter and starts empty, so an interpreter
    // that never executes anything has no records and cannot pretend to.
    let core = make_core("trace-empty");
    assert_eq!(
        core.hostcall_telemetry().len(),
        0,
        "a fresh interpreter must start with zero recorded hostcalls"
    );
    assert!(
        core.hostcall_telemetry().is_empty(),
        "is_empty() must agree with len()==0"
    );
}

#[test]
fn require_failure_emits_deterministic_module_load_record() {
    fn run_once() -> (InterpreterError, Vec<HostcallTelemetryRecord>) {
        // Bare `require(...)` is correctly rejected as ambient authority by
        // source lowering. Exercise the public IR dispatch boundary directly,
        // which remains reachable by validated/loaded IR modules.
        let module = Ir3Module {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir3,
                source_hash: None,
                source_label: "bd-juz83-require-telemetry".to_string(),
            },
            instructions: vec![
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("module:require".to_string()),
                    args: RegRange { start: 0, count: 1 },
                    dst: 1,
                },
            ],
            constant_pool: Vec::new(),
            function_table: Vec::new(),
            specialization: None,
            required_capabilities: Vec::new(),
        };

        let mut core =
            make_core_with_capabilities("trace-require-bd-juz83", &[RuntimeCapability::ModuleLoad]);
        let error = core
            .execute(&module)
            .expect_err("non-string require must fail after dispatch");
        (error, core.hostcall_telemetry().records().to_vec())
    }

    let (first_error, first_records) = run_once();
    assert!(matches!(
        first_error,
        InterpreterError::RequireSpecifierNotString { ref got } if got == "number"
    ));
    let require_records = first_records
        .iter()
        .filter(|record| record.hostcall_type == HostcallType::ModuleLoad)
        .collect::<Vec<_>>();
    assert_eq!(
        require_records.len(),
        1,
        "one require dispatch must emit exactly one module-load record"
    );
    let record = require_records[0];
    assert_eq!(record.capability_used, RuntimeCapability::ModuleLoad);
    assert!(matches!(
        record.result_status,
        HostcallResult::Error { code: 12 }
    ));
    assert!(record.verify_integrity());

    let (second_error, second_records) = run_once();
    assert_eq!(
        first_error.to_string(),
        second_error.to_string(),
        "control-flow failure must be deterministic"
    );
    assert_eq!(
        first_records, second_records,
        "module-load telemetry must be byte-identical across replays"
    );
}

#[test]
fn import_module_without_module_grant_denies_before_resolution() {
    let root = temp_module_root("bd_juz83_import_without_grant");
    fs::create_dir_all(&root).expect("create module root");
    let module = Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: root.join("main.mjs").display().to_string(),
        },
        instructions: vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
        ],
        constant_pool: vec!["./missing.mjs".into()],
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    };

    let mut config = interpreter_config(&[]);
    config.module_root = Some(root.display().to_string());
    let mut core = InterpreterCore::new(config, "trace-import-capture-bd-juz83");
    let error = core
        .execute(&module)
        .expect_err("ImportModule must not reach resolution without a ModuleLoad grant");
    assert!(matches!(
        error,
        InterpreterError::CapabilityDenied { capability }
            if capability == "module_load"
    ));
    assert!(
        core.hostcall_telemetry().is_empty(),
        "an authority denial must precede module-resolution telemetry"
    );
}

#[test]
fn direct_import_hostcall_alias_emits_module_load_record() {
    let module = Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "bd-juz83-direct-import-hostcall".to_string(),
        },
        instructions: vec![
            Ir3Instruction::LoadInt { dst: 0, value: 9 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("module.import".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
        ],
        constant_pool: Vec::new(),
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    };

    let mut core = make_core_with_capabilities(
        "trace-direct-import-bd-juz83",
        &[RuntimeCapability::ModuleLoad],
    );
    let error = core
        .execute(&module)
        .expect_err("non-string import hostcall must fail after dispatch");
    assert!(matches!(
        error,
        InterpreterError::ImportSpecifierNotString { got } if got == "number"
    ));
    let records = core.hostcall_telemetry().records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].hostcall_type, HostcallType::ModuleLoad);
    assert_eq!(records[0].capability_used, RuntimeCapability::ModuleLoad);
    assert!(matches!(
        records[0].result_status,
        HostcallResult::Error { .. }
    ));
    assert!(records[0].verify_integrity());
}

#[test]
fn apply_hostcall_module_load_aliases_record_inner_and_outer_without_drops() {
    fn run_target(target_capability: &str, suffix: &str) {
        let root = temp_module_root(&format!("bd_juz83_apply_{suffix}"));
        fs::create_dir_all(&root).expect("create module root");
        fs::write(root.join("dep.cjs"), "module.exports = 23;\n").expect("write dependency module");

        let module = Ir3Module {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir3,
                source_hash: None,
                source_label: root.join("main.mjs").display().to_string(),
            },
            instructions: vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::NewArray { dst: 1 },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 1,
                },
                Ir3Instruction::ArrayPush {
                    array: 1,
                    element: 2,
                },
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:ApplyHostCall".to_string()),
                    args: RegRange { start: 0, count: 2 },
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
            ],
            constant_pool: vec![target_capability.into(), "./dep.cjs".into()],
            function_table: Vec::new(),
            specialization: None,
            required_capabilities: Vec::new(),
        };

        let mut config = interpreter_config(&[RuntimeCapability::ModuleLoad]);
        config.module_root = Some(root.display().to_string());
        let mut core = InterpreterCore::new(config, format!("trace-apply-{suffix}-bd-juz83"));
        let result = core
            .execute(&module)
            .expect("ApplyHostCall module-load target should execute");

        let decisions = result
            .hostcall_decisions
            .iter()
            .map(|decision| (decision.capability.0.as_str(), decision.allowed))
            .collect::<Vec<_>>();
        assert_eq!(
            decisions,
            vec![("builtin:ApplyHostCall", true), ("module_load", true)],
            "target={target_capability}: delegated aliases must share canonical authority evidence"
        );
        assert!(result.witness_events.iter().any(|event| {
            event.kind == WitnessEventKind::HostcallDispatched
                && event.payload_hash == ContentHash::compute(b"cap:module_load")
        }));
        if target_capability != "module_load" {
            let alias_payload = ContentHash::compute(format!("cap:{target_capability}").as_bytes());
            assert!(
                result.witness_events.iter().all(|event| {
                    event.kind != WitnessEventKind::HostcallDispatched
                        || event.payload_hash != alias_payload
                }),
                "target={target_capability}: witness evidence must not fragment by alias"
            );
        }

        assert_eq!(
            core.hostcall_telemetry().drop_counts(),
            Default::default(),
            "nested ApplyHostCall completion must preserve timestamp monotonicity"
        );
        let records = core.hostcall_telemetry().records();
        assert_eq!(records.len(), 2, "target={target_capability}");
        assert_eq!(records[0].hostcall_type, HostcallType::ModuleLoad);
        assert_eq!(records[1].hostcall_type, HostcallType::Builtin);
        assert!(records.iter().all(|record| record.verify_integrity()));
    }

    run_target("module:require", "require");
    run_target("module:import", "import_colon");
    run_target("module.import", "import_dot");
    run_target("module_load", "canonical");
}

#[test]
fn nested_module_require_product_path_captures_every_dispatch() {
    fn run_once() -> Vec<HostcallTelemetryRecord> {
        let root = temp_module_root("bd_juz83_nested_require");
        fs::create_dir_all(&root).expect("create module root");
        fs::write(root.join("dep.cjs"), "module.exports = 17;\n").expect("write dependency module");
        fs::write(
            root.join("entry.cjs"),
            "module.exports = module.require('./dep.cjs');\n",
        )
        .expect("write entry module");

        let module = Ir3Module {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir3,
                source_hash: None,
                source_label: root.join("main.mjs").display().to_string(),
            },
            instructions: vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::ImportModule {
                    specifier: 0,
                    dst: 1,
                },
                Ir3Instruction::Return { value: 1 },
            ],
            constant_pool: vec!["./entry.cjs".into()],
            function_table: Vec::new(),
            specialization: None,
            required_capabilities: Vec::new(),
        };

        // Both the outer ImportModule and the nested first-class
        // module.require must consume the same explicit ModuleLoad grant and
        // record one canonical decision apiece.
        let mut config = interpreter_config(&[RuntimeCapability::ModuleLoad]);
        config.module_root = Some(root.display().to_string());
        let mut core = InterpreterCore::new(config, "trace-module-load-bd-juz83");
        let result = core
            .execute(&module)
            .expect("nested module.require product path should execute");
        let decisions = result
            .hostcall_decisions
            .iter()
            .map(|decision| (decision.capability.0.as_str(), decision.allowed))
            .collect::<Vec<_>>();
        assert_eq!(
            decisions,
            vec![("module_load", true), ("module_load", true)],
            "both module-load dispatch routes must use canonical allowed evidence"
        );

        assert_eq!(
            core.hostcall_telemetry().drop_counts(),
            Default::default(),
            "nested completion order must not trigger a recorder drop"
        );
        core.hostcall_telemetry().records().to_vec()
    }

    let first_records = run_once();
    assert_eq!(
        first_records.len(),
        2,
        "outer module:import and inner first-class module.require must each be captured"
    );
    for record in &first_records {
        assert_eq!(record.hostcall_type, HostcallType::ModuleLoad);
        assert_eq!(record.capability_used, RuntimeCapability::ModuleLoad);
        assert_eq!(record.result_status, HostcallResult::Success);
        assert!(record.verify_integrity());
    }
    assert_eq!(
        first_records,
        run_once(),
        "nested module-load telemetry must be byte-identical across replays"
    );
}

#[test]
fn incident_trace_with_telemetry_recorder_carries_retention_evidence() {
    // The forensic_replayer bridge: an IncidentTrace seeded from interpreter
    // recorder state carries both the live records and the source recorder's
    // drop evidence. Dispatch-site capture coverage is tested independently.
    let core = run_to_core(
        "trace-incident",
        "console.log('seed-bd-qi3hs'); console.error('uh-oh');",
    );
    let live_records: Vec<_> = core.hostcall_telemetry().records().to_vec();
    assert!(
        live_records
            .iter()
            .any(|r| matches!(r.hostcall_type, HostcallType::Console)),
        "live recorder must contain at least one Console record before bridging"
    );

    let trace = IncidentTrace {
        metadata: IncidentMetadata {
            trace_id: "trace-incident".to_string(),
            extension_id: "trace-incident".to_string(),
            start_epoch: frankenengine_engine::security_epoch::SecurityEpoch::GENESIS,
            start_timestamp_ns: 0,
            end_timestamp_ns: 0,
            initial_prior: frankenengine_engine::bayesian_posterior::Posterior::default_prior(),
            loss_matrix_id: "balanced".to_string(),
            annotations: std::collections::BTreeMap::new(),
        },
        telemetry_log: Vec::new(),
        telemetry_drop_counts: Default::default(),
        posterior_history: Vec::new(),
        decision_log: Vec::new(),
        evidence_log: Vec::new(),
        containment_log: Vec::new(),
        loss_matrix: frankenengine_engine::expected_loss_selector::LossMatrix::balanced(),
        likelihood_model: frankenengine_engine::bayesian_posterior::LikelihoodModel::default(),
    };

    let trace_pre = trace.clone();
    assert!(
        trace_pre.telemetry_log.is_empty(),
        "an unbridged IncidentTrace starts with an empty telemetry_log"
    );

    let bridged = trace.with_telemetry_recorder(core.hostcall_telemetry());
    assert_eq!(
        bridged.telemetry_log.len(),
        live_records.len(),
        "bridged trace must carry every live record (no silent truncation)"
    );
    for (a, b) in bridged.telemetry_log.iter().zip(live_records.iter()) {
        assert_eq!(a, b, "bridged records must equal the live source records");
    }
    assert_eq!(
        bridged.telemetry_drop_counts,
        core.hostcall_telemetry().drop_counts(),
        "bridged trace must retain source-recorder drop evidence"
    );

    // The trace's content hash must change once real records replace the
    // empty placeholder — otherwise the bridge has no observable effect.
    assert_ne!(
        trace_pre.content_hash(),
        bridged.content_hash(),
        "trace content_hash must differ once real telemetry_log is bridged in"
    );
}
