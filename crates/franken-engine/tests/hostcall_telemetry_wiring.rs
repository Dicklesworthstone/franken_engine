//! Live wiring tests for the [`TelemetryRecorder`] inside
//! [`InterpreterCore`] (bd-qi3hs).
//!
//! Drives real JavaScript source through the full pipeline
//! (parse -> IR0 -> IR1 -> IR2 -> IR3 -> interpreter execution) and asserts
//! that the interpreter's hostcall dispatch sites feed the recorder with
//! schema-valid, deterministic, replay-aligned records.
//!
//! These tests guard against the failure mode the recorder shipped with for
//! months (cf. closed bd-ygbaj): the schema existed but no production code
//! ever called `TelemetryRecorder::record`, and `forensic_replayer`'s
//! `telemetry_log` was always empty. Each test below would be silently green
//! before the wiring landed.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::forensic_replayer::{IncidentMetadata, IncidentTrace};
use frankenengine_engine::hostcall_telemetry::{HostcallResult, HostcallType};
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

fn make_core(trace_id: &str) -> InterpreterCore {
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
    InterpreterCore::new(config, trace_id)
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
fn incident_trace_with_telemetry_log_carries_real_records() {
    // The forensic_replayer bridge: an IncidentTrace seeded from interpreter
    // recorder state actually carries the live records (the old `Vec::new()`
    // placeholders left telemetry_log empty no matter what).
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

    let bridged = trace.with_telemetry_log(live_records.clone());
    assert_eq!(
        bridged.telemetry_log.len(),
        live_records.len(),
        "bridged trace must carry every live record (no silent truncation)"
    );
    for (a, b) in bridged.telemetry_log.iter().zip(live_records.iter()) {
        assert_eq!(a, b, "bridged records must equal the live source records");
    }

    // The trace's content hash must change once real records replace the
    // empty placeholder — otherwise the bridge has no observable effect.
    assert_ne!(
        trace_pre.content_hash(),
        bridged.content_hash(),
        "trace content_hash must differ once real telemetry_log is bridged in"
    );
}
