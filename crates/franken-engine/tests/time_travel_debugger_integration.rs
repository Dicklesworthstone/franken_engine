//! Integration tests for `time_travel_debugger` (E3.T5b, `bd-fqlfw.3.5.2`).
//!
//! Proves the bead's acceptance criterion end-to-end through the public
//! `--robot` JSON-line protocol: an agent can ask "at exactly which tick and
//! why did my program get contained" and receive one structured answer,
//! instead of reading a multi-thousand-line trace.

use frankenengine_engine::deterministic_replay::{
    NondeterminismSource, NondeterminismTrace, ReplayMode,
};
use frankenengine_engine::replay_time_travel::{TimeTravelConfig, TimeTravelCursor};
use frankenengine_engine::time_travel_debugger::{
    DebuggerEvent, DebuggerEventKind, RobotSession, SECRET_LABEL_LEVEL, TimeTravelDebugger,
};

fn make_cursor(ticks: usize) -> TimeTravelCursor {
    let mut trace = NondeterminismTrace::new("ttd-itest");
    for index in 0..ticks {
        trace.capture(
            NondeterminismSource::PropertyResolution,
            vec![index as u8, 0xAB],
            (index as u64).saturating_add(1),
            "ttd-itest",
        );
    }
    trace.finalise(ticks as u64);
    TimeTravelCursor::new(
        trace,
        ReplayMode::Strict,
        TimeTravelConfig {
            checkpoint_interval: 8,
        },
    )
    .expect("cursor construction should succeed")
}

fn base_event(tick: u64, seq: u64, kind: DebuggerEventKind, detail: &str) -> DebuggerEvent {
    DebuggerEvent {
        tick,
        seq,
        kind,
        label_level: None,
        capability_allowed: None,
        malicious_posterior_millionths: None,
        decision_id: None,
        detail: detail.to_string(),
    }
}

/// A realistic containment incident: benign activity, then a Secret-labeled
/// value, an exfil-shaped denied capability check, a rising malicious
/// posterior, and finally guardplane containment with a recorded decision.
fn incident_events() -> Vec<DebuggerEvent> {
    let mut events = vec![
        base_event(
            1,
            0,
            DebuggerEventKind::HostcallDispatched,
            "fs.readFile config",
        ),
        base_event(2, 1, DebuggerEventKind::GcTriggered, "minor gc"),
    ];

    let mut allowed = base_event(4, 2, DebuggerEventKind::CapabilityChecked, "FsRead granted");
    allowed.capability_allowed = Some(true);
    events.push(allowed);

    let mut secret = base_event(
        6,
        3,
        DebuggerEventKind::FlowLabelChecked,
        "secret.field read labeled Secret",
    );
    secret.label_level = Some(SECRET_LABEL_LEVEL);
    events.push(secret);

    let mut denied = base_event(
        9,
        4,
        DebuggerEventKind::CapabilityChecked,
        "NetEgress denied for host exfil.example",
    );
    denied.capability_allowed = Some(false);
    events.push(denied);

    let mut posterior_low = base_event(
        10,
        5,
        DebuggerEventKind::PosteriorObserved,
        "malicious posterior 0.12",
    );
    posterior_low.malicious_posterior_millionths = Some(120_000);
    events.push(posterior_low);

    let mut posterior_high = base_event(
        12,
        6,
        DebuggerEventKind::PosteriorObserved,
        "malicious posterior 0.27",
    );
    posterior_high.malicious_posterior_millionths = Some(270_000);
    events.push(posterior_high);

    let mut contained = base_event(
        14,
        7,
        DebuggerEventKind::ContainmentAction,
        "guardplane quarantine",
    );
    contained.decision_id = Some("decision-itest-quarantine-7".to_string());
    events.push(contained);

    events
}

fn make_session() -> RobotSession {
    RobotSession::new(TimeTravelDebugger::new(make_cursor(16), incident_events()))
}

#[test]
fn acceptance_agent_learns_containment_tick_and_why_in_one_answer() {
    let mut session = make_session();

    // The agent arms the bead's canonical breakpoint and runs to it.
    let added = session.handle_line(
        r#"{"cmd":"add_breakpoint","breakpoint":{"type":"kind_is","kind":"ContainmentAction"}}"#,
    );
    assert!(added.contains("\"ok\":true"), "add failed: {added}");

    let run = session.handle_line(r#"{"cmd":"run_until_break"}"#);
    assert!(run.contains("break_hit"), "expected a hit: {run}");
    assert!(
        run.contains("\"tick\":14"),
        "containment tick missing: {run}"
    );

    // One question, one structured answer.
    let why = session.handle_line(r#"{"cmd":"why","tick":14}"#);
    assert!(why.contains("\"ok\":true"));
    assert!(why.contains("containment_action"));
    assert!(why.contains("decision-itest-quarantine-7"));
    assert!(why.contains("data_sensitivity_precursor"));
    assert!(why.contains("authority_precursor"));
    assert!(why.contains("risk_signal_precursor"));
    assert!(
        !why.contains('\n'),
        "the answer must be a single JSON line, got: {why}"
    );
}

#[test]
fn all_three_bead_example_breakpoints_fire_at_expected_ticks() {
    // "break when any value labeled Secret is created" -> tick 6
    let mut secret_session = make_session();
    secret_session.handle_line(
        r#"{"cmd":"add_breakpoint","breakpoint":{"type":"label_level_at_least","min_level":3}}"#,
    );
    let secret_hit = secret_session.handle_line(r#"{"cmd":"run_until_break"}"#);
    assert!(secret_hit.contains("\"tick\":6"), "secret: {secret_hit}");

    // "break on first denied capability check" -> tick 9 (allowed check at 4
    // must not fire).
    let mut denial_session = make_session();
    denial_session
        .handle_line(r#"{"cmd":"add_breakpoint","breakpoint":{"type":"capability_denied"}}"#);
    let denial_hit = denial_session.handle_line(r#"{"cmd":"run_until_break"}"#);
    assert!(denial_hit.contains("\"tick\":9"), "denial: {denial_hit}");

    // "break when malicious-posterior crosses 0.2" -> tick 12 (0.12 at tick
    // 10 must not fire).
    let mut posterior_session = make_session();
    posterior_session.handle_line(
        r#"{"cmd":"add_breakpoint","breakpoint":{"type":"malicious_posterior_above","threshold_millionths":200000}}"#,
    );
    let posterior_hit = posterior_session.handle_line(r#"{"cmd":"run_until_break"}"#);
    assert!(
        posterior_hit.contains("\"tick\":12"),
        "posterior: {posterior_hit}"
    );
}

#[test]
fn sequential_breakpoint_hits_walk_the_escalation_chain() {
    let mut session = make_session();
    session.handle_line(
        r#"{"cmd":"add_breakpoint","breakpoint":{"type":"label_level_at_least","min_level":3}}"#,
    );
    session.handle_line(r#"{"cmd":"add_breakpoint","breakpoint":{"type":"capability_denied"}}"#);
    session.handle_line(
        r#"{"cmd":"add_breakpoint","breakpoint":{"type":"malicious_posterior_above","threshold_millionths":200000}}"#,
    );
    session.handle_line(
        r#"{"cmd":"add_breakpoint","breakpoint":{"type":"kind_is","kind":"ContainmentAction"}}"#,
    );

    let mut hit_ticks = Vec::new();
    loop {
        let line = session.handle_line(r#"{"cmd":"run_until_break"}"#);
        if line.contains("no_break_hit") {
            break;
        }
        let tick_field = line
            .split("\"event\":")
            .nth(1)
            .and_then(|rest| rest.split("\"tick\":").nth(1))
            .and_then(|rest| rest.split(&[',', '}'][..]).next())
            .and_then(|digits| digits.trim().parse::<u64>().ok())
            .expect("hit line should carry an event tick");
        hit_ticks.push(tick_field);
        if hit_ticks.len() > 8 {
            panic!("breakpoint loop failed to terminate: {hit_ticks:?}");
        }
    }
    assert_eq!(hit_ticks, vec![6, 9, 12, 14]);
}

#[test]
fn navigation_and_breakpoints_compose_with_time_travel() {
    let mut session = make_session();
    session.handle_line(r#"{"cmd":"add_breakpoint","breakpoint":{"type":"capability_denied"}}"#);

    // Run to the denial, rewind before the secret read, run again: the same
    // denial fires again (deterministic re-run, no state corruption).
    let first = session.handle_line(r#"{"cmd":"run_until_break"}"#);
    assert!(first.contains("\"tick\":9"));
    let rewind = session.handle_line(r#"{"cmd":"goto","tick":3}"#);
    assert!(rewind.contains("\"ok\":true"));
    let second = session.handle_line(r#"{"cmd":"run_until_break"}"#);
    assert!(
        second.contains("\"tick\":9"),
        "re-run after rewind: {second}"
    );
}

#[test]
fn why_mid_incident_excludes_future_events() {
    let mut session = make_session();
    let why = session.handle_line(r#"{"cmd":"why","tick":10}"#);
    assert!(why.contains("\"ok\":true"));
    // Subject is the low posterior at tick 10; containment (tick 14) and the
    // high posterior (tick 12) must not appear.
    assert!(why.contains("posterior_observed"));
    assert!(!why.contains("containment_action"), "future leak: {why}");
    assert!(!why.contains("decision-itest-quarantine-7"));
}

#[test]
fn robot_protocol_is_fail_closed_and_deterministic() {
    let script = [
        r#"{"cmd":"state"}"#,
        r#"{"cmd":"goto","tick":99}"#,
        "garbage",
        r#"{"cmd":"add_breakpoint","breakpoint":{"type":"capability_denied"}}"#,
        r#"{"cmd":"run_until_break"}"#,
        r#"{"cmd":"why","tick":14}"#,
        r#"{"cmd":"events_at","tick":9}"#,
    ];
    let mut first_session = make_session();
    let mut second_session = make_session();
    let first: Vec<String> = script
        .iter()
        .map(|line| first_session.handle_line(line))
        .collect();
    let second: Vec<String> = script
        .iter()
        .map(|line| second_session.handle_line(line))
        .collect();
    assert_eq!(first, second, "transcripts must be byte-identical");
    assert!(first[1].contains("\"ok\":false"));
    assert!(first[2].contains("\"ok\":false"));
    // Every line is exactly one JSON object.
    for line in &first {
        assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
        assert!(!line.contains('\n'));
    }
}
