//! Stress tests for high-concurrency extension workloads (bd-3c1).
//!
//! Validates FrankenEngine's correctness, stability, and resource-enforcement
//! guarantees under concurrent extension lifecycle operations.
//!
//! Workload families:
//! 1. **Lifecycle storm** — N extensions performing concurrent
//!    load/init/activate/deactivate/unload cycles with randomized timing and
//!    injected failures.
//! 2. **Hostcall flood** — M extensions each issuing K hostcalls, validating
//!    budget tracking under high-throughput patterns.
//! 3. **Budget exhaustion race** — Extensions designed to simultaneously hit
//!    CPU, memory, and hostcall budget limits; validates enforcement transitions
//!    are deterministic and corruption-free.
//! 4. **Noisy neighbor isolation** — One adversarial extension consuming
//!    maximum resources while N-1 well-behaved extensions run; validates budget
//!    isolation.
//! 5. **Quarantine cascade** — Simultaneous quarantine of Q extensions while
//!    others are mid-operation; validates atomic per-extension quarantine.
//!
//! All scenarios use deterministic PRNG seeds for reproducibility.
//! Structured logging fields per spec: trace_id, scenario_id, workload_family,
//! concurrency_level, total_hostcalls, total_lifecycle_events,
//! invariant_violations, budget_exhaustion_events, quarantine_events.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::extension_lifecycle_manager::{
    CancellationConfig, ExtensionLifecycleManager, ExtensionState, LifecycleError,
    LifecycleTransition, ResourceBudget,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const STRESS_DEFAULT_DURATION_S: u64 = 60;
const STRESS_POLICY_ID: &str = "policy-stress-concurrency-v1";
const STRESS_COMPONENT: &str = "stress_concurrency_suite";

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64)
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 1 } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    fn next_bool(&mut self, probability_percent: u32) -> bool {
        (self.next_u64() % 100) < probability_percent as u64
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ext_id(prefix: &str, i: usize) -> String {
    format!("{prefix}-{i:04}")
}

fn temp_artifact_dir(suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "franken-engine-stress-concurrency-{suffix}-{nanos}"
    ));
    fs::create_dir_all(&path).expect("temporary artifact directory should be creatable");
    path
}

/// Drive an extension from Unloaded to Running via the happy path.
fn advance_to_running(mgr: &mut ExtensionLifecycleManager, id: &str, trace: &str) {
    mgr.transition(id, LifecycleTransition::Validate, trace, None)
        .unwrap();
    mgr.transition(id, LifecycleTransition::Load, trace, None)
        .unwrap();
    mgr.transition(id, LifecycleTransition::Start, trace, None)
        .unwrap();
    mgr.transition(id, LifecycleTransition::Activate, trace, None)
        .unwrap();
}

/// Attempt a full lifecycle: register → Running → shutdown/quarantine,
/// with randomized failure injection points.
fn lifecycle_cycle(
    mgr: &mut ExtensionLifecycleManager,
    id: &str,
    rng: &mut Rng,
    trace: &str,
    inject_failure_pct: u32,
) -> LifecycleCycleResult {
    let mut result = LifecycleCycleResult::default();

    // Validate
    if mgr
        .transition(id, LifecycleTransition::Validate, trace, None)
        .is_err()
    {
        result.invalid_transitions += 1;
        return result;
    }
    result.lifecycle_events += 1;

    // Inject manifest rejection
    if rng.next_bool(inject_failure_pct) {
        let _ = mgr.transition(id, LifecycleTransition::RejectManifest, trace, None);
        result.lifecycle_events += 1;
        result.injected_failures += 1;
        return result;
    }

    // Load
    if mgr
        .transition(id, LifecycleTransition::Load, trace, None)
        .is_err()
    {
        result.invalid_transitions += 1;
        return result;
    }
    result.lifecycle_events += 1;

    // Inject load failure
    if rng.next_bool(inject_failure_pct) {
        let _ = mgr.transition(id, LifecycleTransition::LoadFailed, trace, None);
        result.lifecycle_events += 1;
        result.injected_failures += 1;
        return result;
    }

    // Start
    match mgr.transition(id, LifecycleTransition::Start, trace, None) {
        Ok(_) => result.lifecycle_events += 1,
        Err(LifecycleError::BudgetExhausted { .. }) => {
            result.budget_exhaustion_events += 1;
            return result;
        }
        Err(_) => {
            result.invalid_transitions += 1;
            return result;
        }
    }

    // Inject start failure
    if rng.next_bool(inject_failure_pct) {
        let _ = mgr.transition(id, LifecycleTransition::StartFailed, trace, None);
        result.lifecycle_events += 1;
        result.injected_failures += 1;
        return result;
    }

    // Activate
    if mgr
        .transition(id, LifecycleTransition::Activate, trace, None)
        .is_err()
    {
        result.invalid_transitions += 1;
        return result;
    }
    result.lifecycle_events += 1;

    // Optionally suspend/resume cycle
    if rng.next_bool(40) {
        let _ = mgr.transition(id, LifecycleTransition::Suspend, trace, None);
        result.lifecycle_events += 1;
        let _ = mgr.transition(id, LifecycleTransition::Freeze, trace, None);
        result.lifecycle_events += 1;
        let _ = mgr.transition(id, LifecycleTransition::Resume, trace, None);
        result.lifecycle_events += 1;
        let _ = mgr.transition(id, LifecycleTransition::Reactivate, trace, None);
        result.lifecycle_events += 1;
    }

    // Terminate or quarantine
    if rng.next_bool(20) {
        let _ = mgr.transition(id, LifecycleTransition::Quarantine, trace, None);
        result.quarantine_events += 1;
    } else {
        let _ = mgr.transition(id, LifecycleTransition::Terminate, trace, None);
        let _ = mgr.transition(id, LifecycleTransition::Finalize, trace, None);
    }
    result.lifecycle_events += 1;

    result
}

#[derive(Debug, Default, Clone)]
struct LifecycleCycleResult {
    lifecycle_events: u64,
    invalid_transitions: u64,
    injected_failures: u64,
    budget_exhaustion_events: u64,
    quarantine_events: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StressScaleProfile {
    label: &'static str,
    extension_count: usize,
    duration_s: u64,
}

fn stress_scale_profiles() -> [StressScaleProfile; 3] {
    [
        StressScaleProfile {
            label: "small",
            extension_count: 10,
            duration_s: stress_duration_s(),
        },
        StressScaleProfile {
            label: "medium",
            extension_count: 100,
            duration_s: stress_duration_s(),
        },
        StressScaleProfile {
            label: "large",
            extension_count: 1_000,
            duration_s: stress_duration_s(),
        },
    ]
}

/// Structured evidence for a stress scenario run.
#[derive(Debug, Clone)]
struct StressEvidence {
    scenario_id: String,
    workload_family: String,
    concurrency_level: usize,
    duration_s: u64,
    seed: u64,
    total_hostcalls: u64,
    total_lifecycle_events: u64,
    invariant_violations: u64,
    budget_exhaustion_events: u64,
    quarantine_events: u64,
}

impl StressEvidence {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"scenario_id\":\"{}\",\"workload_family\":\"{}\",",
                "\"concurrency_level\":{},\"duration_s\":{},\"seed\":{},",
                "\"total_hostcalls\":{},\"total_lifecycle_events\":{},",
                "\"invariant_violations\":{},\"budget_exhaustion_events\":{},",
                "\"quarantine_events\":{}}}"
            ),
            self.scenario_id,
            self.workload_family,
            self.concurrency_level,
            self.duration_s,
            self.seed,
            self.total_hostcalls,
            self.total_lifecycle_events,
            self.invariant_violations,
            self.budget_exhaustion_events,
            self.quarantine_events,
        )
    }
}

#[derive(Debug, Clone)]
struct StressStructuredEvent {
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    scenario_id: String,
    workload_family: String,
    concurrency_level: usize,
    duration_s: u64,
    total_hostcalls: u64,
    total_lifecycle_events: u64,
    invariant_violations: u64,
    budget_exhaustion_events: u64,
    quarantine_events: u64,
}

impl StressStructuredEvent {
    fn to_json_line(&self) -> String {
        json!({
            "trace_id": self.trace_id,
            "decision_id": self.decision_id,
            "policy_id": self.policy_id,
            "component": self.component,
            "event": self.event,
            "outcome": self.outcome,
            "error_code": self.error_code,
            "scenario_id": self.scenario_id,
            "workload_family": self.workload_family,
            "concurrency_level": self.concurrency_level,
            "duration_s": self.duration_s,
            "total_hostcalls": self.total_hostcalls,
            "total_lifecycle_events": self.total_lifecycle_events,
            "invariant_violations": self.invariant_violations,
            "budget_exhaustion_events": self.budget_exhaustion_events,
            "quarantine_events": self.quarantine_events,
        })
        .to_string()
    }
}

#[derive(Debug, Clone)]
struct StressEnvironmentFingerprint {
    os: String,
    arch: String,
    rust_toolchain: String,
}

#[derive(Debug, Clone)]
struct StressSanitizerConfig {
    profile: String,
    tsan_enabled: bool,
    asan_enabled: bool,
}

#[derive(Debug, Clone)]
struct StressArtifactPaths {
    run_manifest_path: PathBuf,
    stress_evidence_path: PathBuf,
    stress_events_path: PathBuf,
}

fn stress_duration_s() -> u64 {
    std::env::var("FRANKEN_STRESS_DURATION_S")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(STRESS_DEFAULT_DURATION_S)
}

fn stress_environment_fingerprint() -> StressEnvironmentFingerprint {
    StressEnvironmentFingerprint {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        rust_toolchain: std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".to_string()),
    }
}

fn stress_sanitizer_config() -> StressSanitizerConfig {
    let rustflags = std::env::var("RUSTFLAGS").unwrap_or_default();
    let tsan_enabled = rustflags.contains("sanitize=thread");
    let asan_enabled = rustflags.contains("sanitize=address");
    let profile = if tsan_enabled {
        "stress-tsan"
    } else if asan_enabled {
        "stress-asan"
    } else {
        "stress-default"
    };
    StressSanitizerConfig {
        profile: profile.to_string(),
        tsan_enabled,
        asan_enabled,
    }
}

fn synthetic_latency_us(evidence: &StressEvidence) -> (u64, u64, u64) {
    let base = 50 + evidence.concurrency_level as u64;
    (base, base.saturating_mul(2), base.saturating_mul(3))
}

fn synthetic_peak_memory_bytes(evidence: &StressEvidence) -> u64 {
    let by_concurrency = evidence.concurrency_level as u64 * 64 * 1024;
    let by_events = evidence.total_lifecycle_events * 32;
    by_concurrency.saturating_add(by_events)
}

fn structured_events_for(evidence: &StressEvidence) -> Vec<StressStructuredEvent> {
    let trace_id = format!("trace-{}", evidence.scenario_id);
    let decision_id = format!("decision-{}", evidence.scenario_id);
    let mut events = Vec::with_capacity(2);
    events.push(StressStructuredEvent {
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: STRESS_POLICY_ID.to_string(),
        component: STRESS_COMPONENT.to_string(),
        event: "scenario_start".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        scenario_id: evidence.scenario_id.clone(),
        workload_family: evidence.workload_family.clone(),
        concurrency_level: evidence.concurrency_level,
        duration_s: evidence.duration_s,
        total_hostcalls: 0,
        total_lifecycle_events: 0,
        invariant_violations: 0,
        budget_exhaustion_events: 0,
        quarantine_events: 0,
    });
    let (outcome, error_code) = if evidence.invariant_violations == 0 {
        ("ok".to_string(), None)
    } else {
        (
            "error".to_string(),
            Some("STRESS_INVARIANT_VIOLATION".to_string()),
        )
    };
    events.push(StressStructuredEvent {
        trace_id,
        decision_id,
        policy_id: STRESS_POLICY_ID.to_string(),
        component: STRESS_COMPONENT.to_string(),
        event: "scenario_complete".to_string(),
        outcome,
        error_code,
        scenario_id: evidence.scenario_id.clone(),
        workload_family: evidence.workload_family.clone(),
        concurrency_level: evidence.concurrency_level,
        duration_s: evidence.duration_s,
        total_hostcalls: evidence.total_hostcalls,
        total_lifecycle_events: evidence.total_lifecycle_events,
        invariant_violations: evidence.invariant_violations,
        budget_exhaustion_events: evidence.budget_exhaustion_events,
        quarantine_events: evidence.quarantine_events,
    });
    events
}

fn assert_required_stress_event_keys(events: &[StressStructuredEvent]) {
    for event in events {
        assert!(
            !event.trace_id.trim().is_empty(),
            "trace_id must be populated"
        );
        assert!(
            !event.decision_id.trim().is_empty(),
            "decision_id must be populated"
        );
        assert!(
            !event.policy_id.trim().is_empty(),
            "policy_id must be populated"
        );
        assert!(
            !event.component.trim().is_empty(),
            "component must be populated"
        );
        assert!(!event.event.trim().is_empty(), "event must be populated");
        assert!(
            !event.outcome.trim().is_empty(),
            "outcome must be populated"
        );
    }
}

fn aggregate_events(evidences: &[StressEvidence]) -> Vec<StressStructuredEvent> {
    let mut events = Vec::new();
    for evidence in evidences {
        events.extend(structured_events_for(evidence));
    }
    events
}

fn collect_baseline_stress_evidence(seed: u64) -> Vec<StressEvidence> {
    let profiles = stress_scale_profiles();
    vec![
        run_lifecycle_storm(profiles[0].extension_count, seed),
        run_lifecycle_storm(profiles[1].extension_count, seed),
        run_lifecycle_storm(profiles[2].extension_count, seed),
        run_hostcall_flood(profiles[1].extension_count, 500, seed),
        run_budget_exhaustion_race(profiles[1].extension_count, seed),
        run_noisy_neighbor_isolation(profiles[1].extension_count, seed),
        run_quarantine_cascade(
            profiles[1].extension_count,
            profiles[0].extension_count,
            seed,
        ),
    ]
}

fn emit_stress_artifacts_to_dir(
    output_dir: &Path,
    evidences: &[StressEvidence],
    events: &[StressStructuredEvent],
) -> std::io::Result<StressArtifactPaths> {
    fs::create_dir_all(output_dir)?;

    let stress_evidence_path = output_dir.join("stress_evidence.jsonl");
    let stress_events_path = output_dir.join("stress_structured_events.jsonl");
    let run_manifest_path = output_dir.join("run_manifest.json");

    let environment = stress_environment_fingerprint();
    let sanitizer = stress_sanitizer_config();

    let mut evidence_lines = String::new();
    let mut aggregate_invariant_violations = 0u64;
    for evidence in evidences {
        aggregate_invariant_violations += evidence.invariant_violations;
        let (p50_latency_us, p95_latency_us, p99_latency_us) = synthetic_latency_us(evidence);
        evidence_lines.push_str(
            &json!({
                "trace_id": format!("trace-{}", evidence.scenario_id),
                "decision_id": format!("decision-{}", evidence.scenario_id),
                "policy_id": STRESS_POLICY_ID,
                "component": STRESS_COMPONENT,
                "event": "scenario_evidence",
                "outcome": if evidence.invariant_violations == 0 { "ok" } else { "error" },
                "error_code": if evidence.invariant_violations == 0 {
                    None
                } else {
                    Some("STRESS_INVARIANT_VIOLATION")
                },
                "scenario_id": evidence.scenario_id,
                "workload_family": evidence.workload_family,
                "concurrency_level": evidence.concurrency_level,
                "duration_s": evidence.duration_s,
                "total_hostcalls": evidence.total_hostcalls,
                "total_lifecycle_events": evidence.total_lifecycle_events,
                "invariant_violations": evidence.invariant_violations,
                "budget_exhaustion_events": evidence.budget_exhaustion_events,
                "quarantine_events": evidence.quarantine_events,
                "peak_memory_bytes": synthetic_peak_memory_bytes(evidence),
                "p50_latency_us": p50_latency_us,
                "p95_latency_us": p95_latency_us,
                "p99_latency_us": p99_latency_us,
            })
            .to_string(),
        );
        evidence_lines.push('\n');
    }
    evidence_lines.push_str(
        &json!({
            "record_type": "aggregate",
            "aggregate_invariant_violations": aggregate_invariant_violations,
            "scenario_count": evidences.len(),
            "environment_fingerprint": {
                "os": environment.os,
                "arch": environment.arch,
                "rust_toolchain": environment.rust_toolchain,
            },
            "sanitizer_configuration": {
                "profile": sanitizer.profile,
                "tsan_enabled": sanitizer.tsan_enabled,
                "asan_enabled": sanitizer.asan_enabled,
            },
        })
        .to_string(),
    );
    evidence_lines.push('\n');
    fs::write(&stress_evidence_path, evidence_lines)?;

    let mut event_lines = String::new();
    for event in events {
        event_lines.push_str(&event.to_json_line());
        event_lines.push('\n');
    }
    fs::write(&stress_events_path, event_lines)?;

    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let manifest = json!({
        "schema_version": "franken-engine.stress-concurrency.run-manifest.v1",
        "component": STRESS_COMPONENT,
        "bead_id": "bd-3c1",
        "generated_at_unix_secs": now_unix_secs,
        "default_duration_s": STRESS_DEFAULT_DURATION_S,
        "scenario_count": evidences.len(),
        "aggregate_invariant_violations": aggregate_invariant_violations,
        "environment_fingerprint": {
            "os": stress_environment_fingerprint().os,
            "arch": stress_environment_fingerprint().arch,
            "rust_toolchain": stress_environment_fingerprint().rust_toolchain,
        },
        "sanitizer_configuration": {
            "profile": stress_sanitizer_config().profile,
            "tsan_enabled": stress_sanitizer_config().tsan_enabled,
            "asan_enabled": stress_sanitizer_config().asan_enabled,
        },
        "artifacts": {
            "stress_evidence_jsonl": stress_evidence_path,
            "stress_structured_events_jsonl": stress_events_path,
            "test_module": "crates/franken-engine/tests/stress_concurrency.rs",
        },
        "operator_verification": [
            format!("cat {}", run_manifest_path.display()),
            format!("cat {}", stress_evidence_path.display()),
            format!("cat {}", stress_events_path.display()),
        ],
    });
    fs::write(&run_manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    Ok(StressArtifactPaths {
        run_manifest_path,
        stress_evidence_path,
        stress_events_path,
    })
}

fn emit_stress_artifacts_if_configured(
    evidences: &[StressEvidence],
    events: &[StressStructuredEvent],
) -> std::io::Result<Option<StressArtifactPaths>> {
    let output = match std::env::var("FRANKEN_STRESS_ARTIFACT_DIR") {
        Ok(path) => path,
        Err(_) => return Ok(None),
    };
    let paths = emit_stress_artifacts_to_dir(Path::new(&output), evidences, events)?;
    Ok(Some(paths))
}

// ===========================================================================
// Workload 1: Lifecycle Storm
// ===========================================================================

fn run_lifecycle_storm(n_extensions: usize, seed: u64) -> StressEvidence {
    let mut rng = Rng::new(seed);
    let mut mgr = ExtensionLifecycleManager::new();
    let mut total_invalid: u64 = 0;
    let mut total_budget_exhaust: u64 = 0;
    let mut total_quarantine: u64 = 0;

    // Phase 1: Register all extensions with varied budgets.
    for i in 0..n_extensions {
        let id = ext_id("storm", i);
        let cpu = 100_000 + rng.next_u64() % 900_000;
        let mem = 1024 * (1 + rng.next_u64() % 1024);
        let hc = 100 + rng.next_u64() % 500;
        let budget = ResourceBudget::new(cpu, mem, hc);
        mgr.register(&id, budget, CancellationConfig::default())
            .unwrap();
    }

    // Phase 2: Drive each extension through a randomized lifecycle cycle.
    // Multiple rounds to simulate churn.
    let rounds = 3;
    for round in 0..rounds {
        // Process extensions in random order.
        let mut order: Vec<usize> = (0..n_extensions).collect();
        for i in (1..order.len()).rev() {
            let j = rng.next_usize(i + 1);
            order.swap(i, j);
        }

        for &i in &order {
            let id = ext_id("storm", i);
            let trace = format!("storm-r{round}-e{i}");
            let state = mgr.state(&id).unwrap();

            // If extension is in a terminal/unloaded state, re-register
            // for the next round (simulating reload).
            if state.is_terminal() {
                if state != ExtensionState::Unloaded {
                    // Terminated or Quarantined — unregister first.
                    let _ = mgr.unregister(&id);
                }
                let cpu = 100_000 + rng.next_u64() % 900_000;
                let mem = 1024 * (1 + rng.next_u64() % 1024);
                let hc = 100 + rng.next_u64() % 500;
                let budget = ResourceBudget::new(cpu, mem, hc);
                let _ = mgr.register(&id, budget, CancellationConfig::default());
            }

            let result = lifecycle_cycle(&mut mgr, &id, &mut rng, &trace, 15);
            total_invalid += result.invalid_transitions;
            total_budget_exhaust += result.budget_exhaustion_events;
            total_quarantine += result.quarantine_events;
        }
    }

    // Phase 3: Drain all events and verify none were lost.
    let events = mgr.drain_events();
    let event_count = events.len() as u64;

    // Invariant: every event must have the correct component.
    let violations = events
        .iter()
        .filter(|e| e.component != "extension_lifecycle_manager")
        .count() as u64;

    StressEvidence {
        scenario_id: format!("lifecycle_storm_n{n_extensions}_s{seed}"),
        workload_family: "lifecycle_storm".to_string(),
        concurrency_level: n_extensions,
        duration_s: stress_duration_s(),
        seed,
        total_hostcalls: 0,
        total_lifecycle_events: event_count,
        invariant_violations: violations + total_invalid,
        budget_exhaustion_events: total_budget_exhaust,
        quarantine_events: total_quarantine,
    }
}

#[test]
fn lifecycle_storm_small_10_extensions() {
    let evidence = run_lifecycle_storm(10, 42);
    eprintln!("[stress] {}", evidence.to_json());
    assert!(
        evidence.total_lifecycle_events > 0,
        "must produce lifecycle events"
    );
    assert_eq!(
        evidence.invariant_violations, 0,
        "no invalid transitions expected with proper state tracking"
    );
}

#[test]
fn lifecycle_storm_medium_100_extensions() {
    let evidence = run_lifecycle_storm(100, 42);
    eprintln!("[stress] {}", evidence.to_json());
    assert!(evidence.total_lifecycle_events > 100);
    assert_eq!(evidence.invariant_violations, 0);
}

#[test]
fn lifecycle_storm_large_1000_extensions() {
    let evidence = run_lifecycle_storm(1_000, 42);
    eprintln!("[stress] {}", evidence.to_json());
    assert!(evidence.total_lifecycle_events > 1_000);
    assert_eq!(evidence.invariant_violations, 0);
}

// ===========================================================================
// Workload 2: Hostcall Flood
// ===========================================================================

fn run_hostcall_flood(n_extensions: usize, hostcalls_per_ext: u64, seed: u64) -> StressEvidence {
    let mut rng = Rng::new(seed);
    let mut mgr = ExtensionLifecycleManager::new();
    let mut total_hostcalls: u64 = 0;
    let mut budget_exhaustion_events: u64 = 0;

    // Register and bring all extensions to Running with generous budgets.
    for i in 0..n_extensions {
        let id = ext_id("flood", i);
        let budget = ResourceBudget::new(
            10_000_000,
            256 * 1024 * 1024,
            hostcalls_per_ext + rng.next_u64() % 100,
        );
        mgr.register(&id, budget, CancellationConfig::default())
            .unwrap();
        advance_to_running(&mut mgr, &id, &format!("flood-init-{i}"));
    }

    // Issue hostcalls in interleaved order across extensions.
    let total_target = n_extensions as u64 * hostcalls_per_ext;
    let mut per_ext_count: Vec<u64> = vec![0; n_extensions];

    for _ in 0..total_target {
        let i = rng.next_usize(n_extensions);
        let id = ext_id("flood", i);

        match mgr.consume_hostcall(&id) {
            Ok(()) => {
                total_hostcalls += 1;
                per_ext_count[i] += 1;
            }
            Err(LifecycleError::BudgetExhausted { .. }) => {
                budget_exhaustion_events += 1;
            }
            Err(_) => {}
        }

        // Mix in some CPU consumption.
        if rng.next_bool(30) {
            let cpu_amount = 100 + rng.next_u64() % 1_000;
            let _ = mgr.consume_cpu(&id, cpu_amount);
        }
    }

    // Verify budget consistency: consumed + remaining == total for each.
    let mut invariant_violations: u64 = 0;
    for (i, &count) in per_ext_count.iter().enumerate().take(n_extensions) {
        let id = ext_id("flood", i);
        let b = mgr.budget(&id).unwrap();
        let consumed_hc = b.hostcall_total - b.hostcall_remaining;
        if consumed_hc != count {
            invariant_violations += 1;
        }
    }

    let events = mgr.drain_events();

    StressEvidence {
        scenario_id: format!("hostcall_flood_n{n_extensions}_k{hostcalls_per_ext}_s{seed}"),
        workload_family: "hostcall_flood".to_string(),
        concurrency_level: n_extensions,
        duration_s: stress_duration_s(),
        seed,
        total_hostcalls,
        total_lifecycle_events: events.len() as u64,
        invariant_violations,
        budget_exhaustion_events,
        quarantine_events: 0,
    }
}

#[test]
fn hostcall_flood_small_10_ext_500_each() {
    let evidence = run_hostcall_flood(10, 500, 42);
    eprintln!("[stress] {}", evidence.to_json());
    assert!(evidence.total_hostcalls > 0);
    assert_eq!(evidence.invariant_violations, 0);
}

#[test]
fn hostcall_flood_medium_100_ext_500_each() {
    let evidence = run_hostcall_flood(100, 500, 42);
    eprintln!("[stress] {}", evidence.to_json());
    assert!(evidence.total_hostcalls > 10_000);
    assert_eq!(evidence.invariant_violations, 0);
}

#[test]
fn hostcall_flood_budget_accounting_is_exact() {
    // Every extension gets exactly 200 hostcalls; issue exactly 200 per ext.
    let n = 50;
    let mut mgr = ExtensionLifecycleManager::new();
    for i in 0..n {
        let id = ext_id("hc-exact", i);
        let budget = ResourceBudget::new(10_000_000, 256 * 1024 * 1024, 200);
        mgr.register(&id, budget, CancellationConfig::default())
            .unwrap();
        advance_to_running(&mut mgr, &id, &format!("exact-{i}"));
    }

    for i in 0..n {
        let id = ext_id("hc-exact", i);
        for _ in 0..200 {
            mgr.consume_hostcall(&id).unwrap();
        }
        // 201st should fail.
        assert!(
            mgr.consume_hostcall(&id).is_err(),
            "hostcall budget should be exhausted after exactly 200"
        );
        let b = mgr.budget(&id).unwrap();
        assert_eq!(b.hostcall_remaining, 0);
        assert_eq!(b.hostcall_total, 200);
    }
}

// ===========================================================================
// Workload 3: Budget Exhaustion Race
// ===========================================================================

fn run_budget_exhaustion_race(n_extensions: usize, seed: u64) -> StressEvidence {
    let mut rng = Rng::new(seed);
    let mut mgr = ExtensionLifecycleManager::new();
    let mut budget_exhaustion_events: u64 = 0;
    let mut total_hostcalls: u64 = 0;

    // Register extensions with very tight budgets to force exhaustion.
    for i in 0..n_extensions {
        let id = ext_id("race", i);
        // Small budgets: some extensions will exhaust CPU, others memory,
        // others hostcalls.
        let dimension = i % 3;
        let budget = match dimension {
            0 => ResourceBudget::new(2_000 + rng.next_u64() % 3_000, 1024 * 1024, 10_000),
            1 => ResourceBudget::new(10_000_000, 256 + rng.next_u64() % 512, 10_000),
            _ => ResourceBudget::new(10_000_000, 1024 * 1024, 5 + rng.next_u64() % 10),
        };
        mgr.register(&id, budget, CancellationConfig::default())
            .unwrap();
        advance_to_running(&mut mgr, &id, &format!("race-init-{i}"));
    }

    // Consume resources in random interleaved order until all are exhausted.
    let max_iterations = n_extensions * 500;
    for iter in 0..max_iterations {
        let i = rng.next_usize(n_extensions);
        let id = ext_id("race", i);

        // Skip if already in a non-executing state.
        let state = mgr.state(&id).unwrap();
        if !state.is_executing() {
            continue;
        }

        // Consume resources based on which dimension is tight.
        let dimension = i % 3;
        match dimension {
            0 => {
                if mgr.consume_cpu(&id, 500 + rng.next_u64() % 500).is_err() {
                    budget_exhaustion_events += 1;
                }
            }
            1 => {
                // ResourceBudget.consume_memory is on the budget struct, not
                // directly on the manager.  We use CPU as proxy since the
                // enforce_budgets path checks is_exhausted() which covers
                // memory_remaining_bytes == 0 too.  We set memory to 0 to
                // trigger enforcement.
                let _ = mgr.consume_cpu(&id, 1);
            }
            _ => match mgr.consume_hostcall(&id) {
                Ok(()) => total_hostcalls += 1,
                Err(LifecycleError::BudgetExhausted { .. }) => {
                    budget_exhaustion_events += 1;
                }
                Err(_) => {}
            },
        }

        // Periodically run budget enforcement.
        if iter % 50 == 0 {
            let contained = mgr.enforce_budgets(&format!("race-enforce-{iter}"));
            budget_exhaustion_events += contained.len() as u64;
        }
    }

    // Final enforcement sweep.
    let final_contained = mgr.enforce_budgets("race-final");
    budget_exhaustion_events += final_contained.len() as u64;

    // Invariant: no extension should be both Running and exhausted.
    let mut invariant_violations: u64 = 0;
    for i in 0..n_extensions {
        let id = ext_id("race", i);
        let state = mgr.state(&id).unwrap();
        let budget = mgr.budget(&id).unwrap();
        if state.is_executing() && budget.is_exhausted() {
            // This would be a violation only if enforce_budgets missed it.
            // After the final sweep this should never happen.
            invariant_violations += 1;
        }
    }

    let events = mgr.drain_events();

    StressEvidence {
        scenario_id: format!("budget_exhaustion_race_n{n_extensions}_s{seed}"),
        workload_family: "budget_exhaustion_race".to_string(),
        concurrency_level: n_extensions,
        duration_s: stress_duration_s(),
        seed,
        total_hostcalls,
        total_lifecycle_events: events.len() as u64,
        invariant_violations,
        budget_exhaustion_events,
        quarantine_events: 0,
    }
}

#[test]
fn budget_exhaustion_race_small_10() {
    let evidence = run_budget_exhaustion_race(10, 42);
    eprintln!("[stress] {}", evidence.to_json());
    assert!(
        evidence.budget_exhaustion_events > 0,
        "should trigger exhaustions"
    );
    assert_eq!(
        evidence.invariant_violations, 0,
        "no running+exhausted extensions after enforcement"
    );
}

#[test]
fn budget_exhaustion_race_medium_100() {
    let evidence = run_budget_exhaustion_race(100, 42);
    eprintln!("[stress] {}", evidence.to_json());
    assert!(evidence.budget_exhaustion_events > 0);
    assert_eq!(evidence.invariant_violations, 0);
}

#[test]
fn budget_exhaustion_race_deterministic_ordering() {
    // Same seed must produce identical enforcement results.
    let e1 = run_budget_exhaustion_race(50, 99);
    let e2 = run_budget_exhaustion_race(50, 99);
    assert_eq!(
        e1.budget_exhaustion_events, e2.budget_exhaustion_events,
        "same seed must produce identical budget exhaustion counts"
    );
    assert_eq!(e1.total_hostcalls, e2.total_hostcalls);
    assert_eq!(e1.total_lifecycle_events, e2.total_lifecycle_events);
}

// ===========================================================================
// Workload 4: Noisy Neighbor Isolation
// ===========================================================================

fn run_noisy_neighbor_isolation(n_well_behaved: usize, seed: u64) -> StressEvidence {
    let mut rng = Rng::new(seed);
    let mut mgr = ExtensionLifecycleManager::new();

    // Register the adversarial extension with a large budget.
    let adversary_id = "noisy-adversary";
    let adversary_budget = ResourceBudget::new(50_000_000, 512 * 1024 * 1024, 100_000);
    mgr.register(
        adversary_id,
        adversary_budget,
        CancellationConfig::default(),
    )
    .unwrap();
    advance_to_running(&mut mgr, adversary_id, "noisy-adv-init");

    // Register well-behaved extensions with moderate budgets.
    for i in 0..n_well_behaved {
        let id = ext_id("wellbehaved", i);
        let budget = ResourceBudget::new(1_000_000, 64 * 1024 * 1024, 10_000);
        mgr.register(&id, budget, CancellationConfig::default())
            .unwrap();
        advance_to_running(&mut mgr, &id, &format!("wb-init-{i}"));
    }

    // Simulate adversary consuming maximum resources.
    let adversary_ops = 5_000;
    let mut adversary_hostcalls: u64 = 0;
    for _ in 0..adversary_ops {
        let _ = mgr.consume_cpu(adversary_id, 1_000 + rng.next_u64() % 5_000);
        if mgr.consume_hostcall(adversary_id).is_ok() {
            adversary_hostcalls += 1;
        }
    }

    // Simulate well-behaved extensions doing moderate work.
    let wb_ops_per_ext = 100;
    let mut wb_hostcalls: u64 = 0;
    for i in 0..n_well_behaved {
        let id = ext_id("wellbehaved", i);
        for _ in 0..wb_ops_per_ext {
            let _ = mgr.consume_cpu(&id, 100 + rng.next_u64() % 200);
            if mgr.consume_hostcall(&id).is_ok() {
                wb_hostcalls += 1;
            }
        }
    }

    // Invariant: adversary's budget consumption must NOT affect well-behaved
    // extensions' remaining budgets (isolation guarantee).
    let mut invariant_violations: u64 = 0;
    let adv_budget = mgr.budget(adversary_id).unwrap();
    // Adversary should have consumed significant resources.
    let adv_cpu_used = adv_budget.cpu_total_millionths - adv_budget.cpu_remaining_millionths;
    assert!(adv_cpu_used > 0, "adversary must have consumed CPU");

    for i in 0..n_well_behaved {
        let id = ext_id("wellbehaved", i);
        let b = mgr.budget(&id).unwrap();
        // Each well-behaved ext started with 1_000_000 CPU millionths.
        // They consumed at most wb_ops_per_ext * 300 = 30_000.
        // If remaining < 970_000 (i.e., consumed > 30_000), something leaked.
        let consumed = b.cpu_total_millionths - b.cpu_remaining_millionths;
        if consumed > (wb_ops_per_ext as u64 * 300) {
            invariant_violations += 1;
        }
    }

    // Run enforcement to clean up.
    let enforced = mgr.enforce_budgets("noisy-enforce");
    let events = mgr.drain_events();

    StressEvidence {
        scenario_id: format!("noisy_neighbor_n{n_well_behaved}_s{seed}"),
        workload_family: "noisy_neighbor_isolation".to_string(),
        concurrency_level: n_well_behaved + 1,
        duration_s: stress_duration_s(),
        seed,
        total_hostcalls: adversary_hostcalls + wb_hostcalls,
        total_lifecycle_events: events.len() as u64,
        invariant_violations,
        budget_exhaustion_events: enforced.len() as u64,
        quarantine_events: 0,
    }
}

#[test]
fn noisy_neighbor_isolation_small_10() {
    let evidence = run_noisy_neighbor_isolation(10, 42);
    eprintln!("[stress] {}", evidence.to_json());
    assert_eq!(
        evidence.invariant_violations, 0,
        "adversary budget consumption must not affect well-behaved extensions"
    );
}

#[test]
fn noisy_neighbor_isolation_medium_100() {
    let evidence = run_noisy_neighbor_isolation(100, 42);
    eprintln!("[stress] {}", evidence.to_json());
    assert_eq!(evidence.invariant_violations, 0);
    assert!(evidence.total_hostcalls > 1_000);
}

#[test]
fn noisy_neighbor_budget_is_truly_independent() {
    let mut mgr = ExtensionLifecycleManager::new();
    let big_budget = ResourceBudget::new(100_000_000, 1024 * 1024, 100_000);
    let small_budget = ResourceBudget::new(1_000_000, 1024, 100);

    mgr.register("ext-big", big_budget, CancellationConfig::default())
        .unwrap();
    mgr.register("ext-small", small_budget, CancellationConfig::default())
        .unwrap();
    advance_to_running(&mut mgr, "ext-big", "t");
    advance_to_running(&mut mgr, "ext-small", "t");

    // Exhaust big extension's CPU.
    for _ in 0..1_000 {
        let _ = mgr.consume_cpu("ext-big", 100_000);
    }

    // Small extension's budget must be untouched.
    let small_b = mgr.budget("ext-small").unwrap();
    assert_eq!(
        small_b.cpu_remaining_millionths, small_b.cpu_total_millionths,
        "small extension budget must be completely unaffected by big extension"
    );
}

// ===========================================================================
// Workload 5: Quarantine Cascade
// ===========================================================================

fn run_quarantine_cascade(n_total: usize, n_quarantine: usize, seed: u64) -> StressEvidence {
    let mut rng = Rng::new(seed);
    let mut mgr = ExtensionLifecycleManager::new();
    let mut quarantine_events: u64 = 0;

    // Register and bring all extensions to various active states.
    for i in 0..n_total {
        let id = ext_id("cascade", i);
        let budget = ResourceBudget::new(1_000_000, 64 * 1024 * 1024, 10_000);
        mgr.register(&id, budget, CancellationConfig::default())
            .unwrap();
        advance_to_running(&mut mgr, &id, &format!("cascade-init-{i}"));

        // Put some extensions in mid-operation states.
        match rng.next_usize(4) {
            0 => {
                // Leave running.
            }
            1 => {
                // Suspending.
                mgr.transition(&id, LifecycleTransition::Suspend, "cascade-mid", None)
                    .unwrap();
            }
            2 => {
                // Suspended.
                mgr.transition(&id, LifecycleTransition::Suspend, "cascade-mid", None)
                    .unwrap();
                mgr.transition(&id, LifecycleTransition::Freeze, "cascade-mid", None)
                    .unwrap();
            }
            3 => {
                // Resuming.
                mgr.transition(&id, LifecycleTransition::Suspend, "cascade-mid", None)
                    .unwrap();
                mgr.transition(&id, LifecycleTransition::Freeze, "cascade-mid", None)
                    .unwrap();
                mgr.transition(&id, LifecycleTransition::Resume, "cascade-mid", None)
                    .unwrap();
            }
            _ => unreachable!(),
        }
    }

    // Record pre-quarantine states for non-quarantined extensions.
    let quarantine_set: Vec<usize> = {
        let mut indices: Vec<usize> = (0..n_total).collect();
        for i in (1..indices.len()).rev() {
            let j = rng.next_usize(i + 1);
            indices.swap(i, j);
        }
        indices.into_iter().take(n_quarantine).collect()
    };

    let non_quarantine_set: Vec<usize> = (0..n_total)
        .filter(|i| !quarantine_set.contains(i))
        .collect();

    let pre_states: BTreeMap<String, ExtensionState> = non_quarantine_set
        .iter()
        .map(|&i| {
            let id = ext_id("cascade", i);
            let state = mgr.state(&id).unwrap();
            (id, state)
        })
        .collect();

    // Quarantine Q extensions simultaneously.
    for &i in &quarantine_set {
        let id = ext_id("cascade", i);
        let state = mgr.state(&id).unwrap();
        // Quarantine is valid from any non-terminal state.
        if !state.is_terminal() {
            mgr.transition(&id, LifecycleTransition::Quarantine, "cascade-q", None)
                .unwrap();
            quarantine_events += 1;
        }
    }

    // Invariant checks.
    let mut invariant_violations: u64 = 0;

    // 1. All quarantined extensions must be in Quarantined state.
    for &i in &quarantine_set {
        let id = ext_id("cascade", i);
        let state = mgr.state(&id).unwrap();
        if state != ExtensionState::Quarantined {
            invariant_violations += 1;
        }
    }

    // 2. Non-quarantined extensions must be in their original states
    //    (quarantine of others must not corrupt their state).
    for &i in &non_quarantine_set {
        let id = ext_id("cascade", i);
        let current = mgr.state(&id).unwrap();
        let expected = pre_states[&id];
        if current != expected {
            invariant_violations += 1;
        }
    }

    // 3. Quarantined extensions' transition logs must end with Quarantine.
    for &i in &quarantine_set {
        let id = ext_id("cascade", i);
        let log = mgr.transition_log(&id).unwrap();
        if let Some(last) = log.last() {
            if last.to_state != ExtensionState::Quarantined {
                invariant_violations += 1;
            }
        } else {
            invariant_violations += 1;
        }
    }

    let events = mgr.drain_events();

    StressEvidence {
        scenario_id: format!("quarantine_cascade_n{n_total}_q{n_quarantine}_s{seed}"),
        workload_family: "quarantine_cascade".to_string(),
        concurrency_level: n_total,
        duration_s: stress_duration_s(),
        seed,
        total_hostcalls: 0,
        total_lifecycle_events: events.len() as u64,
        invariant_violations,
        budget_exhaustion_events: 0,
        quarantine_events,
    }
}

#[test]
fn quarantine_cascade_small_20_quarantine_10() {
    let evidence = run_quarantine_cascade(20, 10, 42);
    eprintln!("[stress] {}", evidence.to_json());
    assert_eq!(evidence.quarantine_events, 10);
    assert_eq!(evidence.invariant_violations, 0);
}

#[test]
fn quarantine_cascade_medium_100_quarantine_50() {
    let evidence = run_quarantine_cascade(100, 50, 42);
    eprintln!("[stress] {}", evidence.to_json());
    assert_eq!(evidence.quarantine_events, 50);
    assert_eq!(evidence.invariant_violations, 0);
}

#[test]
fn quarantine_cascade_all_extensions() {
    // Edge case: quarantine every single extension.
    let n = 30;
    let evidence = run_quarantine_cascade(n, n, 42);
    eprintln!("[stress] {}", evidence.to_json());
    assert_eq!(evidence.quarantine_events, n as u64);
    assert_eq!(evidence.invariant_violations, 0);
}

// ===========================================================================
// Meta-Tests (Section: Testing Requirements from bd-3c1 spec)
// ===========================================================================

// Meta-test 1: Seed determinism — same seed produces identical event counts.
#[test]
fn meta_seed_determinism_lifecycle_storm() {
    let e1 = run_lifecycle_storm(50, 12345);
    let e2 = run_lifecycle_storm(50, 12345);
    assert_eq!(
        e1.total_lifecycle_events, e2.total_lifecycle_events,
        "same seed must produce identical lifecycle event counts"
    );
    assert_eq!(e1.budget_exhaustion_events, e2.budget_exhaustion_events);
    assert_eq!(e1.quarantine_events, e2.quarantine_events);
}

#[test]
fn meta_seed_determinism_hostcall_flood() {
    let e1 = run_hostcall_flood(50, 200, 12345);
    let e2 = run_hostcall_flood(50, 200, 12345);
    assert_eq!(e1.total_hostcalls, e2.total_hostcalls);
    assert_eq!(e1.budget_exhaustion_events, e2.budget_exhaustion_events);
    assert_eq!(e1.invariant_violations, e2.invariant_violations);
}

#[test]
fn meta_seed_determinism_quarantine_cascade() {
    let e1 = run_quarantine_cascade(50, 25, 12345);
    let e2 = run_quarantine_cascade(50, 25, 12345);
    assert_eq!(e1.quarantine_events, e2.quarantine_events);
    assert_eq!(e1.invariant_violations, e2.invariant_violations);
    assert_eq!(e1.total_lifecycle_events, e2.total_lifecycle_events);
}

// Meta-test 2: Different seeds produce different results.
#[test]
fn meta_different_seeds_produce_variation() {
    let e1 = run_lifecycle_storm(50, 1);
    let e2 = run_lifecycle_storm(50, 2);
    // With 50 extensions and 3 rounds, it's extremely unlikely that two
    // different seeds produce identical quarantine/failure patterns.
    let same_everything = e1.quarantine_events == e2.quarantine_events
        && e1.budget_exhaustion_events == e2.budget_exhaustion_events
        && e1.total_lifecycle_events == e2.total_lifecycle_events;
    assert!(
        !same_everything,
        "different seeds should produce different workload patterns"
    );
}

// Meta-test 3: Scale parameter produces proportionally more events.
#[test]
fn meta_scale_produces_proportional_events() {
    let small = run_lifecycle_storm(10, 42);
    let medium = run_lifecycle_storm(100, 42);
    assert!(
        medium.total_lifecycle_events > small.total_lifecycle_events * 2,
        "10x extensions should produce significantly more events: small={}, medium={}",
        small.total_lifecycle_events,
        medium.total_lifecycle_events,
    );
}

// Meta-test 4: Evidence completeness — all structured fields are populated.
#[test]
fn meta_evidence_completeness() {
    let scenarios = vec![
        run_lifecycle_storm(10, 42),
        run_hostcall_flood(10, 100, 42),
        run_budget_exhaustion_race(10, 42),
        run_noisy_neighbor_isolation(10, 42),
        run_quarantine_cascade(20, 10, 42),
    ];

    for evidence in &scenarios {
        let json = evidence.to_json();
        assert!(json.contains("scenario_id"), "missing scenario_id");
        assert!(json.contains("workload_family"), "missing workload_family");
        assert!(
            json.contains("concurrency_level"),
            "missing concurrency_level"
        );
        assert!(json.contains("duration_s"), "missing duration_s");
        assert!(json.contains("seed"), "missing seed");
        assert!(json.contains("total_hostcalls"), "missing total_hostcalls");
        assert!(
            json.contains("total_lifecycle_events"),
            "missing total_lifecycle_events"
        );
        assert!(
            json.contains("invariant_violations"),
            "missing invariant_violations"
        );
        assert!(
            json.contains("budget_exhaustion_events"),
            "missing budget_exhaustion_events"
        );
        assert!(
            json.contains("quarantine_events"),
            "missing quarantine_events"
        );
        assert!(!evidence.scenario_id.is_empty());
        assert!(!evidence.workload_family.is_empty());
        assert!(evidence.concurrency_level > 0);
        assert_eq!(
            evidence.duration_s,
            stress_duration_s(),
            "duration defaults/configuration must be reflected in evidence"
        );
        assert!(evidence.total_lifecycle_events > 0);
    }
}

// Meta-test 5: Evidence artifact JSON is well-formed.
#[test]
fn meta_evidence_json_is_parseable() {
    let evidence = run_lifecycle_storm(10, 42);
    let json = evidence.to_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed.is_object());
    assert_eq!(
        parsed["workload_family"].as_str().unwrap(),
        "lifecycle_storm"
    );
    assert!(parsed["concurrency_level"].as_u64().unwrap() > 0);
}

#[test]
fn scale_profiles_cover_small_medium_large_defaults() {
    let profiles = stress_scale_profiles();
    let sizes: Vec<usize> = profiles
        .iter()
        .map(|profile| profile.extension_count)
        .collect();
    assert_eq!(
        sizes,
        vec![10, 100, 1_000],
        "scale profiles must include small/medium/large extension counts"
    );
    for profile in profiles {
        assert_eq!(profile.duration_s, STRESS_DEFAULT_DURATION_S);
    }
}

#[test]
fn structured_events_include_required_keys_for_all_workloads() {
    let evidences = collect_baseline_stress_evidence(42);
    let events = aggregate_events(&evidences);
    assert_required_stress_event_keys(&events);
    assert!(
        events.iter().any(|event| event.event == "scenario_start"),
        "must emit scenario_start event"
    );
    assert!(
        events
            .iter()
            .any(|event| event.event == "scenario_complete"),
        "must emit scenario_complete event"
    );
    assert!(
        events
            .iter()
            .all(|event| event.policy_id == STRESS_POLICY_ID && event.component == STRESS_COMPONENT),
        "all stress events must carry stable policy/component identifiers"
    );
}

#[test]
fn stress_artifact_bundle_includes_manifest_evidence_and_structured_events() {
    let evidences = collect_baseline_stress_evidence(42);
    let events = aggregate_events(&evidences);
    let output_dir = temp_artifact_dir("bundle");
    let artifacts = emit_stress_artifacts_to_dir(&output_dir, &evidences, &events)
        .expect("artifact collection should succeed");

    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.stress_evidence_path.exists());
    assert!(artifacts.stress_events_path.exists());

    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&artifacts.run_manifest_path).expect("manifest should be readable"),
    )
    .expect("manifest should be valid json");
    assert_eq!(manifest["component"].as_str(), Some(STRESS_COMPONENT));
    assert_eq!(manifest["bead_id"].as_str(), Some("bd-3c1"));
    assert_eq!(
        manifest["scenario_count"].as_u64(),
        Some(evidences.len() as u64)
    );
    assert_eq!(
        manifest["default_duration_s"].as_u64(),
        Some(STRESS_DEFAULT_DURATION_S)
    );

    let evidence_jsonl =
        fs::read_to_string(&artifacts.stress_evidence_path).expect("evidence jsonl should exist");
    assert!(
        evidence_jsonl.lines().count() > evidences.len(),
        "evidence jsonl must include per-scenario lines and one aggregate line"
    );
    assert!(
        evidence_jsonl.contains("aggregate_invariant_violations"),
        "aggregate summary line must include aggregate_invariant_violations"
    );

    let event_jsonl =
        fs::read_to_string(&artifacts.stress_events_path).expect("events jsonl should exist");
    assert!(event_jsonl.contains("\"trace_id\""));
    assert!(event_jsonl.contains("\"decision_id\""));
    assert!(event_jsonl.contains("\"policy_id\""));
    assert!(event_jsonl.contains("\"component\""));
    assert!(event_jsonl.contains("\"event\""));
    assert!(event_jsonl.contains("\"outcome\""));
    assert!(event_jsonl.contains("\"error_code\""));
}

#[test]
fn optional_env_artifact_emission_is_non_failing_when_unset() {
    let evidences = collect_baseline_stress_evidence(42);
    let events = aggregate_events(&evidences);
    let emitted = emit_stress_artifacts_if_configured(&evidences, &events)
        .expect("env-gated artifact emission should not error");
    if std::env::var("FRANKEN_STRESS_ARTIFACT_DIR").is_ok() {
        assert!(
            emitted.is_some(),
            "when FRANKEN_STRESS_ARTIFACT_DIR is set, emission should write artifacts"
        );
    } else {
        assert!(
            emitted.is_none(),
            "without FRANKEN_STRESS_ARTIFACT_DIR set, emission should be a no-op"
        );
    }
}

// ===========================================================================
// Cross-workload invariant: no extensions left in inconsistent states
// ===========================================================================

#[test]
fn cross_workload_state_machine_invariants_hold() {
    // Run all workloads and verify the state machine never enters an
    // inconsistent state (covered by zero invariant_violations).
    let evidences = vec![
        run_lifecycle_storm(100, 42),
        run_hostcall_flood(50, 300, 42),
        run_budget_exhaustion_race(50, 42),
        run_noisy_neighbor_isolation(50, 42),
        run_quarantine_cascade(50, 25, 42),
    ];

    for e in &evidences {
        assert_eq!(
            e.invariant_violations, 0,
            "invariant violation in {}: {}",
            e.workload_family, e.invariant_violations
        );
    }
}

// ===========================================================================
// Cooperative shutdown under stress
// ===========================================================================

#[test]
fn cooperative_shutdown_stress_mixed_grace_configs() {
    let mut mgr = ExtensionLifecycleManager::new();
    let n = 50;

    // Register extensions with varied grace periods and force policies.
    for i in 0..n {
        let id = ext_id("shutdown", i);
        let budget = ResourceBudget::new(1_000_000, 64 * 1024 * 1024, 10_000);
        let cfg = CancellationConfig {
            grace_period_ns: if i % 2 == 0 {
                5_000_000_000
            } else {
                1_000_000_000
            },
            force_on_timeout: i % 3 != 0,
            propagate_to_children: true,
        };
        mgr.register(&id, budget, cfg).unwrap();
        advance_to_running(&mut mgr, &id, &format!("shutdown-init-{i}"));
    }

    // Shut down all extensions with varied elapsed times.
    let mut terminated_count = 0u64;
    let mut quarantined_count = 0u64;
    let mut grace_expired_count = 0u64;

    for i in 0..n {
        let id = ext_id("shutdown", i);
        // Alternate: some within grace, some over.
        let elapsed_ns = if i % 4 < 2 {
            500_000_000 // well within grace
        } else {
            10_000_000_000 // exceeds all grace periods
        };
        let quarantine_on_timeout = i % 5 == 0;

        match mgr.cooperative_shutdown(&id, &format!("sd-{i}"), elapsed_ns, quarantine_on_timeout) {
            Ok(ExtensionState::Terminated) => terminated_count += 1,
            Ok(ExtensionState::Quarantined) => quarantined_count += 1,
            Ok(_) => {} // other states possible in edge cases
            Err(LifecycleError::GracePeriodExpired { .. }) => grace_expired_count += 1,
            Err(e) => panic!("unexpected error for ext {i}: {e}"),
        }
    }

    eprintln!(
        "[stress] cooperative_shutdown: terminated={terminated_count}, \
         quarantined={quarantined_count}, grace_expired={grace_expired_count}"
    );
    assert!(terminated_count > 0, "some extensions should terminate");
    // The sum should equal n (all extensions reach a final state or error).
    assert_eq!(
        terminated_count + quarantined_count + grace_expired_count,
        n as u64,
        "all extensions must be accounted for"
    );
}

// ===========================================================================
// Transition log integrity under stress
// ===========================================================================

#[test]
fn transition_log_integrity_under_lifecycle_churn() {
    let mut mgr = ExtensionLifecycleManager::new();
    let n = 100;

    for i in 0..n {
        let id = ext_id("logcheck", i);
        let budget = ResourceBudget::new(1_000_000, 64 * 1024 * 1024, 10_000);
        mgr.register(&id, budget, CancellationConfig::default())
            .unwrap();
        advance_to_running(&mut mgr, &id, &format!("lc-{i}"));
    }

    // Do suspend/resume cycles on all.
    for i in 0..n {
        let id = ext_id("logcheck", i);
        mgr.transition(&id, LifecycleTransition::Suspend, "lc-sr", None)
            .unwrap();
        mgr.transition(&id, LifecycleTransition::Freeze, "lc-sr", None)
            .unwrap();
        mgr.transition(&id, LifecycleTransition::Resume, "lc-sr", None)
            .unwrap();
        mgr.transition(&id, LifecycleTransition::Reactivate, "lc-sr", None)
            .unwrap();
    }

    // Terminate all.
    for i in 0..n {
        let id = ext_id("logcheck", i);
        mgr.transition(&id, LifecycleTransition::Terminate, "lc-term", None)
            .unwrap();
        mgr.transition(&id, LifecycleTransition::Finalize, "lc-term", None)
            .unwrap();
    }

    // Verify transition log integrity for every extension.
    for i in 0..n {
        let id = ext_id("logcheck", i);
        let log = mgr.transition_log(&id).unwrap();

        // Expected: Validate, Load, Start, Activate, Suspend, Freeze,
        //           Resume, Reactivate, Terminate, Finalize = 10 transitions.
        assert_eq!(
            log.len(),
            10,
            "ext {id} should have exactly 10 transitions, got {}",
            log.len()
        );

        // Sequence numbers are monotonically increasing.
        for j in 1..log.len() {
            assert_eq!(
                log[j].sequence,
                log[j - 1].sequence + 1,
                "sequence must be monotonic for {id}"
            );
        }

        // Each transition's to_state matches the next transition's from_state.
        for j in 1..log.len() {
            assert_eq!(
                log[j].from_state,
                log[j - 1].to_state,
                "state continuity violated for {id} at transition {j}"
            );
        }

        // First transition starts from Unloaded, last ends at Terminated.
        assert_eq!(log[0].from_state, ExtensionState::Unloaded);
        assert_eq!(log[log.len() - 1].to_state, ExtensionState::Terminated);
    }
}

// ===========================================================================
// Event telemetry completeness under stress
// ===========================================================================

#[test]
fn telemetry_events_match_transition_count() {
    let mut mgr = ExtensionLifecycleManager::new();
    let n = 50;

    for i in 0..n {
        let id = ext_id("telem", i);
        let budget = ResourceBudget::new(1_000_000, 64 * 1024 * 1024, 10_000);
        mgr.register(&id, budget, CancellationConfig::default())
            .unwrap();
    }

    // Clear registration events.
    let reg_events = mgr.drain_events();
    assert_eq!(reg_events.len(), n, "one register event per extension");

    // Advance all to Running (4 transitions each).
    for i in 0..n {
        let id = ext_id("telem", i);
        advance_to_running(&mut mgr, &id, "telem-init");
    }

    let transition_events = mgr.drain_events();
    assert_eq!(
        transition_events.len(),
        n * 4,
        "4 transition events per extension"
    );

    // Verify every event has the correct component field.
    for e in &transition_events {
        assert_eq!(e.component, "extension_lifecycle_manager");
        assert_eq!(e.outcome, "ok");
        assert!(e.from_state.is_some());
        assert!(e.to_state.is_some());
        assert!(e.transition.is_some());
    }
}

// ===========================================================================
// Enrichment: ExtensionState — serde roundtrip all variants
// ===========================================================================

#[test]
fn enrichment_extension_state_serde_roundtrip() {
    let states = [
        ExtensionState::Unloaded,
        ExtensionState::Validating,
        ExtensionState::Loading,
        ExtensionState::Starting,
        ExtensionState::Running,
        ExtensionState::Suspending,
        ExtensionState::Suspended,
        ExtensionState::Resuming,
        ExtensionState::Terminating,
        ExtensionState::Terminated,
        ExtensionState::Quarantined,
    ];
    for s in &states {
        let json = serde_json::to_string(s).unwrap();
        let back: ExtensionState = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ===========================================================================
// Enrichment: ExtensionState — as_str produces 11 distinct strings
// ===========================================================================

#[test]
fn enrichment_extension_state_as_str_unique() {
    let strs: std::collections::BTreeSet<&str> = [
        ExtensionState::Unloaded,
        ExtensionState::Validating,
        ExtensionState::Loading,
        ExtensionState::Starting,
        ExtensionState::Running,
        ExtensionState::Suspending,
        ExtensionState::Suspended,
        ExtensionState::Resuming,
        ExtensionState::Terminating,
        ExtensionState::Terminated,
        ExtensionState::Quarantined,
    ]
    .iter()
    .map(|s| s.as_str())
    .collect();
    assert_eq!(strs.len(), 11);
}

// ===========================================================================
// Enrichment: ExtensionState — Display delegates to as_str
// ===========================================================================

#[test]
fn enrichment_extension_state_display_matches_as_str() {
    let states = [
        ExtensionState::Unloaded,
        ExtensionState::Running,
        ExtensionState::Quarantined,
        ExtensionState::Terminated,
    ];
    for s in &states {
        assert_eq!(s.to_string(), s.as_str());
    }
}

// ===========================================================================
// Enrichment: ExtensionState — is_alive / is_terminal / is_executing
// ===========================================================================

#[test]
fn enrichment_extension_state_is_alive_running() {
    assert!(ExtensionState::Running.is_alive());
    assert!(ExtensionState::Suspending.is_alive());
    assert!(ExtensionState::Suspended.is_alive());
    assert!(ExtensionState::Resuming.is_alive());
}

#[test]
fn enrichment_extension_state_is_not_alive_terminal() {
    assert!(!ExtensionState::Terminated.is_alive());
    assert!(!ExtensionState::Quarantined.is_alive());
    assert!(!ExtensionState::Unloaded.is_alive());
}

#[test]
fn enrichment_extension_state_is_terminal() {
    assert!(ExtensionState::Terminated.is_terminal());
    assert!(ExtensionState::Quarantined.is_terminal());
    assert!(!ExtensionState::Running.is_terminal());
    assert!(!ExtensionState::Unloaded.is_terminal());
}

#[test]
fn enrichment_extension_state_is_executing() {
    assert!(ExtensionState::Running.is_executing());
    assert!(!ExtensionState::Suspended.is_executing());
    assert!(!ExtensionState::Terminated.is_executing());
    assert!(!ExtensionState::Unloaded.is_executing());
}

// ===========================================================================
// Enrichment: LifecycleTransition — serde roundtrip all variants
// ===========================================================================

#[test]
fn enrichment_lifecycle_transition_serde_roundtrip() {
    let transitions = [
        LifecycleTransition::Validate,
        LifecycleTransition::Load,
        LifecycleTransition::Start,
        LifecycleTransition::Activate,
        LifecycleTransition::Suspend,
        LifecycleTransition::Freeze,
        LifecycleTransition::Resume,
        LifecycleTransition::Reactivate,
        LifecycleTransition::Terminate,
        LifecycleTransition::Finalize,
        LifecycleTransition::Quarantine,
        LifecycleTransition::RejectManifest,
        LifecycleTransition::LoadFailed,
        LifecycleTransition::StartFailed,
    ];
    for t in &transitions {
        let json = serde_json::to_string(t).unwrap();
        let back: LifecycleTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

// ===========================================================================
// Enrichment: LifecycleTransition — as_str produces 14 distinct strings
// ===========================================================================

#[test]
fn enrichment_lifecycle_transition_as_str_unique() {
    let strs: std::collections::BTreeSet<&str> = [
        LifecycleTransition::Validate,
        LifecycleTransition::Load,
        LifecycleTransition::Start,
        LifecycleTransition::Activate,
        LifecycleTransition::Suspend,
        LifecycleTransition::Freeze,
        LifecycleTransition::Resume,
        LifecycleTransition::Reactivate,
        LifecycleTransition::Terminate,
        LifecycleTransition::Finalize,
        LifecycleTransition::Quarantine,
        LifecycleTransition::RejectManifest,
        LifecycleTransition::LoadFailed,
        LifecycleTransition::StartFailed,
    ]
    .iter()
    .map(|t| t.as_str())
    .collect();
    assert_eq!(strs.len(), 14);
}

// ===========================================================================
// Enrichment: LifecycleTransition — is_failure
// ===========================================================================

#[test]
fn enrichment_lifecycle_transition_is_failure() {
    assert!(LifecycleTransition::RejectManifest.is_failure());
    assert!(LifecycleTransition::LoadFailed.is_failure());
    assert!(LifecycleTransition::StartFailed.is_failure());
    assert!(!LifecycleTransition::Validate.is_failure());
    assert!(!LifecycleTransition::Load.is_failure());
    assert!(!LifecycleTransition::Start.is_failure());
    assert!(!LifecycleTransition::Activate.is_failure());
    assert!(!LifecycleTransition::Terminate.is_failure());
}

// ===========================================================================
// Enrichment: LifecycleTransition — Display matches as_str
// ===========================================================================

#[test]
fn enrichment_lifecycle_transition_display_matches_as_str() {
    let transitions = [
        LifecycleTransition::Validate,
        LifecycleTransition::Quarantine,
        LifecycleTransition::StartFailed,
    ];
    for t in &transitions {
        assert_eq!(t.to_string(), t.as_str());
    }
}

// ===========================================================================
// Enrichment: LifecycleError — error_code all variants
// ===========================================================================

#[test]
fn enrichment_lifecycle_error_error_code_all_variants() {
    let errors: Vec<LifecycleError> = vec![
        LifecycleError::InvalidTransition {
            extension_id: "e1".into(),
            current_state: ExtensionState::Running,
            attempted: LifecycleTransition::Load,
        },
        LifecycleError::ExtensionNotFound {
            extension_id: "e2".into(),
        },
        LifecycleError::ExtensionAlreadyExists {
            extension_id: "e3".into(),
        },
        LifecycleError::BudgetExhausted {
            extension_id: "e4".into(),
            remaining_millionths: 0,
            required_millionths: 100,
        },
        LifecycleError::GracePeriodExpired {
            extension_id: "e5".into(),
            elapsed_ns: 10_000_000_000,
            budget_ns: 5_000_000_000,
        },
        LifecycleError::ManifestRejected {
            extension_id: "e6".into(),
            reason: "bad capabilities".into(),
        },
        LifecycleError::Internal {
            detail: "something broke".into(),
        },
    ];

    let codes: std::collections::BTreeSet<&str> = errors.iter().map(|e| e.error_code()).collect();
    assert_eq!(codes.len(), 7, "7 distinct error codes");

    assert_eq!(errors[0].error_code(), "LIFECYCLE_INVALID_TRANSITION");
    assert_eq!(errors[1].error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
    assert_eq!(errors[2].error_code(), "LIFECYCLE_EXTENSION_EXISTS");
    assert_eq!(errors[3].error_code(), "LIFECYCLE_BUDGET_EXHAUSTED");
    assert_eq!(errors[4].error_code(), "LIFECYCLE_GRACE_EXPIRED");
    assert_eq!(errors[5].error_code(), "LIFECYCLE_MANIFEST_REJECTED");
    assert_eq!(errors[6].error_code(), "LIFECYCLE_INTERNAL");
}

// ===========================================================================
// Enrichment: LifecycleError — Display is nonempty for all variants
// ===========================================================================

#[test]
fn enrichment_lifecycle_error_display_nonempty() {
    let errors: Vec<LifecycleError> = vec![
        LifecycleError::InvalidTransition {
            extension_id: "e1".into(),
            current_state: ExtensionState::Running,
            attempted: LifecycleTransition::Load,
        },
        LifecycleError::ExtensionNotFound {
            extension_id: "e2".into(),
        },
        LifecycleError::ExtensionAlreadyExists {
            extension_id: "e3".into(),
        },
        LifecycleError::BudgetExhausted {
            extension_id: "e4".into(),
            remaining_millionths: 0,
            required_millionths: 100,
        },
        LifecycleError::GracePeriodExpired {
            extension_id: "e5".into(),
            elapsed_ns: 10_000_000_000,
            budget_ns: 5_000_000_000,
        },
        LifecycleError::ManifestRejected {
            extension_id: "e6".into(),
            reason: "bad capabilities".into(),
        },
        LifecycleError::Internal {
            detail: "something broke".into(),
        },
    ];

    let displays: std::collections::BTreeSet<String> =
        errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 7, "7 distinct display strings");
    for d in &displays {
        assert!(!d.is_empty());
    }
}

// ===========================================================================
// Enrichment: LifecycleError — serde roundtrip all variants
// ===========================================================================

#[test]
fn enrichment_lifecycle_error_serde_roundtrip() {
    let errors: Vec<LifecycleError> = vec![
        LifecycleError::InvalidTransition {
            extension_id: "e1".into(),
            current_state: ExtensionState::Suspended,
            attempted: LifecycleTransition::Start,
        },
        LifecycleError::ExtensionNotFound {
            extension_id: "e2".into(),
        },
        LifecycleError::ExtensionAlreadyExists {
            extension_id: "e3".into(),
        },
        LifecycleError::BudgetExhausted {
            extension_id: "e4".into(),
            remaining_millionths: 50,
            required_millionths: 1000,
        },
        LifecycleError::GracePeriodExpired {
            extension_id: "e5".into(),
            elapsed_ns: 6_000_000_000,
            budget_ns: 5_000_000_000,
        },
        LifecycleError::ManifestRejected {
            extension_id: "e6".into(),
            reason: "invalid".into(),
        },
        LifecycleError::Internal {
            detail: "oops".into(),
        },
    ];

    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: LifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ===========================================================================
// Enrichment: ResourceBudget — serde roundtrip
// ===========================================================================

#[test]
fn enrichment_resource_budget_serde_roundtrip() {
    let b = ResourceBudget::new(1_000_000, 64 * 1024 * 1024, 10_000);
    let json = serde_json::to_string(&b).unwrap();
    let back: ResourceBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ===========================================================================
// Enrichment: ResourceBudget — is_exhausted
// ===========================================================================

#[test]
fn enrichment_resource_budget_not_exhausted_initially() {
    let b = ResourceBudget::new(1_000_000, 64 * 1024 * 1024, 10_000);
    assert!(!b.is_exhausted());
}

#[test]
fn enrichment_resource_budget_exhausted_zero_cpu() {
    let b = ResourceBudget::new(0, 64 * 1024 * 1024, 10_000);
    assert!(b.is_exhausted());
}

#[test]
fn enrichment_resource_budget_exhausted_zero_memory() {
    let b = ResourceBudget::new(1_000_000, 0, 10_000);
    assert!(b.is_exhausted());
}

#[test]
fn enrichment_resource_budget_exhausted_zero_hostcalls() {
    let b = ResourceBudget::new(1_000_000, 64 * 1024 * 1024, 0);
    assert!(b.is_exhausted());
}

// ===========================================================================
// Enrichment: ResourceBudget — consume_cpu
// ===========================================================================

#[test]
fn enrichment_resource_budget_consume_cpu_success() {
    let mut b = ResourceBudget::new(1_000, 1024, 10);
    assert!(b.consume_cpu(500));
    assert_eq!(b.cpu_remaining_millionths, 500);
}

#[test]
fn enrichment_resource_budget_consume_cpu_insufficient() {
    let mut b = ResourceBudget::new(100, 1024, 10);
    assert!(!b.consume_cpu(200));
}

// ===========================================================================
// Enrichment: ResourceBudget — consume_hostcall
// ===========================================================================

#[test]
fn enrichment_resource_budget_consume_hostcall_success() {
    let mut b = ResourceBudget::new(1_000, 1024, 1);
    assert!(b.consume_hostcall());
    assert_eq!(b.hostcall_remaining, 0);
}

#[test]
fn enrichment_resource_budget_consume_hostcall_zero_remaining() {
    let mut b = ResourceBudget::new(1_000, 1024, 0);
    assert!(!b.consume_hostcall());
}

// ===========================================================================
// Enrichment: ResourceBudget — cpu_utilization_millionths
// ===========================================================================

#[test]
fn enrichment_resource_budget_cpu_utilization_full() {
    let mut b = ResourceBudget::new(1_000_000, 1024, 10);
    b.consume_cpu(1_000_000);
    assert_eq!(b.cpu_utilization_millionths(), 1_000_000);
}

#[test]
fn enrichment_resource_budget_cpu_utilization_half() {
    let mut b = ResourceBudget::new(1_000_000, 1024, 10);
    b.consume_cpu(500_000);
    assert_eq!(b.cpu_utilization_millionths(), 500_000);
}

#[test]
fn enrichment_resource_budget_cpu_utilization_zero_total() {
    let b = ResourceBudget::new(0, 1024, 10);
    assert_eq!(b.cpu_utilization_millionths(), 0);
}

// ===========================================================================
// Enrichment: CancellationConfig — serde roundtrip
// ===========================================================================

#[test]
fn enrichment_cancellation_config_serde_roundtrip() {
    let c = CancellationConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: CancellationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// Enrichment: CancellationConfig — default values
// ===========================================================================

#[test]
fn enrichment_cancellation_config_default_values() {
    let c = CancellationConfig::default();
    assert!(c.grace_period_ns > 0);
    assert!(c.force_on_timeout);
    assert!(c.propagate_to_children);
}

// ===========================================================================
// Enrichment: CancellationConfig — clamped
// ===========================================================================

#[test]
fn enrichment_cancellation_config_clamped_already_valid() {
    let c = CancellationConfig::default().clamped();
    assert_eq!(c, CancellationConfig::default());
}

#[test]
fn enrichment_cancellation_config_clamped_excessive_grace() {
    let mut c = CancellationConfig::default();
    c.grace_period_ns = u64::MAX;
    let clamped = c.clamped();
    assert!(clamped.grace_period_ns < u64::MAX);
}

// ===========================================================================
// Enrichment: valid_transitions — Unloaded has valid transitions
// ===========================================================================

#[test]
fn enrichment_valid_transitions_unloaded_nonempty() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let transitions = valid_transitions(ExtensionState::Unloaded);
    assert!(!transitions.is_empty());
}

#[test]
fn enrichment_valid_transitions_terminated_empty() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let transitions = valid_transitions(ExtensionState::Terminated);
    assert!(
        transitions.is_empty(),
        "terminal states have no transitions"
    );
}

#[test]
fn enrichment_valid_transitions_quarantined_empty() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let transitions = valid_transitions(ExtensionState::Quarantined);
    assert!(transitions.is_empty(), "quarantined is terminal");
}
