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

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TailMemoryBudgets {
    max_p95_ns: u64,
    max_p99_ns: u64,
    max_p999_ns: u64,
    max_cvar_ns: u64,
    max_peak_heap_bytes: u64,
    max_live_allocations_tail: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DecompositionLedgerNs {
    queueing: u64,
    service: u64,
    synchronization: u64,
    retries: u64,
    gc_allocator: u64,
    abi_boundary: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MetricVector {
    mean_latency_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    p999_ns: u64,
    cvar_ns: u64,
    peak_heap_bytes: u64,
    live_allocations_tail: u64,
    throughput_ops_per_sec_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EvInputs {
    impact: u64,
    confidence: u64,
    reuse: u64,
    effort: u64,
    friction: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CampaignRun {
    campaign_id: String,
    lever_id: String,
    lever_category: String,
    commit: String,
    run_id: String,
    generated_at_utc: String,
    changed_paths: Vec<String>,
    decomposition_ledger_ns: DecompositionLedgerNs,
    baseline_metrics: MetricVector,
    candidate_metrics: MetricVector,
    compatibility_invariant_ok: bool,
    ev_inputs: EvInputs,
    expected_ev_score_millionths: u64,
    expected_outcome: String,
    replay_command: String,
    artifact_manifest: String,
    artifact_report: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReplayScenario {
    scenario_id: String,
    scenario_kind: String,
    replay_command: String,
    expected_pass: bool,
    expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Fixture {
    schema_version: String,
    campaign_version: String,
    metric_schema_version: String,
    tail_memory_budgets: TailMemoryBudgets,
    required_log_keys: Vec<String>,
    campaign_runs: Vec<CampaignRun>,
    expected_selected_campaign: String,
    expected_fail_closed_campaigns: Vec<String>,
    cross_subsystem_replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CampaignDecision {
    campaign_id: String,
    ev_score_millionths: u64,
    outcome: String,
}

fn load_fixture() -> Fixture {
    let path = Path::new("tests/fixtures/tail_latency_memory_hardening_regression_gate_v1.json");
    let bytes = fs::read(path).expect("read tail-memory fixture");
    serde_json::from_slice(&bytes).expect("deserialize tail-memory fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/TAIL_LATENCY_MEMORY_HARDENING_REGRESSION_GATE.md");
    fs::read_to_string(path).expect("read tail-memory doc")
}

fn replay_script_path(command: &str) -> Option<PathBuf> {
    let script = command.split_whitespace().next()?;
    if !script.starts_with("./scripts/e2e/") || !script.ends_with(".sh") {
        return None;
    }
    Some(Path::new("../../").join(script.trim_start_matches("./")))
}

fn ev_score_millionths(inputs: &EvInputs) -> u64 {
    let numerator = inputs
        .impact
        .saturating_mul(inputs.confidence)
        .saturating_mul(inputs.reuse)
        .saturating_mul(1_000_000);
    let denominator = inputs.effort.saturating_mul(inputs.friction).max(1);
    numerator / denominator
}

fn classify_tail_memory_lever(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if lower.contains("queue") {
        return Some("queueing");
    }
    if lower.contains("service") {
        return Some("service");
    }
    if lower.contains("sync") || lower.contains("lock") {
        return Some("synchronization");
    }
    if lower.contains("retry") {
        return Some("retries");
    }
    if lower.contains("gc") || lower.contains("allocator") {
        return Some("gc_allocator");
    }
    if lower.contains("abi") || lower.contains("bridge") {
        return Some("abi_boundary");
    }
    None
}

fn leverage_classification_is_one_family(paths: &[String]) -> bool {
    let families = paths
        .iter()
        .filter_map(|path| classify_tail_memory_lever(path.as_str()))
        .collect::<BTreeSet<_>>();
    families.len() == 1
}

fn breaches_budget(run: &CampaignRun, budgets: &TailMemoryBudgets) -> bool {
    run.candidate_metrics.p95_ns > budgets.max_p95_ns
        || run.candidate_metrics.p99_ns > budgets.max_p99_ns
        || run.candidate_metrics.p999_ns > budgets.max_p999_ns
        || run.candidate_metrics.cvar_ns > budgets.max_cvar_ns
        || run.candidate_metrics.peak_heap_bytes > budgets.max_peak_heap_bytes
        || run.candidate_metrics.live_allocations_tail > budgets.max_live_allocations_tail
}

fn central_metric_improved(run: &CampaignRun) -> bool {
    run.candidate_metrics.mean_latency_ns < run.baseline_metrics.mean_latency_ns
        || run.candidate_metrics.throughput_ops_per_sec_millionths
            > run.baseline_metrics.throughput_ops_per_sec_millionths
}

fn tail_or_memory_regressed(run: &CampaignRun) -> bool {
    run.candidate_metrics.p95_ns > run.baseline_metrics.p95_ns
        || run.candidate_metrics.p99_ns > run.baseline_metrics.p99_ns
        || run.candidate_metrics.p999_ns > run.baseline_metrics.p999_ns
        || run.candidate_metrics.cvar_ns > run.baseline_metrics.cvar_ns
        || run.candidate_metrics.peak_heap_bytes > run.baseline_metrics.peak_heap_bytes
        || run.candidate_metrics.live_allocations_tail > run.baseline_metrics.live_allocations_tail
}

fn evaluate_campaign(run: &CampaignRun, budgets: &TailMemoryBudgets) -> CampaignDecision {
    let ev = ev_score_millionths(&run.ev_inputs);
    let outcome = if breaches_budget(run, budgets)
        || !run.compatibility_invariant_ok
        || (central_metric_improved(run) && tail_or_memory_regressed(run))
    {
        "hold"
    } else {
        "promote"
    };

    CampaignDecision {
        campaign_id: run.campaign_id.clone(),
        ev_score_millionths: ev,
        outcome: outcome.to_string(),
    }
}

fn selected_campaign(decisions: &[CampaignDecision]) -> Option<String> {
    let mut promotable = decisions
        .iter()
        .filter(|decision| decision.outcome == "promote")
        .cloned()
        .collect::<Vec<_>>();
    promotable.sort_by(|left, right| {
        right
            .ev_score_millionths
            .cmp(&left.ev_score_millionths)
            .then_with(|| left.campaign_id.cmp(&right.campaign_id))
    });
    promotable.first().map(|entry| entry.campaign_id.clone())
}

fn emit_structured_events(decisions: &[CampaignDecision]) -> Vec<serde_json::Value> {
    decisions
        .iter()
        .map(|decision| {
            serde_json::json!({
                "schema_version": "franken-engine.tail-latency-memory.log-event.v1",
                "trace_id": "trace-tail-latency-memory-hardening-v1",
                "decision_id": format!("decision-{}", decision.campaign_id),
                "policy_id": "policy-tail-latency-memory-hardening-v1",
                "component": "tail_latency_memory_hardening_regression_gate",
                "event": "campaign_run_scored",
                "outcome": decision.outcome,
                "error_code": serde_json::Value::Null
            })
        })
        .collect()
}

#[test]
fn tail_memory_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Tail-Latency and Memory Hardening Regression Gate (`bd-mjh3.6.4`)",
        "## Tail Decomposition Ledger Contract",
        "## Tail-Risk and Memory Objectives",
        "## Fail-Closed Decision Policy",
        "## One-Lever Attribution Discipline",
        "## Structured Log Contract",
        "./scripts/run_tail_latency_memory_hardening_regression_gate.sh ci",
        "./scripts/e2e/tail_latency_memory_hardening_regression_gate_replay.sh",
        "pause_distribution_report.json",
    ] {
        assert!(doc.contains(section), "missing doc section: {section}");
    }
}

#[test]
fn fixture_is_well_formed_and_contractual() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.tail-latency-memory-hardening-regression-gate.v1"
    );
    assert_eq!(fixture.campaign_version, "1.0.0");
    assert_eq!(
        fixture.metric_schema_version,
        "franken-engine.tail-memory-telemetry.v1"
    );

    let required_keys = fixture
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for key in [
        "schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(required_keys.contains(key), "missing required key `{key}`");
    }

    assert!(!fixture.campaign_runs.is_empty());
    for run in &fixture.campaign_runs {
        assert!(!run.campaign_id.trim().is_empty());
        assert!(!run.lever_id.trim().is_empty());
        assert!(!run.lever_category.trim().is_empty());
        assert!(!run.commit.trim().is_empty());
        assert!(!run.run_id.trim().is_empty());
        assert!(!run.generated_at_utc.trim().is_empty());
        assert!(!run.changed_paths.is_empty());
        assert!(!run.replay_command.trim().is_empty());
        assert!(!run.artifact_manifest.trim().is_empty());
        assert!(!run.artifact_report.trim().is_empty());
        assert!(run.ev_inputs.effort > 0);
        assert!(run.ev_inputs.friction > 0);

        let ledger = &run.decomposition_ledger_ns;
        let terms = [
            ledger.queueing,
            ledger.service,
            ledger.synchronization,
            ledger.retries,
            ledger.gc_allocator,
            ledger.abi_boundary,
        ];
        assert!(terms.iter().all(|term| *term > 0));
        assert!(
            leverage_classification_is_one_family(&run.changed_paths),
            "run must stay one-lever attributable: {}",
            run.campaign_id
        );
    }

    assert!(!fixture.cross_subsystem_replay_scenarios.is_empty());
}

#[test]
fn ev_scoring_and_fail_closed_outcomes_match_fixture() {
    let fixture = load_fixture();
    let decisions = fixture
        .campaign_runs
        .iter()
        .map(|run| evaluate_campaign(run, &fixture.tail_memory_budgets))
        .collect::<Vec<_>>();

    for (run, decision) in fixture.campaign_runs.iter().zip(decisions.iter()) {
        assert_eq!(decision.campaign_id, run.campaign_id);
        assert_eq!(
            decision.ev_score_millionths, run.expected_ev_score_millionths,
            "ev score mismatch for {}",
            run.campaign_id
        );
        assert_eq!(
            decision.outcome, run.expected_outcome,
            "gate outcome mismatch for {}",
            run.campaign_id
        );
    }

    let selected = selected_campaign(&decisions).expect("one campaign should be promotable");
    assert_eq!(selected, fixture.expected_selected_campaign);

    let fail_closed = decisions
        .iter()
        .filter(|decision| decision.outcome == "hold")
        .map(|decision| decision.campaign_id.clone())
        .collect::<BTreeSet<_>>();
    let expected_fail_closed = fixture
        .expected_fail_closed_campaigns
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(fail_closed, expected_fail_closed);
}

#[test]
fn replay_scenarios_reference_existing_wrapper_commands() {
    let fixture = load_fixture();
    for scenario in &fixture.cross_subsystem_replay_scenarios {
        assert!(!scenario.scenario_id.trim().is_empty());
        assert!(!scenario.scenario_kind.trim().is_empty());
        assert!(scenario.expected_pass);
        assert_eq!(scenario.expected_outcome, "pass");
        let script_path = replay_script_path(scenario.replay_command.as_str())
            .expect("replay command must use scripts/e2e wrapper");
        assert!(
            script_path.is_file(),
            "replay wrapper script does not exist: {}",
            script_path.display()
        );
    }
}

#[test]
fn structured_log_events_include_required_keys() {
    let fixture = load_fixture();
    let decisions = fixture
        .campaign_runs
        .iter()
        .map(|run| evaluate_campaign(run, &fixture.tail_memory_budgets))
        .collect::<Vec<_>>();
    let events = emit_structured_events(&decisions);

    assert_eq!(events.len(), fixture.campaign_runs.len());
    for event in events {
        for key in &fixture.required_log_keys {
            assert!(event.get(key).is_some(), "missing required key `{key}`");
        }
        assert!(
            event["schema_version"]
                .as_str()
                .expect("schema version string")
                .starts_with("franken-engine.tail-latency-memory"),
            "schema version prefix mismatch"
        );
    }
}

// ── EV scoring tests ──────────────────────────────────────────────────

#[test]
fn ev_score_zero_impact_yields_zero() {
    let inputs = EvInputs {
        impact: 0,
        confidence: 100,
        reuse: 50,
        effort: 10,
        friction: 5,
    };
    assert_eq!(ev_score_millionths(&inputs), 0);
}

#[test]
fn ev_score_high_effort_reduces_score() {
    let low_effort = EvInputs {
        impact: 100,
        confidence: 80,
        reuse: 50,
        effort: 1,
        friction: 1,
    };
    let high_effort = EvInputs {
        impact: 100,
        confidence: 80,
        reuse: 50,
        effort: 100,
        friction: 1,
    };
    assert!(ev_score_millionths(&low_effort) > ev_score_millionths(&high_effort));
}

#[test]
fn ev_score_high_friction_reduces_score() {
    let low_friction = EvInputs {
        impact: 100,
        confidence: 80,
        reuse: 50,
        effort: 10,
        friction: 1,
    };
    let high_friction = EvInputs {
        impact: 100,
        confidence: 80,
        reuse: 50,
        effort: 10,
        friction: 100,
    };
    assert!(ev_score_millionths(&low_friction) > ev_score_millionths(&high_friction));
}

#[test]
fn ev_score_denominator_clamped_to_at_least_one() {
    let inputs = EvInputs {
        impact: 10,
        confidence: 10,
        reuse: 10,
        effort: 0,
        friction: 0,
    };
    let score = ev_score_millionths(&inputs);
    assert!(
        score > 0,
        "saturating_mul(0,0).max(1) should clamp denominator"
    );
}

// ── Budget breach tests ───────────────────────────────────────────────

#[test]
fn breaches_budget_when_p95_exceeds() {
    let budgets = TailMemoryBudgets {
        max_p95_ns: 1000,
        max_p99_ns: 5000,
        max_p999_ns: 10000,
        max_cvar_ns: 2000,
        max_peak_heap_bytes: 1_000_000,
        max_live_allocations_tail: 500,
    };
    let mut run = make_baseline_run("breach-p95");
    run.candidate_metrics.p95_ns = 1001;
    assert!(breaches_budget(&run, &budgets));
}

#[test]
fn breaches_budget_when_peak_heap_exceeds() {
    let budgets = TailMemoryBudgets {
        max_p95_ns: 10000,
        max_p99_ns: 50000,
        max_p999_ns: 100000,
        max_cvar_ns: 20000,
        max_peak_heap_bytes: 1_000_000,
        max_live_allocations_tail: 500,
    };
    let mut run = make_baseline_run("breach-heap");
    run.candidate_metrics.peak_heap_bytes = 1_000_001;
    assert!(breaches_budget(&run, &budgets));
}

#[test]
fn no_breach_when_all_within_budget() {
    let budgets = TailMemoryBudgets {
        max_p95_ns: 10000,
        max_p99_ns: 50000,
        max_p999_ns: 100000,
        max_cvar_ns: 20000,
        max_peak_heap_bytes: 1_000_000,
        max_live_allocations_tail: 500,
    };
    let run = make_baseline_run("no-breach");
    assert!(!breaches_budget(&run, &budgets));
}

// ── Central metric improvement tests ──────────────────────────────────

#[test]
fn central_metric_improved_when_latency_decreased() {
    let mut run = make_baseline_run("lat-improved");
    run.candidate_metrics.mean_latency_ns = run.baseline_metrics.mean_latency_ns - 100;
    assert!(central_metric_improved(&run));
}

#[test]
fn central_metric_improved_when_throughput_increased() {
    let mut run = make_baseline_run("tput-improved");
    run.candidate_metrics.throughput_ops_per_sec_millionths =
        run.baseline_metrics.throughput_ops_per_sec_millionths + 100;
    assert!(central_metric_improved(&run));
}

#[test]
fn central_metric_not_improved_when_same() {
    let run = make_baseline_run("same-metrics");
    assert!(!central_metric_improved(&run));
}

// ── Tail regression tests ─────────────────────────────────────────────

#[test]
fn tail_or_memory_regressed_when_p99_increases() {
    let mut run = make_baseline_run("p99-regressed");
    run.candidate_metrics.p99_ns = run.baseline_metrics.p99_ns + 1;
    assert!(tail_or_memory_regressed(&run));
}

#[test]
fn tail_not_regressed_when_identical() {
    let run = make_baseline_run("no-regression");
    assert!(!tail_or_memory_regressed(&run));
}

#[test]
fn tail_regressed_when_live_allocations_increase() {
    let mut run = make_baseline_run("alloc-regressed");
    run.candidate_metrics.live_allocations_tail = run.baseline_metrics.live_allocations_tail + 10;
    assert!(tail_or_memory_regressed(&run));
}

// ── Campaign evaluation tests ─────────────────────────────────────────

#[test]
fn evaluate_promotes_when_all_good() {
    let budgets = large_budgets();
    let run = make_baseline_run("all-good");
    let decision = evaluate_campaign(&run, &budgets);
    assert_eq!(decision.outcome, "promote");
    assert_eq!(decision.campaign_id, "all-good");
}

#[test]
fn evaluate_holds_when_budget_breached() {
    let mut budgets = large_budgets();
    budgets.max_p95_ns = 1;
    let run = make_baseline_run("budget-breach");
    let decision = evaluate_campaign(&run, &budgets);
    assert_eq!(decision.outcome, "hold");
}

#[test]
fn evaluate_holds_when_compatibility_invariant_broken() {
    let budgets = large_budgets();
    let mut run = make_baseline_run("compat-broken");
    run.compatibility_invariant_ok = false;
    let decision = evaluate_campaign(&run, &budgets);
    assert_eq!(decision.outcome, "hold");
}

#[test]
fn evaluate_holds_when_central_improved_but_tail_regressed() {
    let budgets = large_budgets();
    let mut run = make_baseline_run("improved-but-regressed");
    run.candidate_metrics.mean_latency_ns = run.baseline_metrics.mean_latency_ns - 100;
    run.candidate_metrics.p99_ns = run.baseline_metrics.p99_ns + 500;
    let decision = evaluate_campaign(&run, &budgets);
    assert_eq!(decision.outcome, "hold");
}

// ── Selection tests ───────────────────────────────────────────────────

#[test]
fn selected_campaign_picks_highest_ev_promotable() {
    let decisions = vec![
        CampaignDecision {
            campaign_id: "low-ev".to_string(),
            ev_score_millionths: 100,
            outcome: "promote".to_string(),
        },
        CampaignDecision {
            campaign_id: "high-ev".to_string(),
            ev_score_millionths: 1000,
            outcome: "promote".to_string(),
        },
        CampaignDecision {
            campaign_id: "held".to_string(),
            ev_score_millionths: 5000,
            outcome: "hold".to_string(),
        },
    ];
    assert_eq!(selected_campaign(&decisions), Some("high-ev".to_string()));
}

#[test]
fn selected_campaign_returns_none_when_all_held() {
    let decisions = vec![
        CampaignDecision {
            campaign_id: "held-1".to_string(),
            ev_score_millionths: 1000,
            outcome: "hold".to_string(),
        },
        CampaignDecision {
            campaign_id: "held-2".to_string(),
            ev_score_millionths: 500,
            outcome: "hold".to_string(),
        },
    ];
    assert_eq!(selected_campaign(&decisions), None);
}

#[test]
fn selected_campaign_breaks_ev_tie_by_campaign_id() {
    let decisions = vec![
        CampaignDecision {
            campaign_id: "beta".to_string(),
            ev_score_millionths: 500,
            outcome: "promote".to_string(),
        },
        CampaignDecision {
            campaign_id: "alpha".to_string(),
            ev_score_millionths: 500,
            outcome: "promote".to_string(),
        },
    ];
    assert_eq!(selected_campaign(&decisions), Some("alpha".to_string()));
}

#[test]
fn selected_campaign_empty_decisions_returns_none() {
    assert_eq!(selected_campaign(&[]), None);
}

// ── Leverage classification tests ─────────────────────────────────────

#[test]
fn classify_queue_path() {
    assert_eq!(
        classify_tail_memory_lever("src/request_queue.rs"),
        Some("queueing")
    );
}

#[test]
fn classify_gc_allocator_path() {
    assert_eq!(
        classify_tail_memory_lever("src/gc_allocator_pool.rs"),
        Some("gc_allocator")
    );
}

#[test]
fn classify_sync_lock_path() {
    assert_eq!(
        classify_tail_memory_lever("src/sync_barrier.rs"),
        Some("synchronization")
    );
}

#[test]
fn classify_abi_path() {
    assert_eq!(
        classify_tail_memory_lever("src/abi_bridge.rs"),
        Some("abi_boundary")
    );
}

#[test]
fn classify_retry_path() {
    assert_eq!(
        classify_tail_memory_lever("src/retry_policy.rs"),
        Some("retries")
    );
}

#[test]
fn classify_unrelated_path_returns_none() {
    assert_eq!(classify_tail_memory_lever("src/main.rs"), None);
}

#[test]
fn leverage_one_family_true_for_same_category() {
    let paths = vec![
        "src/gc_pool.rs".to_string(),
        "src/allocator_slab.rs".to_string(),
    ];
    assert!(leverage_classification_is_one_family(&paths));
}

#[test]
fn leverage_one_family_false_for_mixed_categories() {
    let paths = vec![
        "src/gc_pool.rs".to_string(),
        "src/retry_handler.rs".to_string(),
    ];
    assert!(!leverage_classification_is_one_family(&paths));
}

// ── Structured event tests ────────────────────────────────────────────

#[test]
fn emit_structured_events_has_correct_count() {
    let decisions = vec![
        CampaignDecision {
            campaign_id: "c1".to_string(),
            ev_score_millionths: 100,
            outcome: "promote".to_string(),
        },
        CampaignDecision {
            campaign_id: "c2".to_string(),
            ev_score_millionths: 200,
            outcome: "hold".to_string(),
        },
    ];
    let events = emit_structured_events(&decisions);
    assert_eq!(events.len(), 2);
}

#[test]
fn emit_structured_events_decision_id_contains_campaign_id() {
    let decisions = vec![CampaignDecision {
        campaign_id: "my-campaign".to_string(),
        ev_score_millionths: 100,
        outcome: "promote".to_string(),
    }];
    let events = emit_structured_events(&decisions);
    assert_eq!(
        events[0]["decision_id"].as_str(),
        Some("decision-my-campaign")
    );
}

#[test]
fn emit_structured_events_outcome_matches_decision() {
    let decisions = vec![CampaignDecision {
        campaign_id: "hold-campaign".to_string(),
        ev_score_millionths: 100,
        outcome: "hold".to_string(),
    }];
    let events = emit_structured_events(&decisions);
    assert_eq!(events[0]["outcome"].as_str(), Some("hold"));
}

#[test]
fn emit_structured_events_error_code_is_null() {
    let decisions = vec![CampaignDecision {
        campaign_id: "ok".to_string(),
        ev_score_millionths: 100,
        outcome: "promote".to_string(),
    }];
    let events = emit_structured_events(&decisions);
    assert!(events[0]["error_code"].is_null());
}

// ── Test helpers ──────────────────────────────────────────────────────

fn make_baseline_run(campaign_id: &str) -> CampaignRun {
    let metrics = MetricVector {
        mean_latency_ns: 5000,
        p95_ns: 500,
        p99_ns: 2000,
        p999_ns: 5000,
        cvar_ns: 1000,
        peak_heap_bytes: 100_000,
        live_allocations_tail: 50,
        throughput_ops_per_sec_millionths: 1_000_000,
    };
    CampaignRun {
        campaign_id: campaign_id.to_string(),
        lever_id: "lever-001".to_string(),
        lever_category: "gc_allocator".to_string(),
        commit: "abc123".to_string(),
        run_id: "run-001".to_string(),
        generated_at_utc: "2026-03-01T00:00:00Z".to_string(),
        changed_paths: vec!["src/gc_allocator_pool.rs".to_string()],
        decomposition_ledger_ns: DecompositionLedgerNs {
            queueing: 100,
            service: 200,
            synchronization: 50,
            retries: 10,
            gc_allocator: 300,
            abi_boundary: 40,
        },
        baseline_metrics: metrics.clone(),
        candidate_metrics: metrics,
        compatibility_invariant_ok: true,
        ev_inputs: EvInputs {
            impact: 50,
            confidence: 80,
            reuse: 40,
            effort: 10,
            friction: 5,
        },
        expected_ev_score_millionths: 0,
        expected_outcome: "promote".to_string(),
        replay_command:
            "./scripts/e2e/tail_latency_memory_hardening_regression_gate_replay.sh check"
                .to_string(),
        artifact_manifest: "artifacts/manifest.json".to_string(),
        artifact_report: "artifacts/report.json".to_string(),
    }
}

fn large_budgets() -> TailMemoryBudgets {
    TailMemoryBudgets {
        max_p95_ns: 1_000_000,
        max_p99_ns: 5_000_000,
        max_p999_ns: 10_000_000,
        max_cvar_ns: 2_000_000,
        max_peak_heap_bytes: 100_000_000,
        max_live_allocations_tail: 50_000,
    }
}
