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

use frankenengine_engine::flamegraph_pipeline::{
    FLAMEGRAPH_SCHEMA_VERSION, FLAMEGRAPH_STORAGE_INTEGRATION_POINT, FlamegraphArtifact,
    FlamegraphKind, FlamegraphPipelineRequest, FlamegraphQuery, query_flamegraph_artifacts,
    run_flamegraph_pipeline, validate_flamegraph_artifact,
};
use frankenengine_engine::storage_adapter::{
    EventContext, InMemoryStorageAdapter, StorageAdapter, StoreKind, StoreQuery,
};

fn candidate_cpu_folded() -> String {
    [
        "runtime;dispatch;policy_eval 36",
        "runtime;dispatch;hostcall 22",
        "runtime;scheduler;poll 12",
    ]
    .join("\n")
}

fn candidate_alloc_folded() -> String {
    [
        "runtime;alloc;vec_grow 20",
        "runtime;alloc;string_clone 18",
        "runtime;alloc;hashmap_resize 8",
    ]
    .join("\n")
}

fn baseline_cpu_folded() -> String {
    [
        "runtime;dispatch;policy_eval 10",
        "runtime;dispatch;hostcall 30",
        "runtime;scheduler;poll 12",
    ]
    .join("\n")
}

fn baseline_alloc_folded() -> String {
    [
        "runtime;alloc;vec_grow 8",
        "runtime;alloc;string_clone 18",
        "runtime;alloc;hashmap_resize 14",
    ]
    .join("\n")
}

fn request_with_diff() -> FlamegraphPipelineRequest {
    FlamegraphPipelineRequest {
        trace_id: "trace-flamegraph-pipeline".to_string(),
        decision_id: "decision-flamegraph-pipeline".to_string(),
        policy_id: "policy-flamegraph-pipeline-v1".to_string(),
        benchmark_run_id: "bench-run-0001".to_string(),
        optimization_decision_id: "opt-dec-001".to_string(),
        workload_id: "mixed-cpu-io-agent-mesh/L".to_string(),
        benchmark_profile: "L".to_string(),
        config_fingerprint: "cfg-fp-9c91f3ad".to_string(),
        git_commit: "deadbeefcafefeed".to_string(),
        generated_at_utc: "2026-02-22T06:00:00Z".to_string(),
        cpu_folded_stacks: candidate_cpu_folded(),
        allocation_folded_stacks: candidate_alloc_folded(),
        baseline_benchmark_run_id: Some("bench-run-0000".to_string()),
        baseline_cpu_folded_stacks: Some(baseline_cpu_folded()),
        baseline_allocation_folded_stacks: Some(baseline_alloc_folded()),
    }
}

#[test]
fn integration_run_generates_and_stores_cpu_alloc_and_diff_flamegraphs() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(decision.is_success());
    assert_eq!(decision.artifacts.len(), 4);
    assert_eq!(decision.store_keys.len(), 4);

    for artifact in &decision.artifacts {
        validate_flamegraph_artifact(artifact).expect("artifact should be valid");
        assert!(
            artifact.folded_stacks_text.contains(' '),
            "folded-stack payload should contain stack/count rows"
        );
        assert!(artifact.svg.starts_with("<svg"));
        assert!(
            artifact.svg.ends_with("</svg>"),
            "svg must have a closing tag"
        );
    }

    assert!(
        decision.events.iter().any(|event| {
            event.event == "pipeline_completed"
                && event.outcome == "pass"
                && event.error_code.is_none()
        }),
        "pipeline completion event should be present"
    );
    assert_eq!(
        decision
            .events
            .iter()
            .filter(|event| event.event == "flamegraph_stored")
            .count(),
        4
    );
}

#[test]
fn diff_flamegraph_highlights_expected_regression_and_improvement() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let cpu_diff = decision
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == FlamegraphKind::DiffCpu)
        .expect("cpu diff artifact should exist");

    let hotspot_regression = cpu_diff
        .diff_entries
        .iter()
        .find(|entry| entry.stack == "runtime;dispatch;policy_eval")
        .expect("expected regression stack");
    assert_eq!(hotspot_regression.baseline_samples, 10);
    assert_eq!(hotspot_regression.candidate_samples, 36);
    assert_eq!(hotspot_regression.delta_samples, 26);

    let hotspot_improvement = cpu_diff
        .diff_entries
        .iter()
        .find(|entry| entry.stack == "runtime;dispatch;hostcall")
        .expect("expected improvement stack");
    assert_eq!(hotspot_improvement.baseline_samples, 30);
    assert_eq!(hotspot_improvement.candidate_samples, 22);
    assert_eq!(hotspot_improvement.delta_samples, -8);
}

#[test]
fn metadata_is_complete_and_queryable_from_benchmark_ledger_store() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let cpu_artifacts = query_flamegraph_artifacts(
        &mut adapter,
        &FlamegraphQuery {
            benchmark_run_id: Some("bench-run-0001".to_string()),
            workload_id: Some("mixed-cpu-io-agent-mesh/L".to_string()),
            git_commit: Some("deadbeefcafefeed".to_string()),
            kind: Some(FlamegraphKind::Cpu),
            decision_id: Some("decision-flamegraph-pipeline".to_string()),
            trace_id: Some("trace-flamegraph-pipeline".to_string()),
            limit: Some(10),
        },
        "trace-query",
        "decision-query",
        "policy-query",
    )
    .expect("query should succeed");

    assert_eq!(cpu_artifacts.len(), 1);
    let artifact = &cpu_artifacts[0];
    assert_eq!(artifact.kind, FlamegraphKind::Cpu);
    assert_eq!(artifact.metadata.benchmark_run_id, "bench-run-0001");
    assert_eq!(artifact.metadata.workload_id, "mixed-cpu-io-agent-mesh/L");
    assert_eq!(artifact.metadata.git_commit, "deadbeefcafefeed");
    assert_eq!(
        artifact.storage_integration_point,
        "frankensqlite::benchmark::ledger"
    );
}

#[test]
fn invalid_folded_stack_returns_typed_error_and_no_partial_artifacts() {
    let mut request = request_with_diff();
    request.cpu_folded_stacks = "runtime;dispatch;policy_eval".to_string();
    request.baseline_cpu_folded_stacks = None;
    request.baseline_allocation_folded_stacks = None;
    request.baseline_benchmark_run_id = None;

    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(!decision.is_success());
    assert_eq!(decision.error_code.as_deref(), Some("FE-FLAME-1003"));
    assert!(!decision.rollback_required);
    assert!(
        decision.events.iter().any(|event| {
            event.event == "pipeline_completed"
                && event.outcome == "fail"
                && event.error_code.as_deref() == Some("FE-FLAME-1003")
        }),
        "failure completion event must include typed error code"
    );

    let stored = query_flamegraph_artifacts(
        &mut adapter,
        &FlamegraphQuery::default(),
        "trace-query-empty",
        "decision-query-empty",
        "policy-query-empty",
    )
    .expect("empty query should succeed");
    assert!(stored.is_empty(), "no artifacts should have been stored");
}

#[test]
fn storage_failure_sets_rollback_required_and_keeps_store_empty() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(!decision.is_success());
    assert_eq!(decision.error_code.as_deref(), Some("FE-FLAME-1007"));
    assert!(
        decision.rollback_required,
        "storage failures should trigger rollback-required semantics"
    );

    let context = EventContext::new(
        "trace-store-check",
        "decision-store-check",
        "policy-store-check",
    )
    .expect("context");
    let rows = adapter
        .query(StoreKind::BenchmarkLedger, &StoreQuery::default(), &context)
        .expect("query should succeed");
    assert!(
        rows.is_empty(),
        "put_batch failure must not leave partial benchmark ledger writes"
    );
}

#[test]
fn artifact_ids_are_deterministic_for_identical_inputs() {
    let request = request_with_diff();

    let mut adapter_a = InMemoryStorageAdapter::new();
    let mut adapter_b = InMemoryStorageAdapter::new();
    let decision_a = run_flamegraph_pipeline(&mut adapter_a, &request);
    let decision_b = run_flamegraph_pipeline(&mut adapter_b, &request);

    assert!(decision_a.is_success());
    assert!(decision_b.is_success());

    let mut ids_a: Vec<String> = decision_a
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect();
    let mut ids_b: Vec<String> = decision_b
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect();
    ids_a.sort();
    ids_b.sort();
    assert_eq!(ids_a, ids_b);
}

// ---------- no-baseline mode ----------

fn request_no_baseline() -> FlamegraphPipelineRequest {
    FlamegraphPipelineRequest {
        trace_id: "trace-no-baseline".to_string(),
        decision_id: "decision-no-baseline".to_string(),
        policy_id: "policy-no-baseline".to_string(),
        benchmark_run_id: "bench-run-nb-001".to_string(),
        optimization_decision_id: "opt-dec-nb-001".to_string(),
        workload_id: "simple-workload/S".to_string(),
        benchmark_profile: "S".to_string(),
        config_fingerprint: "cfg-fp-no-baseline".to_string(),
        git_commit: "aabbccdd11223344".to_string(),
        generated_at_utc: "2026-03-01T12:00:00Z".to_string(),
        cpu_folded_stacks: candidate_cpu_folded(),
        allocation_folded_stacks: candidate_alloc_folded(),
        baseline_benchmark_run_id: None,
        baseline_cpu_folded_stacks: None,
        baseline_allocation_folded_stacks: None,
    }
}

#[test]
fn no_baseline_produces_two_artifacts_cpu_and_allocation() {
    let request = request_no_baseline();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(decision.is_success());
    assert_eq!(decision.artifacts.len(), 2);
    assert_eq!(decision.store_keys.len(), 2);

    let kinds: BTreeSet<FlamegraphKind> = decision.artifacts.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&FlamegraphKind::Cpu));
    assert!(kinds.contains(&FlamegraphKind::Allocation));
    assert!(!kinds.contains(&FlamegraphKind::DiffCpu));
    assert!(!kinds.contains(&FlamegraphKind::DiffAllocation));
}

#[test]
fn no_baseline_artifacts_have_no_diff_entries() {
    let request = request_no_baseline();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(decision.is_success());
    for artifact in &decision.artifacts {
        assert!(
            artifact.diff_entries.is_empty(),
            "non-diff artifact should have no diff entries"
        );
        assert!(
            artifact.diff_from_artifact_id.is_none(),
            "non-diff artifact should have no diff reference"
        );
    }
}

// ---------- FlamegraphKind ----------

#[test]
fn flamegraph_kind_as_str_round_trips() {
    for (kind, expected) in [
        (FlamegraphKind::Cpu, "cpu"),
        (FlamegraphKind::Allocation, "allocation"),
        (FlamegraphKind::DiffCpu, "diff_cpu"),
        (FlamegraphKind::DiffAllocation, "diff_allocation"),
    ] {
        assert_eq!(kind.as_str(), expected);
    }
}

#[test]
fn flamegraph_kind_display_matches_as_str() {
    for kind in [
        FlamegraphKind::Cpu,
        FlamegraphKind::Allocation,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::DiffAllocation,
    ] {
        assert_eq!(format!("{kind}"), kind.as_str());
    }
}

#[test]
fn flamegraph_kind_ordering_is_stable() {
    let mut kinds = vec![
        FlamegraphKind::DiffAllocation,
        FlamegraphKind::Cpu,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::Allocation,
    ];
    kinds.sort();
    assert_eq!(
        kinds,
        vec![
            FlamegraphKind::Cpu,
            FlamegraphKind::Allocation,
            FlamegraphKind::DiffCpu,
            FlamegraphKind::DiffAllocation,
        ]
    );
}

#[test]
fn flamegraph_kind_serde_roundtrip() {
    for kind in [
        FlamegraphKind::Cpu,
        FlamegraphKind::Allocation,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::DiffAllocation,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize kind");
        let recovered: FlamegraphKind = serde_json::from_str(&json).expect("deserialize kind");
        assert_eq!(recovered, kind);
    }
}

// ---------- artifact schema / metadata ----------

#[test]
fn all_artifacts_have_correct_schema_version_and_storage_point() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    for artifact in &decision.artifacts {
        assert_eq!(artifact.schema_version, FLAMEGRAPH_SCHEMA_VERSION);
        assert_eq!(
            artifact.storage_integration_point,
            FLAMEGRAPH_STORAGE_INTEGRATION_POINT
        );
    }
}

#[test]
fn all_artifacts_have_evidence_link_fields() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    for artifact in &decision.artifacts {
        assert_eq!(artifact.evidence_link.trace_id, "trace-flamegraph-pipeline");
        assert_eq!(
            artifact.evidence_link.decision_id,
            "decision-flamegraph-pipeline"
        );
        assert_eq!(
            artifact.evidence_link.policy_id,
            "policy-flamegraph-pipeline-v1"
        );
        assert_eq!(artifact.evidence_link.benchmark_run_id, "bench-run-0001");
        assert_eq!(
            artifact.evidence_link.optimization_decision_id,
            "opt-dec-001"
        );
        assert!(!artifact.evidence_link.evidence_node_id.is_empty());
    }
}

#[test]
fn artifact_metadata_carries_request_fields() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    for artifact in &decision.artifacts {
        assert_eq!(artifact.metadata.benchmark_run_id, "bench-run-0001");
        assert_eq!(artifact.metadata.workload_id, "mixed-cpu-io-agent-mesh/L");
        assert_eq!(artifact.metadata.benchmark_profile, "L");
        assert_eq!(artifact.metadata.config_fingerprint, "cfg-fp-9c91f3ad");
        assert_eq!(artifact.metadata.git_commit, "deadbeefcafefeed");
        assert_eq!(artifact.metadata.generated_at_utc, "2026-02-22T06:00:00Z");
    }
}

#[test]
fn diff_artifacts_have_baseline_run_id_in_metadata() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    for artifact in &decision.artifacts {
        match artifact.kind {
            FlamegraphKind::DiffCpu | FlamegraphKind::DiffAllocation => {
                assert_eq!(
                    artifact.metadata.baseline_benchmark_run_id.as_deref(),
                    Some("bench-run-0000"),
                    "diff artifact must carry baseline run id"
                );
                assert!(artifact.diff_from_artifact_id.is_some());
            }
            _ => {
                // Non-diff artifacts may still carry baseline run id from the request
                assert!(artifact.diff_entries.is_empty());
            }
        }
    }
}

// ---------- total_samples ----------

#[test]
fn total_samples_equals_sum_of_folded_stack_counts() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    for artifact in &decision.artifacts {
        let sum: u64 = artifact.folded_stacks.iter().map(|s| s.sample_count).sum();
        assert_eq!(
            artifact.total_samples, sum,
            "total_samples mismatch for {:?}",
            artifact.kind
        );
    }
}

#[test]
fn cpu_artifact_total_samples_matches_input() {
    let request = request_no_baseline();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let cpu = decision
        .artifacts
        .iter()
        .find(|a| a.kind == FlamegraphKind::Cpu)
        .expect("cpu artifact");
    assert_eq!(cpu.total_samples, 36 + 22 + 12);

    let alloc = decision
        .artifacts
        .iter()
        .find(|a| a.kind == FlamegraphKind::Allocation)
        .expect("allocation artifact");
    assert_eq!(alloc.total_samples, 20 + 18 + 8);
}

// ---------- SVG structure ----------

#[test]
fn svg_contains_rect_and_text_elements() {
    let request = request_no_baseline();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    for artifact in &decision.artifacts {
        assert!(
            artifact.svg.contains("<rect"),
            "SVG must contain <rect elements"
        );
        assert!(
            artifact.svg.contains("<text"),
            "SVG must contain <text elements"
        );
    }
}

// ---------- diff allocation ----------

#[test]
fn diff_allocation_contains_expected_entries() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let alloc_diff = decision
        .artifacts
        .iter()
        .find(|a| a.kind == FlamegraphKind::DiffAllocation)
        .expect("allocation diff artifact");

    let vec_grow = alloc_diff
        .diff_entries
        .iter()
        .find(|e| e.stack == "runtime;alloc;vec_grow")
        .expect("vec_grow diff entry");
    assert_eq!(vec_grow.baseline_samples, 8);
    assert_eq!(vec_grow.candidate_samples, 20);
    assert_eq!(vec_grow.delta_samples, 12);

    let hashmap_resize = alloc_diff
        .diff_entries
        .iter()
        .find(|e| e.stack == "runtime;alloc;hashmap_resize")
        .expect("hashmap_resize diff entry");
    assert_eq!(hashmap_resize.baseline_samples, 14);
    assert_eq!(hashmap_resize.candidate_samples, 8);
    assert_eq!(hashmap_resize.delta_samples, -6);

    // string_clone has identical samples in baseline and candidate (18 each),
    // so it should appear with delta=0 if present in the diff
    if let Some(string_clone) = alloc_diff
        .diff_entries
        .iter()
        .find(|e| e.stack == "runtime;alloc;string_clone")
    {
        assert_eq!(string_clone.delta_samples, 0);
    }
}

// ---------- query filtering ----------

#[test]
fn query_by_kind_returns_only_matching_artifacts() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    for kind in [
        FlamegraphKind::Cpu,
        FlamegraphKind::Allocation,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::DiffAllocation,
    ] {
        let results = query_flamegraph_artifacts(
            &mut adapter,
            &FlamegraphQuery {
                kind: Some(kind),
                ..Default::default()
            },
            "trace-q",
            "decision-q",
            "policy-q",
        )
        .expect("query should succeed");
        assert_eq!(results.len(), 1, "expected exactly one {kind:?} artifact");
        assert_eq!(results[0].kind, kind);
    }
}

#[test]
fn query_with_default_returns_all_stored_artifacts() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let all = query_flamegraph_artifacts(
        &mut adapter,
        &FlamegraphQuery::default(),
        "trace-all",
        "decision-all",
        "policy-all",
    )
    .expect("query should succeed");
    assert_eq!(all.len(), 4);
}

#[test]
fn query_with_limit_caps_results() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let limited = query_flamegraph_artifacts(
        &mut adapter,
        &FlamegraphQuery {
            limit: Some(2),
            ..Default::default()
        },
        "trace-lim",
        "decision-lim",
        "policy-lim",
    )
    .expect("query should succeed");
    assert_eq!(limited.len(), 2);
}

#[test]
fn query_with_nonexistent_run_id_returns_empty() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let _decision = run_flamegraph_pipeline(&mut adapter, &request);

    let empty = query_flamegraph_artifacts(
        &mut adapter,
        &FlamegraphQuery {
            benchmark_run_id: Some("nonexistent-run".to_string()),
            ..Default::default()
        },
        "trace-e",
        "decision-e",
        "policy-e",
    )
    .expect("query should succeed");
    assert!(empty.is_empty());
}

#[test]
fn query_by_git_commit_filters_correctly() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let _decision = run_flamegraph_pipeline(&mut adapter, &request);

    let results = query_flamegraph_artifacts(
        &mut adapter,
        &FlamegraphQuery {
            git_commit: Some("deadbeefcafefeed".to_string()),
            ..Default::default()
        },
        "trace-gc",
        "decision-gc",
        "policy-gc",
    )
    .expect("query should succeed");
    assert_eq!(results.len(), 4);

    let no_results = query_flamegraph_artifacts(
        &mut adapter,
        &FlamegraphQuery {
            git_commit: Some("0000000000000000".to_string()),
            ..Default::default()
        },
        "trace-gc2",
        "decision-gc2",
        "policy-gc2",
    )
    .expect("query should succeed");
    assert!(no_results.is_empty());
}

// ---------- error paths ----------

#[test]
fn empty_trace_id_returns_invalid_request_error() {
    let mut request = request_no_baseline();
    request.trace_id = String::new();

    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(!decision.is_success());
    assert_eq!(decision.error_code.as_deref(), Some("FE-FLAME-1001"));
    assert!(!decision.rollback_required);
}

#[test]
fn empty_cpu_folded_stacks_returns_error() {
    let mut request = request_no_baseline();
    request.cpu_folded_stacks = String::new();

    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(!decision.is_success());
    assert_eq!(decision.error_code.as_deref(), Some("FE-FLAME-1003"));
}

#[test]
fn mismatched_baseline_only_cpu_returns_error() {
    let mut request = request_no_baseline();
    request.baseline_benchmark_run_id = Some("bench-baseline".to_string());
    request.baseline_cpu_folded_stacks = Some(baseline_cpu_folded());
    // allocation baseline missing -> mismatched

    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(!decision.is_success());
    assert_eq!(decision.error_code.as_deref(), Some("FE-FLAME-1004"));
}

#[test]
fn mismatched_baseline_only_allocation_returns_error() {
    let mut request = request_no_baseline();
    request.baseline_benchmark_run_id = Some("bench-baseline".to_string());
    request.baseline_allocation_folded_stacks = Some(baseline_alloc_folded());
    // cpu baseline missing -> mismatched

    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(!decision.is_success());
    assert_eq!(decision.error_code.as_deref(), Some("FE-FLAME-1004"));
}

#[test]
fn invalid_timestamp_returns_typed_error() {
    let mut request = request_no_baseline();
    request.generated_at_utc = "not-a-timestamp".to_string();

    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(!decision.is_success());
    assert_eq!(decision.error_code.as_deref(), Some("FE-FLAME-1002"));
}

// ---------- event sequence ----------

#[test]
fn event_sequence_contains_started_parsed_generated_stored_completed() {
    let request = request_no_baseline();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let event_types: Vec<&str> = decision.events.iter().map(|e| e.event.as_str()).collect();
    assert!(
        event_types.contains(&"pipeline_started"),
        "events: {event_types:?}"
    );
    assert!(event_types.contains(&"pipeline_completed"));
    assert!(event_types.contains(&"flamegraph_stored"));

    // completed must be last
    assert_eq!(decision.events.last().unwrap().event, "pipeline_completed");
}

#[test]
fn all_events_carry_request_ids() {
    let request = request_no_baseline();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    for event in &decision.events {
        assert_eq!(event.trace_id, "trace-no-baseline");
        assert_eq!(event.decision_id, "decision-no-baseline");
        assert_eq!(event.policy_id, "policy-no-baseline");
        assert_eq!(event.component, "flamegraph_pipeline");
    }
}

#[test]
fn stored_events_count_matches_artifact_count_with_diff() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let stored_count = decision
        .events
        .iter()
        .filter(|e| e.event == "flamegraph_stored")
        .count();
    assert_eq!(stored_count, 4);
}

#[test]
fn stored_events_count_matches_artifact_count_no_diff() {
    let request = request_no_baseline();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let stored_count = decision
        .events
        .iter()
        .filter(|e| e.event == "flamegraph_stored")
        .count();
    assert_eq!(stored_count, 2);
}

// ---------- pipeline_id ----------

#[test]
fn pipeline_id_is_deterministic() {
    let request = request_with_diff();
    let mut adapter_a = InMemoryStorageAdapter::new();
    let mut adapter_b = InMemoryStorageAdapter::new();
    let decision_a = run_flamegraph_pipeline(&mut adapter_a, &request);
    let decision_b = run_flamegraph_pipeline(&mut adapter_b, &request);

    assert_eq!(decision_a.pipeline_id, decision_b.pipeline_id);
    assert!(decision_a.pipeline_id.starts_with("fgpipe-"));
}

#[test]
fn different_requests_produce_different_pipeline_ids() {
    let request_a = request_with_diff();
    let mut request_b = request_with_diff();
    request_b.benchmark_run_id = "bench-run-different".to_string();

    let mut adapter_a = InMemoryStorageAdapter::new();
    let mut adapter_b = InMemoryStorageAdapter::new();
    let decision_a = run_flamegraph_pipeline(&mut adapter_a, &request_a);
    let decision_b = run_flamegraph_pipeline(&mut adapter_b, &request_b);

    assert!(decision_a.is_success());
    assert!(decision_b.is_success());
    assert_ne!(decision_a.pipeline_id, decision_b.pipeline_id);
}

// ---------- store keys ----------

#[test]
fn store_keys_contain_benchmark_run_id_and_artifact_id() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    for key in &decision.store_keys {
        assert!(
            key.contains("bench-run-0001"),
            "store key should contain benchmark_run_id: {key}"
        );
        assert!(
            key.starts_with("flamegraph/"),
            "store key should start with flamegraph/: {key}"
        );
    }
}

// ---------- serde roundtrip ----------

#[test]
fn flamegraph_query_default_serde_roundtrip() {
    let query = FlamegraphQuery::default();
    let json = serde_json::to_string(&query).expect("serialize query");
    let recovered: FlamegraphQuery = serde_json::from_str(&json).expect("deserialize query");
    assert_eq!(recovered, query);
}

#[test]
fn flamegraph_request_serde_roundtrip() {
    let request = request_with_diff();
    let json = serde_json::to_string(&request).expect("serialize request");
    let recovered: FlamegraphPipelineRequest =
        serde_json::from_str(&json).expect("deserialize request");
    assert_eq!(recovered, request);
}

#[test]
fn flamegraph_artifact_serde_roundtrip() {
    let request = request_no_baseline();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    for artifact in &decision.artifacts {
        let json = serde_json::to_string(artifact).expect("serialize artifact");
        let recovered: FlamegraphArtifact =
            serde_json::from_str(&json).expect("deserialize artifact");
        assert_eq!(&recovered, artifact);
    }
}

// ---------- artifact_id uniqueness ----------

#[test]
fn all_artifact_ids_within_one_decision_are_unique() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let ids: BTreeSet<&str> = decision
        .artifacts
        .iter()
        .map(|a| a.artifact_id.as_str())
        .collect();
    assert_eq!(ids.len(), decision.artifacts.len());
}

#[test]
fn artifact_ids_start_with_fg_prefix() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    for artifact in &decision.artifacts {
        assert!(
            artifact.artifact_id.starts_with("fg-"),
            "artifact_id should start with fg-: {}",
            artifact.artifact_id
        );
    }
}

// ---------- decision fields ----------

#[test]
fn decision_carries_storage_backend_and_integration_point() {
    let request = request_no_baseline();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    assert!(!decision.storage_backend.is_empty());
    assert_eq!(
        decision.storage_integration_point,
        FLAMEGRAPH_STORAGE_INTEGRATION_POINT
    );
}

#[test]
fn failure_decision_has_empty_artifacts_and_store_keys() {
    let mut request = request_no_baseline();
    request.trace_id = String::new();

    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(!decision.is_success());
    assert!(decision.artifacts.is_empty());
    assert!(decision.store_keys.is_empty());
}

// ---------- low sample warning ----------

#[test]
fn low_sample_count_generates_warning() {
    let mut request = request_no_baseline();
    request.cpu_folded_stacks = "runtime;dispatch;policy_eval 3\nruntime;poll 2".to_string();
    request.allocation_folded_stacks = "runtime;alloc;vec_grow 4".to_string();

    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let has_warning = decision
        .artifacts
        .iter()
        .any(|a| a.warnings.iter().any(|w| w.contains("sample")));
    assert!(has_warning, "low sample count should produce a warning");
}
