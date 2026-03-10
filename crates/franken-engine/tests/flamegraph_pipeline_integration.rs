#![forbid(unsafe_code)]
//! Integration tests for the `flamegraph_pipeline` module.
//!
//! Exercises FlamegraphKind, data structs, FlamegraphPipelineError,
//! validate_flamegraph_artifact, run_flamegraph_pipeline with InMemoryStorageAdapter,
//! query_flamegraph_artifacts, and full pipeline lifecycle.

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

use frankenengine_engine::flamegraph_pipeline::{
    FLAMEGRAPH_COMPONENT, FLAMEGRAPH_SCHEMA_VERSION, FLAMEGRAPH_STORAGE_INTEGRATION_POINT,
    FlamegraphDiffEntry, FlamegraphEvidenceLink, FlamegraphKind, FlamegraphMetadata,
    FlamegraphPipelineDecision, FlamegraphPipelineEvent, FlamegraphPipelineRequest,
    FlamegraphQuery, FoldedStackSample, query_flamegraph_artifacts, run_flamegraph_pipeline,
    validate_flamegraph_artifact,
};
use frankenengine_engine::storage_adapter::InMemoryStorageAdapter;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_request() -> FlamegraphPipelineRequest {
    FlamegraphPipelineRequest {
        trace_id: "trace-1".into(),
        decision_id: "dec-1".into(),
        policy_id: "pol-1".into(),
        benchmark_run_id: "run-1".into(),
        optimization_decision_id: "opt-1".into(),
        workload_id: "workload-1".into(),
        benchmark_profile: "profile-1".into(),
        config_fingerprint: "fp-1".into(),
        git_commit: "abc123".into(),
        generated_at_utc: "2026-01-01T00:00:00Z".into(),
        cpu_folded_stacks: "main;foo 100\nmain;bar 200\n".into(),
        allocation_folded_stacks: "alloc;a 50\nalloc;b 150\n".into(),
        baseline_benchmark_run_id: None,
        baseline_cpu_folded_stacks: None,
        baseline_allocation_folded_stacks: None,
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn constants_nonempty() {
    assert!(!FLAMEGRAPH_COMPONENT.is_empty());
    assert!(!FLAMEGRAPH_SCHEMA_VERSION.is_empty());
    assert!(!FLAMEGRAPH_STORAGE_INTEGRATION_POINT.is_empty());
}

// ===========================================================================
// 2. FlamegraphKind
// ===========================================================================

#[test]
fn flamegraph_kind_as_str() {
    assert_eq!(FlamegraphKind::Cpu.as_str(), "cpu");
    assert_eq!(FlamegraphKind::Allocation.as_str(), "allocation");
    assert_eq!(FlamegraphKind::DiffCpu.as_str(), "diff_cpu");
    assert_eq!(FlamegraphKind::DiffAllocation.as_str(), "diff_allocation");
}

#[test]
fn flamegraph_kind_display() {
    assert_eq!(FlamegraphKind::Cpu.to_string(), "cpu");
    assert_eq!(
        FlamegraphKind::DiffAllocation.to_string(),
        "diff_allocation"
    );
}

#[test]
fn flamegraph_kind_serde() {
    for k in [
        FlamegraphKind::Cpu,
        FlamegraphKind::Allocation,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::DiffAllocation,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: FlamegraphKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

// ===========================================================================
// 3. Data struct serde
// ===========================================================================

#[test]
fn folded_stack_sample_serde() {
    let s = FoldedStackSample {
        stack: "main;foo".into(),
        sample_count: 42,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: FoldedStackSample = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

#[test]
fn flamegraph_diff_entry_serde() {
    let e = FlamegraphDiffEntry {
        stack: "main;bar".into(),
        baseline_samples: 100,
        candidate_samples: 150,
        delta_samples: 50,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: FlamegraphDiffEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn flamegraph_metadata_serde() {
    let m = FlamegraphMetadata {
        benchmark_run_id: "run-1".into(),
        baseline_benchmark_run_id: None,
        workload_id: "w-1".into(),
        benchmark_profile: "p-1".into(),
        config_fingerprint: "fp-1".into(),
        git_commit: "abc".into(),
        generated_at_utc: "2026-01-01T00:00:00Z".into(),
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: FlamegraphMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(back, m);
}

#[test]
fn flamegraph_evidence_link_serde() {
    let e = FlamegraphEvidenceLink {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        benchmark_run_id: "r".into(),
        optimization_decision_id: "o".into(),
        evidence_node_id: "e".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: FlamegraphEvidenceLink = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn flamegraph_pipeline_event_serde() {
    let e = FlamegraphPipelineEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: FLAMEGRAPH_COMPONENT.into(),
        event: "test_event".into(),
        outcome: "pass".into(),
        error_code: None,
        artifact_id: None,
        flamegraph_kind: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: FlamegraphPipelineEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn flamegraph_pipeline_request_serde() {
    let r = make_request();
    let json = serde_json::to_string(&r).unwrap();
    let back: FlamegraphPipelineRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn flamegraph_query_default() {
    let q = FlamegraphQuery::default();
    assert!(q.benchmark_run_id.is_none());
    assert!(q.workload_id.is_none());
    assert!(q.kind.is_none());
    assert!(q.limit.is_none());
}

#[test]
fn flamegraph_query_serde() {
    let q = FlamegraphQuery {
        benchmark_run_id: Some("run-1".into()),
        workload_id: Some("w-1".into()),
        git_commit: Some("abc".into()),
        kind: Some(FlamegraphKind::Cpu),
        decision_id: None,
        trace_id: None,
        limit: Some(10),
    };
    let json = serde_json::to_string(&q).unwrap();
    let back: FlamegraphQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(back, q);
}

// ===========================================================================
// 4. FlamegraphPipelineDecision
// ===========================================================================

#[test]
fn pipeline_decision_is_success() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    assert!(decision.is_success());
    assert_eq!(decision.outcome, "pass");
    assert!(decision.error_code.is_none());
    assert!(!decision.rollback_required);
}

// ===========================================================================
// 5. run_flamegraph_pipeline — success paths
// ===========================================================================

#[test]
fn run_pipeline_produces_two_artifacts() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    assert!(decision.is_success());
    // CPU + Allocation = 2 artifacts
    assert_eq!(decision.artifacts.len(), 2);
    let kinds: Vec<FlamegraphKind> = decision.artifacts.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&FlamegraphKind::Cpu));
    assert!(kinds.contains(&FlamegraphKind::Allocation));
}

#[test]
fn run_pipeline_artifacts_have_correct_metadata() {
    let mut adapter = InMemoryStorageAdapter::new();
    let request = make_request();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    for artifact in &decision.artifacts {
        assert_eq!(artifact.schema_version, FLAMEGRAPH_SCHEMA_VERSION);
        assert_eq!(
            artifact.storage_integration_point,
            FLAMEGRAPH_STORAGE_INTEGRATION_POINT
        );
        assert_eq!(artifact.metadata.benchmark_run_id, "run-1");
        assert_eq!(artifact.metadata.workload_id, "workload-1");
        assert_eq!(artifact.evidence_link.trace_id, "trace-1");
    }
}

#[test]
fn run_pipeline_stores_artifacts() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    assert!(decision.is_success());
    assert!(!decision.store_keys.is_empty());
    for key in &decision.store_keys {
        assert!(key.starts_with("flamegraph/"));
    }
}

#[test]
fn run_pipeline_emits_events() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    assert!(!decision.events.is_empty());
    let event_types: Vec<&str> = decision.events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_types.contains(&"pipeline_started"));
    assert!(event_types.contains(&"pipeline_completed"));
    assert!(event_types.contains(&"folded_stacks_parsed"));
    assert!(event_types.contains(&"flamegraph_generated"));
}

#[test]
fn run_pipeline_artifacts_validate() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    for artifact in &decision.artifacts {
        validate_flamegraph_artifact(artifact).unwrap();
    }
}

// ===========================================================================
// 6. run_flamegraph_pipeline — with diff
// ===========================================================================

#[test]
fn run_pipeline_with_diff_produces_four_artifacts() {
    let mut adapter = InMemoryStorageAdapter::new();
    let mut request = make_request();
    request.baseline_benchmark_run_id = Some("baseline-run".into());
    request.baseline_cpu_folded_stacks = Some("main;foo 80\nmain;bar 120\n".into());
    request.baseline_allocation_folded_stacks = Some("alloc;a 40\nalloc;b 100\n".into());

    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());
    // CPU + Allocation + DiffCpu + DiffAllocation = 4
    assert_eq!(decision.artifacts.len(), 4);
    let kinds: Vec<FlamegraphKind> = decision.artifacts.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&FlamegraphKind::DiffCpu));
    assert!(kinds.contains(&FlamegraphKind::DiffAllocation));
}

// ===========================================================================
// 7. run_flamegraph_pipeline — error paths
// ===========================================================================

#[test]
fn run_pipeline_empty_trace_id_fails() {
    let mut adapter = InMemoryStorageAdapter::new();
    let mut request = make_request();
    request.trace_id = String::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(!decision.is_success());
    assert!(decision.error_code.is_some());
}

#[test]
fn run_pipeline_empty_benchmark_run_id_fails() {
    let mut adapter = InMemoryStorageAdapter::new();
    let mut request = make_request();
    request.benchmark_run_id = String::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(!decision.is_success());
}

#[test]
fn run_pipeline_invalid_timestamp_fails() {
    let mut adapter = InMemoryStorageAdapter::new();
    let mut request = make_request();
    request.generated_at_utc = "not-a-timestamp".into();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(!decision.is_success());
}

#[test]
fn run_pipeline_invalid_folded_stacks_fails() {
    let mut adapter = InMemoryStorageAdapter::new();
    let mut request = make_request();
    request.cpu_folded_stacks = "invalid_no_count".into();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(!decision.is_success());
}

#[test]
fn run_pipeline_empty_folded_stacks_fails() {
    let mut adapter = InMemoryStorageAdapter::new();
    let mut request = make_request();
    request.cpu_folded_stacks = String::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(!decision.is_success());
}

#[test]
fn run_pipeline_mismatched_diff_inputs_fails() {
    let mut adapter = InMemoryStorageAdapter::new();
    let mut request = make_request();
    // Only baseline CPU provided, not allocation
    request.baseline_benchmark_run_id = Some("baseline".into());
    request.baseline_cpu_folded_stacks = Some("main;foo 10\n".into());
    request.baseline_allocation_folded_stacks = None;
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(!decision.is_success());
}

#[test]
fn run_pipeline_storage_failure() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    assert!(!decision.is_success());
    assert!(decision.rollback_required);
}

// ===========================================================================
// 8. validate_flamegraph_artifact — error paths
// ===========================================================================

#[test]
fn validate_artifact_wrong_schema() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    let mut artifact = decision.artifacts[0].clone();
    artifact.schema_version = "wrong".into();
    assert!(validate_flamegraph_artifact(&artifact).is_err());
}

#[test]
fn validate_artifact_empty_id() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    let mut artifact = decision.artifacts[0].clone();
    artifact.artifact_id = String::new();
    assert!(validate_flamegraph_artifact(&artifact).is_err());
}

#[test]
fn validate_artifact_wrong_total_samples() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    let mut artifact = decision.artifacts[0].clone();
    artifact.total_samples = 999_999;
    assert!(validate_flamegraph_artifact(&artifact).is_err());
}

// ===========================================================================
// 9. query_flamegraph_artifacts
// ===========================================================================

#[test]
fn query_after_pipeline_returns_artifacts() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    assert!(decision.is_success());

    let query = FlamegraphQuery {
        benchmark_run_id: Some("run-1".into()),
        ..Default::default()
    };
    let results =
        query_flamegraph_artifacts(&mut adapter, &query, "trace-q", "dec-q", "pol-q").unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn query_with_kind_filter() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    assert!(decision.is_success());

    let query = FlamegraphQuery {
        benchmark_run_id: Some("run-1".into()),
        kind: Some(FlamegraphKind::Cpu),
        ..Default::default()
    };
    let results =
        query_flamegraph_artifacts(&mut adapter, &query, "trace-q", "dec-q", "pol-q").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].kind, FlamegraphKind::Cpu);
}

#[test]
fn query_no_match_returns_empty() {
    let mut adapter = InMemoryStorageAdapter::new();
    run_flamegraph_pipeline(&mut adapter, &make_request());

    let query = FlamegraphQuery {
        benchmark_run_id: Some("nonexistent".into()),
        ..Default::default()
    };
    let results =
        query_flamegraph_artifacts(&mut adapter, &query, "trace-q", "dec-q", "pol-q").unwrap();
    assert!(results.is_empty());
}

#[test]
fn query_limit_zero_fails() {
    let mut adapter = InMemoryStorageAdapter::new();
    let query = FlamegraphQuery {
        limit: Some(0),
        ..Default::default()
    };
    assert!(query_flamegraph_artifacts(&mut adapter, &query, "trace-q", "dec-q", "pol-q").is_err());
}

// ===========================================================================
// 10. Serde round-trip of decision
// ===========================================================================

#[test]
fn pipeline_decision_serde() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    let json = serde_json::to_string(&decision).unwrap();
    let back: FlamegraphPipelineDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, decision);
}

// ===========================================================================
// 11. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_pipeline_query_validate() {
    let mut adapter = InMemoryStorageAdapter::new();

    // 1. Run pipeline
    let request = make_request();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());
    assert_eq!(decision.artifacts.len(), 2);

    // 2. Validate all artifacts
    for artifact in &decision.artifacts {
        validate_flamegraph_artifact(artifact).unwrap();
    }

    // 3. Query back
    let query = FlamegraphQuery {
        benchmark_run_id: Some("run-1".into()),
        ..Default::default()
    };
    let queried =
        query_flamegraph_artifacts(&mut adapter, &query, "trace-q", "dec-q", "pol-q").unwrap();
    assert_eq!(queried.len(), 2);

    // 4. Verify queried artifacts match pipeline output
    for q_artifact in &queried {
        assert_eq!(q_artifact.schema_version, FLAMEGRAPH_SCHEMA_VERSION);
        assert_eq!(q_artifact.metadata.benchmark_run_id, "run-1");
        validate_flamegraph_artifact(q_artifact).unwrap();
    }

    // 5. Serde round-trip of decision
    let json = serde_json::to_string(&decision).unwrap();
    let back: FlamegraphPipelineDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, decision);
}
