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

// ===========================================================================
// 12. FlamegraphKind ordering and Clone/Copy
// ===========================================================================

#[test]
fn flamegraph_kind_ordering_is_deterministic() {
    let mut kinds = vec![
        FlamegraphKind::DiffAllocation,
        FlamegraphKind::Cpu,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::Allocation,
    ];
    kinds.sort();
    // Derive order follows variant declaration order: Cpu, Allocation, DiffCpu, DiffAllocation
    assert_eq!(kinds[0], FlamegraphKind::Cpu);
    assert_eq!(kinds[1], FlamegraphKind::Allocation);
    assert_eq!(kinds[2], FlamegraphKind::DiffCpu);
    assert_eq!(kinds[3], FlamegraphKind::DiffAllocation);
}

#[test]
fn flamegraph_kind_clone_copy_eq() {
    let original = FlamegraphKind::Cpu;
    let cloned = original.clone();
    let copied = original;
    assert_eq!(original, cloned);
    assert_eq!(original, copied);
    assert_eq!(cloned, copied);
}

// ===========================================================================
// 13. FlamegraphPipelineError Display and stable_code coverage
// ===========================================================================

#[test]
fn pipeline_error_stable_codes_cover_all_request_fields() {
    // Validate that each required field produces an error when empty
    let required_fields = [
        "trace_id",
        "decision_id",
        "policy_id",
        "benchmark_run_id",
        "optimization_decision_id",
        "workload_id",
        "benchmark_profile",
        "config_fingerprint",
        "git_commit",
    ];
    for field in required_fields {
        let mut adapter = InMemoryStorageAdapter::new();
        let mut request = make_request();
        match field {
            "trace_id" => request.trace_id = String::new(),
            "decision_id" => request.decision_id = String::new(),
            "policy_id" => request.policy_id = String::new(),
            "benchmark_run_id" => request.benchmark_run_id = String::new(),
            "optimization_decision_id" => request.optimization_decision_id = String::new(),
            "workload_id" => request.workload_id = String::new(),
            "benchmark_profile" => request.benchmark_profile = String::new(),
            "config_fingerprint" => request.config_fingerprint = String::new(),
            "git_commit" => request.git_commit = String::new(),
            _ => unreachable!(),
        }
        let decision = run_flamegraph_pipeline(&mut adapter, &request);
        assert!(
            !decision.is_success(),
            "expected failure for empty field `{field}`"
        );
        assert!(
            decision.error_code.is_some(),
            "expected error_code for empty field `{field}`"
        );
    }
}

#[test]
fn pipeline_decision_failed_has_no_artifacts_or_store_keys() {
    let mut adapter = InMemoryStorageAdapter::new();
    let mut request = make_request();
    request.trace_id = String::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(!decision.is_success());
    assert!(decision.artifacts.is_empty());
    assert!(decision.store_keys.is_empty());
}

// ===========================================================================
// 14. Artifact determinism — same inputs produce identical artifact IDs
// ===========================================================================

#[test]
fn pipeline_artifact_ids_are_deterministic() {
    let mut adapter1 = InMemoryStorageAdapter::new();
    let mut adapter2 = InMemoryStorageAdapter::new();
    let request = make_request();
    let decision1 = run_flamegraph_pipeline(&mut adapter1, &request);
    let decision2 = run_flamegraph_pipeline(&mut adapter2, &request);
    assert!(decision1.is_success());
    assert!(decision2.is_success());
    assert_eq!(decision1.artifacts.len(), decision2.artifacts.len());
    for (a1, a2) in decision1.artifacts.iter().zip(decision2.artifacts.iter()) {
        assert_eq!(a1.artifact_id, a2.artifact_id);
        assert_eq!(a1.svg, a2.svg);
        assert_eq!(a1.total_samples, a2.total_samples);
    }
}

#[test]
fn pipeline_id_is_deterministic() {
    let mut adapter1 = InMemoryStorageAdapter::new();
    let mut adapter2 = InMemoryStorageAdapter::new();
    let request = make_request();
    let d1 = run_flamegraph_pipeline(&mut adapter1, &request);
    let d2 = run_flamegraph_pipeline(&mut adapter2, &request);
    assert_eq!(d1.pipeline_id, d2.pipeline_id);
}

// ===========================================================================
// 15. Serde round-trip of FlamegraphArtifact
// ===========================================================================

#[test]
fn flamegraph_artifact_serde_roundtrip() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    assert!(decision.is_success());
    for artifact in &decision.artifacts {
        let json = serde_json::to_string(artifact).unwrap();
        let back: frankenengine_engine::flamegraph_pipeline::FlamegraphArtifact =
            serde_json::from_str(&json).unwrap();
        assert_eq!(&back, artifact);
    }
}

// ===========================================================================
// 16. Query filters — decision_id, trace_id, git_commit
// ===========================================================================

#[test]
fn query_by_decision_id_filter() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    assert!(decision.is_success());

    let query = FlamegraphQuery {
        decision_id: Some("dec-1".into()),
        ..Default::default()
    };
    let results = query_flamegraph_artifacts(&mut adapter, &query, "tq", "dq", "pq").unwrap();
    assert_eq!(results.len(), 2);

    // Non-matching decision_id returns empty
    let query_miss = FlamegraphQuery {
        decision_id: Some("dec-nonexistent".into()),
        ..Default::default()
    };
    let empty = query_flamegraph_artifacts(&mut adapter, &query_miss, "tq", "dq", "pq").unwrap();
    assert!(empty.is_empty());
}

#[test]
fn query_by_git_commit_filter() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    assert!(decision.is_success());

    let query = FlamegraphQuery {
        git_commit: Some("abc123".into()),
        ..Default::default()
    };
    let results = query_flamegraph_artifacts(&mut adapter, &query, "tq", "dq", "pq").unwrap();
    assert_eq!(results.len(), 2);

    let query_miss = FlamegraphQuery {
        git_commit: Some("zzz999".into()),
        ..Default::default()
    };
    let empty = query_flamegraph_artifacts(&mut adapter, &query_miss, "tq", "dq", "pq").unwrap();
    assert!(empty.is_empty());
}

// ===========================================================================
// 17. Whitespace-only fields treated as empty
// ===========================================================================

#[test]
fn whitespace_only_required_field_fails() {
    let mut adapter = InMemoryStorageAdapter::new();
    let mut request = make_request();
    request.workload_id = "   ".into();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(!decision.is_success());
    assert!(decision.error_code.is_some());
}

// ===========================================================================
// 18. Empty baseline_benchmark_run_id string
// ===========================================================================

#[test]
fn empty_baseline_benchmark_run_id_fails() {
    let mut adapter = InMemoryStorageAdapter::new();
    let mut request = make_request();
    request.baseline_benchmark_run_id = Some("".into());
    request.baseline_cpu_folded_stacks = Some("main;foo 10\n".into());
    request.baseline_allocation_folded_stacks = Some("alloc;a 5\n".into());
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(!decision.is_success());
}

// ===========================================================================
// 19. FlamegraphPipelineEvent with all optional fields populated
// ===========================================================================

#[test]
fn flamegraph_pipeline_event_all_fields_serde() {
    let e = FlamegraphPipelineEvent {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: FLAMEGRAPH_COMPONENT.into(),
        event: "flamegraph_generated".into(),
        outcome: "pass".into(),
        error_code: Some("FE-FLAME-1001".into()),
        artifact_id: Some("art-xyz".into()),
        flamegraph_kind: Some("cpu".into()),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: FlamegraphPipelineEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
    assert_eq!(back.error_code.as_deref(), Some("FE-FLAME-1001"));
    assert_eq!(back.artifact_id.as_deref(), Some("art-xyz"));
    assert_eq!(back.flamegraph_kind.as_deref(), Some("cpu"));
}

// ===========================================================================
// 20. Validate artifact rejects wrong storage_integration_point
// ===========================================================================

#[test]
fn validate_artifact_wrong_storage_integration_point() {
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &make_request());
    let mut artifact = decision.artifacts[0].clone();
    artifact.storage_integration_point = "wrong::integration::point".into();
    assert!(validate_flamegraph_artifact(&artifact).is_err());
}

// ===========================================================================
// 21. Diff pipeline events include baseline parse events
// ===========================================================================

#[test]
fn diff_pipeline_emits_baseline_parse_events() {
    let mut adapter = InMemoryStorageAdapter::new();
    let mut request = make_request();
    request.baseline_benchmark_run_id = Some("baseline-run".into());
    request.baseline_cpu_folded_stacks = Some("main;foo 80\n".into());
    request.baseline_allocation_folded_stacks = Some("alloc;a 40\n".into());
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let folded_parsed_events: Vec<&FlamegraphPipelineEvent> = decision
        .events
        .iter()
        .filter(|e| e.event == "folded_stacks_parsed")
        .collect();
    // cpu, allocation, baseline_cpu, baseline_allocation = 4 parse events
    assert!(folded_parsed_events.len() >= 4);

    let generated_events: Vec<&FlamegraphPipelineEvent> = decision
        .events
        .iter()
        .filter(|e| e.event == "flamegraph_generated")
        .collect();
    // cpu, allocation, diff_cpu, diff_allocation = 4 generated events
    assert_eq!(generated_events.len(), 4);
}
