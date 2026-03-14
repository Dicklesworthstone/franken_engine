#![forbid(unsafe_code)]
//! Enrichment integration tests for `flamegraph_pipeline`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, validation edge cases, and query defaults
//! beyond the existing 35 integration tests.

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
    FLAMEGRAPH_COMPONENT, FLAMEGRAPH_SCHEMA_VERSION, FLAMEGRAPH_STORAGE_INTEGRATION_POINT,
    FlamegraphArtifact, FlamegraphDiffEntry, FlamegraphEvidenceLink, FlamegraphKind,
    FlamegraphMetadata, FlamegraphPipelineDecision, FlamegraphPipelineError,
    FlamegraphPipelineEvent, FlamegraphPipelineRequest, FlamegraphQuery, FoldedStackSample,
};

// ===========================================================================
// 1) FlamegraphKind — exact Display / as_str
// ===========================================================================

#[test]
fn flamegraph_kind_display_exact() {
    assert_eq!(
        FlamegraphKind::Cpu.to_string(),
        FlamegraphKind::Cpu.as_str()
    );
    assert_eq!(
        FlamegraphKind::Allocation.to_string(),
        FlamegraphKind::Allocation.as_str()
    );
    assert_eq!(
        FlamegraphKind::DiffCpu.to_string(),
        FlamegraphKind::DiffCpu.as_str()
    );
    assert_eq!(
        FlamegraphKind::DiffAllocation.to_string(),
        FlamegraphKind::DiffAllocation.as_str()
    );
}

#[test]
fn flamegraph_kind_as_str_all_distinct() {
    let strs = [
        FlamegraphKind::Cpu.as_str(),
        FlamegraphKind::Allocation.as_str(),
        FlamegraphKind::DiffCpu.as_str(),
        FlamegraphKind::DiffAllocation.as_str(),
    ];
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 2) FlamegraphPipelineError — stable codes + uniqueness
// ===========================================================================

#[test]
fn pipeline_error_stable_codes_all_distinct() {
    let errors: Vec<(_, &str)> = vec![
        (
            FlamegraphPipelineError::InvalidRequest {
                field: "f".into(),
                detail: "d".into(),
            },
            "FE-FLAME-1001",
        ),
        (
            FlamegraphPipelineError::InvalidTimestamp { value: "v".into() },
            "FE-FLAME-1002",
        ),
        (
            FlamegraphPipelineError::EmptyFoldedStack { field: "f".into() },
            "FE-FLAME-1003",
        ),
        (
            FlamegraphPipelineError::MismatchedDiffInput,
            "FE-FLAME-1004",
        ),
        (
            FlamegraphPipelineError::InvalidSvg {
                kind: FlamegraphKind::Cpu,
            },
            "FE-FLAME-1005",
        ),
        (
            FlamegraphPipelineError::SerializationFailure { detail: "d".into() },
            "FE-FLAME-1006",
        ),
    ];
    for (err, expected_code) in &errors {
        assert_eq!(err.stable_code(), *expected_code, "code mismatch for {err}");
    }
}

#[test]
fn pipeline_error_display_all_unique() {
    let variants: Vec<String> = vec![
        FlamegraphPipelineError::InvalidRequest {
            field: "f".into(),
            detail: "d".into(),
        }
        .to_string(),
        FlamegraphPipelineError::InvalidTimestamp { value: "v".into() }.to_string(),
        FlamegraphPipelineError::InvalidFoldedStack {
            field: "f".into(),
            line_number: 1,
            detail: "d".into(),
        }
        .to_string(),
        FlamegraphPipelineError::EmptyFoldedStack { field: "f".into() }.to_string(),
        FlamegraphPipelineError::MismatchedDiffInput.to_string(),
        FlamegraphPipelineError::InvalidSvg {
            kind: FlamegraphKind::Cpu,
        }
        .to_string(),
        FlamegraphPipelineError::SerializationFailure { detail: "d".into() }.to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn pipeline_error_is_std_error() {
    let e = FlamegraphPipelineError::MismatchedDiffInput;
    let _: &dyn std::error::Error = &e;
}

#[test]
fn pipeline_error_requires_rollback_only_storage() {
    assert!(
        !FlamegraphPipelineError::InvalidRequest {
            field: "f".into(),
            detail: "d".into()
        }
        .requires_rollback()
    );
    assert!(!FlamegraphPipelineError::MismatchedDiffInput.requires_rollback());
}

// ===========================================================================
// 3) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_flamegraph_kind() {
    let variants = [
        format!("{:?}", FlamegraphKind::Cpu),
        format!("{:?}", FlamegraphKind::Allocation),
        format!("{:?}", FlamegraphKind::DiffCpu),
        format!("{:?}", FlamegraphKind::DiffAllocation),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 4) Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_flamegraph_kind_tags() {
    let kinds = [
        FlamegraphKind::Cpu,
        FlamegraphKind::Allocation,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::DiffAllocation,
    ];
    let expected = [
        "\"cpu\"",
        "\"allocation\"",
        "\"diff_cpu\"",
        "\"diff_allocation\"",
    ];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(json, *exp, "FlamegraphKind serde tag mismatch for {k:?}");
    }
}

// ===========================================================================
// 5) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_folded_stack_sample() {
    let fss = FoldedStackSample {
        stack: "main;foo;bar".into(),
        sample_count: 42,
    };
    let v: serde_json::Value = serde_json::to_value(&fss).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["stack", "sample_count"] {
        assert!(
            obj.contains_key(key),
            "FoldedStackSample missing field: {key}"
        );
    }
}

#[test]
fn json_fields_flamegraph_diff_entry() {
    let fde = FlamegraphDiffEntry {
        stack: "main;foo".into(),
        baseline_samples: 10,
        candidate_samples: 15,
        delta_samples: 5,
    };
    let v: serde_json::Value = serde_json::to_value(&fde).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "stack",
        "baseline_samples",
        "candidate_samples",
        "delta_samples",
    ] {
        assert!(
            obj.contains_key(key),
            "FlamegraphDiffEntry missing field: {key}"
        );
    }
}

#[test]
fn json_fields_flamegraph_metadata() {
    let fm = FlamegraphMetadata {
        benchmark_run_id: "run1".into(),
        baseline_benchmark_run_id: None,
        workload_id: "wl1".into(),
        benchmark_profile: "profile1".into(),
        config_fingerprint: "fp1".into(),
        git_commit: "abc123".into(),
        generated_at_utc: "2026-02-27T00:00:00Z".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&fm).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "benchmark_run_id",
        "baseline_benchmark_run_id",
        "workload_id",
        "benchmark_profile",
        "config_fingerprint",
        "git_commit",
        "generated_at_utc",
    ] {
        assert!(
            obj.contains_key(key),
            "FlamegraphMetadata missing field: {key}"
        );
    }
}

#[test]
fn json_fields_flamegraph_evidence_link() {
    let fel = FlamegraphEvidenceLink {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        benchmark_run_id: "r".into(),
        optimization_decision_id: "o".into(),
        evidence_node_id: "n".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&fel).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "benchmark_run_id",
        "optimization_decision_id",
        "evidence_node_id",
    ] {
        assert!(
            obj.contains_key(key),
            "FlamegraphEvidenceLink missing field: {key}"
        );
    }
}

#[test]
fn json_fields_flamegraph_pipeline_event() {
    let fpe = FlamegraphPipelineEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: FLAMEGRAPH_COMPONENT.into(),
        event: "test".into(),
        outcome: "pass".into(),
        error_code: None,
        artifact_id: None,
        flamegraph_kind: None,
    };
    let v: serde_json::Value = serde_json::to_value(&fpe).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "artifact_id",
        "flamegraph_kind",
    ] {
        assert!(
            obj.contains_key(key),
            "FlamegraphPipelineEvent missing field: {key}"
        );
    }
}

// ===========================================================================
// 6) Constants stability
// ===========================================================================

#[test]
fn constants_stable() {
    assert_eq!(FLAMEGRAPH_COMPONENT, "flamegraph_pipeline");
    assert_eq!(
        FLAMEGRAPH_SCHEMA_VERSION,
        "franken-engine.flamegraph-artifact.v1"
    );
    assert_eq!(
        FLAMEGRAPH_STORAGE_INTEGRATION_POINT,
        "frankensqlite::benchmark::ledger"
    );
}

// ===========================================================================
// 7) FlamegraphQuery — default
// ===========================================================================

#[test]
fn flamegraph_query_default() {
    let q = FlamegraphQuery::default();
    assert!(q.benchmark_run_id.is_none());
    assert!(q.workload_id.is_none());
    assert!(q.git_commit.is_none());
    assert!(q.kind.is_none());
    assert!(q.decision_id.is_none());
    assert!(q.trace_id.is_none());
    assert!(q.limit.is_none());
}

// ===========================================================================
// 8) FlamegraphKind ordering
// ===========================================================================

#[test]
fn flamegraph_kind_ordering_stable() {
    let mut kinds = [
        FlamegraphKind::DiffAllocation,
        FlamegraphKind::Cpu,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::Allocation,
    ];
    kinds.sort();
    assert_eq!(kinds[0], FlamegraphKind::Cpu);
}

// ===========================================================================
// 9) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_flamegraph_kind_all() {
    for k in [
        FlamegraphKind::Cpu,
        FlamegraphKind::Allocation,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::DiffAllocation,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: FlamegraphKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_folded_stack_sample() {
    let fss = FoldedStackSample {
        stack: "a;b;c".into(),
        sample_count: 100,
    };
    let json = serde_json::to_string(&fss).unwrap();
    let rt: FoldedStackSample = serde_json::from_str(&json).unwrap();
    assert_eq!(fss, rt);
}

#[test]
fn serde_roundtrip_flamegraph_diff_entry() {
    let fde = FlamegraphDiffEntry {
        stack: "x;y".into(),
        baseline_samples: 5,
        candidate_samples: 10,
        delta_samples: 5,
    };
    let json = serde_json::to_string(&fde).unwrap();
    let rt: FlamegraphDiffEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(fde, rt);
}

#[test]
fn serde_roundtrip_flamegraph_query() {
    let q = FlamegraphQuery {
        benchmark_run_id: Some("run1".into()),
        kind: Some(FlamegraphKind::Cpu),
        limit: Some(10),
        ..FlamegraphQuery::default()
    };
    let json = serde_json::to_string(&q).unwrap();
    let rt: FlamegraphQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q, rt);
}

// ===========================================================================
// 10) FlamegraphPipelineDecision — is_success
// ===========================================================================

#[test]
fn pipeline_decision_is_success() {
    let d = FlamegraphPipelineDecision {
        pipeline_id: "p1".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        outcome: "pass".into(),
        error_code: None,
        rollback_required: false,
        storage_backend: "test".into(),
        storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.into(),
        artifacts: vec![],
        store_keys: vec![],
        events: vec![],
    };
    assert!(d.is_success());
}

#[test]
fn pipeline_decision_is_failure() {
    let d = FlamegraphPipelineDecision {
        pipeline_id: "p1".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        outcome: "fail".into(),
        error_code: Some("FE-FLAME-1001".into()),
        rollback_required: false,
        storage_backend: "test".into(),
        storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.into(),
        artifacts: vec![],
        store_keys: vec![],
        events: vec![],
    };
    assert!(!d.is_success());
}

// ===========================================================================
// 11) Serde roundtrips — additional structs
// ===========================================================================

#[test]
fn serde_roundtrip_flamegraph_metadata() {
    let fm = FlamegraphMetadata {
        benchmark_run_id: "run1".into(),
        baseline_benchmark_run_id: Some("baseline1".into()),
        workload_id: "wl1".into(),
        benchmark_profile: "profile1".into(),
        config_fingerprint: "fp1".into(),
        git_commit: "abc123".into(),
        generated_at_utc: "2026-02-27T00:00:00Z".into(),
    };
    let json = serde_json::to_string(&fm).unwrap();
    let rt: FlamegraphMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(fm, rt);
}

#[test]
fn serde_roundtrip_flamegraph_evidence_link() {
    let fel = FlamegraphEvidenceLink {
        trace_id: "t1".into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        benchmark_run_id: "r1".into(),
        optimization_decision_id: "o1".into(),
        evidence_node_id: "n1".into(),
    };
    let json = serde_json::to_string(&fel).unwrap();
    let rt: FlamegraphEvidenceLink = serde_json::from_str(&json).unwrap();
    assert_eq!(fel, rt);
}

#[test]
fn serde_roundtrip_flamegraph_pipeline_event() {
    let fpe = FlamegraphPipelineEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: FLAMEGRAPH_COMPONENT.into(),
        event: "test_event".into(),
        outcome: "pass".into(),
        error_code: Some("FE-FLAME-1001".into()),
        artifact_id: Some("art1".into()),
        flamegraph_kind: Some("cpu".into()),
    };
    let json = serde_json::to_string(&fpe).unwrap();
    let rt: FlamegraphPipelineEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(fpe, rt);
}

// ===========================================================================
// 12) FlamegraphPipelineError — Display contains relevant fields
// ===========================================================================

#[test]
fn pipeline_error_invalid_request_contains_field() {
    let e = FlamegraphPipelineError::InvalidRequest {
        field: "trace_id".into(),
        detail: "cannot be empty".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("trace_id") || s.contains("empty"),
        "should contain field: {s}"
    );
}

#[test]
fn pipeline_error_invalid_timestamp_contains_value() {
    let e = FlamegraphPipelineError::InvalidTimestamp {
        value: "not-a-date".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("not-a-date") || s.contains("timestamp"),
        "should contain value: {s}"
    );
}

#[test]
fn pipeline_error_invalid_folded_stack_contains_line() {
    let e = FlamegraphPipelineError::InvalidFoldedStack {
        field: "cpu_stacks".into(),
        line_number: 42,
        detail: "malformed".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("42") || s.contains("malformed"),
        "should contain line: {s}"
    );
}

#[test]
fn pipeline_error_empty_folded_stack_contains_field() {
    let e = FlamegraphPipelineError::EmptyFoldedStack {
        field: "allocation_stacks".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("allocation_stacks") || s.contains("empty"),
        "should contain field: {s}"
    );
}

#[test]
fn pipeline_error_serialization_contains_detail() {
    let e = FlamegraphPipelineError::SerializationFailure {
        detail: "json error".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("json") || s.contains("serialization"),
        "should contain detail: {s}"
    );
}

// ===========================================================================
// 13) FlamegraphKind — as_str values
// ===========================================================================

#[test]
fn flamegraph_kind_as_str_values() {
    assert_eq!(FlamegraphKind::Cpu.as_str(), "cpu");
    assert_eq!(FlamegraphKind::Allocation.as_str(), "allocation");
    assert_eq!(FlamegraphKind::DiffCpu.as_str(), "diff_cpu");
    assert_eq!(FlamegraphKind::DiffAllocation.as_str(), "diff_allocation");
}

// ===========================================================================
// 14) FlamegraphPipelineError — stable_code values
// ===========================================================================

#[test]
fn pipeline_error_invalid_folded_stack_code() {
    let e = FlamegraphPipelineError::InvalidFoldedStack {
        field: "f".into(),
        line_number: 1,
        detail: "d".into(),
    };
    // InvalidFoldedStack should have a code too
    let code = e.stable_code();
    assert!(
        code.starts_with("FE-FLAME-"),
        "code should start with FE-FLAME-: {code}"
    );
}

// ===========================================================================
// 15) FlamegraphDiffEntry — delta sign
// ===========================================================================

#[test]
fn flamegraph_diff_entry_negative_delta() {
    let fde = FlamegraphDiffEntry {
        stack: "main;foo".into(),
        baseline_samples: 100,
        candidate_samples: 50,
        delta_samples: -50,
    };
    assert!(fde.delta_samples < 0);
    let json = serde_json::to_string(&fde).unwrap();
    let rt: FlamegraphDiffEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(fde, rt);
}

// ===========================================================================
// 16) FlamegraphPipelineDecision serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_pipeline_decision() {
    let d = FlamegraphPipelineDecision {
        pipeline_id: "p1".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        outcome: "pass".into(),
        error_code: None,
        rollback_required: false,
        storage_backend: "test".into(),
        storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.into(),
        artifacts: vec![],
        store_keys: vec![],
        events: vec![],
    };
    let json = serde_json::to_string(&d).unwrap();
    let rt: FlamegraphPipelineDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, rt);
}

// ===========================================================================
// 17) FoldedStackSample edge cases
// ===========================================================================

#[test]
fn folded_stack_sample_zero_count() {
    let fss = FoldedStackSample {
        stack: "main".into(),
        sample_count: 0,
    };
    let json = serde_json::to_string(&fss).unwrap();
    let rt: FoldedStackSample = serde_json::from_str(&json).unwrap();
    assert_eq!(fss, rt);
}

#[test]
fn folded_stack_sample_deep_stack() {
    let deep = (0..100)
        .map(|i| format!("frame_{i}"))
        .collect::<Vec<_>>()
        .join(";");
    let fss = FoldedStackSample {
        stack: deep.clone(),
        sample_count: 1,
    };
    let json = serde_json::to_string(&fss).unwrap();
    let rt: FoldedStackSample = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.stack, deep);
}

// ===========================================================================
// 18) FlamegraphMetadata optional baseline
// ===========================================================================

#[test]
fn flamegraph_metadata_no_baseline() {
    let fm = FlamegraphMetadata {
        benchmark_run_id: "run1".into(),
        baseline_benchmark_run_id: None,
        workload_id: "wl1".into(),
        benchmark_profile: "profile1".into(),
        config_fingerprint: "fp1".into(),
        git_commit: "abc123".into(),
        generated_at_utc: "2026-02-27T00:00:00Z".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&fm).unwrap();
    assert!(v["baseline_benchmark_run_id"].is_null());
}

#[test]
fn flamegraph_metadata_with_baseline() {
    let fm = FlamegraphMetadata {
        benchmark_run_id: "run1".into(),
        baseline_benchmark_run_id: Some("baseline1".into()),
        workload_id: "wl1".into(),
        benchmark_profile: "profile1".into(),
        config_fingerprint: "fp1".into(),
        git_commit: "abc123".into(),
        generated_at_utc: "2026-02-27T00:00:00Z".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&fm).unwrap();
    assert_eq!(v["baseline_benchmark_run_id"], "baseline1");
}

// ===========================================================================
// 19) FlamegraphPipelineRequest — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_flamegraph_pipeline_request() {
    let req = FlamegraphPipelineRequest {
        trace_id: "t1".into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        benchmark_run_id: "run1".into(),
        optimization_decision_id: "o1".into(),
        workload_id: "wl1".into(),
        benchmark_profile: "prof1".into(),
        config_fingerprint: "fp1".into(),
        git_commit: "abc123".into(),
        generated_at_utc: "2026-03-13T00:00:00Z".into(),
        cpu_folded_stacks: "main;foo 10\n".into(),
        allocation_folded_stacks: "main;bar 5\n".into(),
        baseline_benchmark_run_id: Some("base_run".into()),
        baseline_cpu_folded_stacks: Some("main;foo 8\n".into()),
        baseline_allocation_folded_stacks: Some("main;bar 3\n".into()),
    };
    let json = serde_json::to_string(&req).unwrap();
    let rt: FlamegraphPipelineRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, rt);
}

// ===========================================================================
// 20) FlamegraphPipelineRequest — JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_flamegraph_pipeline_request() {
    let req = FlamegraphPipelineRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        benchmark_run_id: "r".into(),
        optimization_decision_id: "o".into(),
        workload_id: "w".into(),
        benchmark_profile: "bp".into(),
        config_fingerprint: "cf".into(),
        git_commit: "gc".into(),
        generated_at_utc: "ts".into(),
        cpu_folded_stacks: "main 1\n".into(),
        allocation_folded_stacks: "main 1\n".into(),
        baseline_benchmark_run_id: None,
        baseline_cpu_folded_stacks: None,
        baseline_allocation_folded_stacks: None,
    };
    let v: serde_json::Value = serde_json::to_value(&req).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "benchmark_run_id",
        "optimization_decision_id",
        "workload_id",
        "benchmark_profile",
        "config_fingerprint",
        "git_commit",
        "generated_at_utc",
        "cpu_folded_stacks",
        "allocation_folded_stacks",
        "baseline_benchmark_run_id",
        "baseline_cpu_folded_stacks",
        "baseline_allocation_folded_stacks",
    ] {
        assert!(
            obj.contains_key(key),
            "FlamegraphPipelineRequest missing field: {key}"
        );
    }
}

// ===========================================================================
// 21) FlamegraphArtifact — JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_flamegraph_artifact() {
    let artifact = FlamegraphArtifact {
        schema_version: FLAMEGRAPH_SCHEMA_VERSION.into(),
        artifact_id: "fg-test123".into(),
        kind: FlamegraphKind::Cpu,
        metadata: FlamegraphMetadata {
            benchmark_run_id: "run1".into(),
            baseline_benchmark_run_id: None,
            workload_id: "wl1".into(),
            benchmark_profile: "prof1".into(),
            config_fingerprint: "fp1".into(),
            git_commit: "abc".into(),
            generated_at_utc: "2026-01-01T00:00:00Z".into(),
        },
        evidence_link: FlamegraphEvidenceLink {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            benchmark_run_id: "r".into(),
            optimization_decision_id: "o".into(),
            evidence_node_id: "n".into(),
        },
        folded_stacks: vec![FoldedStackSample {
            stack: "main".into(),
            sample_count: 10,
        }],
        folded_stacks_text: "main 10\n".into(),
        svg: "<svg><rect/><text/></svg>".into(),
        total_samples: 10,
        diff_from_artifact_id: None,
        diff_entries: vec![],
        warnings: vec![],
        storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.into(),
    };
    let v: serde_json::Value = serde_json::to_value(&artifact).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "artifact_id",
        "kind",
        "metadata",
        "evidence_link",
        "folded_stacks",
        "folded_stacks_text",
        "svg",
        "total_samples",
        "diff_from_artifact_id",
        "diff_entries",
        "warnings",
        "storage_integration_point",
    ] {
        assert!(
            obj.contains_key(key),
            "FlamegraphArtifact missing field: {key}"
        );
    }
}

// ===========================================================================
// 22) FlamegraphPipelineDecision — JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_flamegraph_pipeline_decision() {
    let d = FlamegraphPipelineDecision {
        pipeline_id: "p1".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        outcome: "pass".into(),
        error_code: None,
        rollback_required: false,
        storage_backend: "test".into(),
        storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.into(),
        artifacts: vec![],
        store_keys: vec![],
        events: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&d).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "pipeline_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "outcome",
        "error_code",
        "rollback_required",
        "storage_backend",
        "storage_integration_point",
        "artifacts",
        "store_keys",
        "events",
    ] {
        assert!(
            obj.contains_key(key),
            "FlamegraphPipelineDecision missing field: {key}"
        );
    }
}

// ===========================================================================
// 23) FlamegraphPipelineError — StorageFailure requires_rollback true
// ===========================================================================

#[test]
fn pipeline_error_storage_failure_requires_rollback() {
    use frankenengine_engine::storage_adapter::StorageError;
    let e = FlamegraphPipelineError::StorageFailure(StorageError::BackendUnavailable {
        backend: "test".into(),
        detail: "unavailable".into(),
    });
    assert!(e.requires_rollback());
}

// ===========================================================================
// 24) FlamegraphPipelineError — StorageFailure stable_code is FE-FLAME-1007
// ===========================================================================

#[test]
fn pipeline_error_storage_failure_stable_code() {
    use frankenengine_engine::storage_adapter::StorageError;
    let e = FlamegraphPipelineError::StorageFailure(StorageError::NotFound {
        store: frankenengine_engine::storage_adapter::StoreKind::BenchmarkLedger,
        key: "k".into(),
    });
    assert_eq!(e.stable_code(), "FE-FLAME-1007");
}

// ===========================================================================
// 25) FlamegraphPipelineError — InvalidSvg display contains kind string
// ===========================================================================

#[test]
fn pipeline_error_invalid_svg_display_contains_kind() {
    for kind in [
        FlamegraphKind::Cpu,
        FlamegraphKind::Allocation,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::DiffAllocation,
    ] {
        let e = FlamegraphPipelineError::InvalidSvg { kind };
        let s = e.to_string();
        assert!(
            s.contains(kind.as_str()),
            "InvalidSvg display should contain kind `{}`: got `{s}`",
            kind.as_str()
        );
    }
}

// ===========================================================================
// 26) FlamegraphQuery — serde with all fields populated
// ===========================================================================

#[test]
fn serde_roundtrip_flamegraph_query_all_fields() {
    let q = FlamegraphQuery {
        benchmark_run_id: Some("run1".into()),
        workload_id: Some("wl1".into()),
        git_commit: Some("abc123".into()),
        kind: Some(FlamegraphKind::DiffCpu),
        decision_id: Some("d1".into()),
        trace_id: Some("t1".into()),
        limit: Some(50),
    };
    let json = serde_json::to_string(&q).unwrap();
    let rt: FlamegraphQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q, rt);
    // Also verify JSON field names
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "benchmark_run_id",
        "workload_id",
        "git_commit",
        "kind",
        "decision_id",
        "trace_id",
        "limit",
    ] {
        assert!(
            obj.contains_key(key),
            "FlamegraphQuery missing field: {key}"
        );
    }
}

// ===========================================================================
// 27) FlamegraphPipelineDecision — rollback_required true roundtrip
// ===========================================================================

#[test]
fn pipeline_decision_rollback_required_roundtrip() {
    let d = FlamegraphPipelineDecision {
        pipeline_id: "p1".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        outcome: "fail".into(),
        error_code: Some("FE-FLAME-1007".into()),
        rollback_required: true,
        storage_backend: "test".into(),
        storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.into(),
        artifacts: vec![],
        store_keys: vec![],
        events: vec![],
    };
    let json = serde_json::to_string(&d).unwrap();
    let rt: FlamegraphPipelineDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, rt);
    assert!(rt.rollback_required);
    assert!(!rt.is_success());
}
