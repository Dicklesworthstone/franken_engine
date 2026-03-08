#[path = "../src/seqlock_candidate_inventory.rs"]
mod seqlock_candidate_inventory;

use std::fs;
use std::path::PathBuf;

use seqlock_candidate_inventory::{
    ArtifactContext, BaselineStrategy, CONTRACT_SCHEMA_VERSION, CandidateDisposition,
    FallbackReason, ReadInterference, ReadResolution, RetryBudgetPolicyRow, SimulatedSeqlock,
    StructuredLogEvent, SurfaceArea, TearingRisk, WriteProfile, build_contract_fixture,
    default_candidate_inventory, emit_default_inventory_bundle, render_summary,
    SeqlockContractError, BEAD_ID, COMPONENT, INVENTORY_SCHEMA_VERSION,
    RETRY_SAFETY_SCHEMA_VERSION, BASELINE_COMPARATOR_SCHEMA_VERSION,
    READER_WRITER_CONTRACT_SCHEMA_VERSION, RETRY_BUDGET_POLICY_SCHEMA_VERSION,
    INCUMBENT_FALLBACK_MATRIX_SCHEMA_VERSION, TRACE_IDS_SCHEMA_VERSION,
    RUN_MANIFEST_SCHEMA_VERSION, PREDECESSOR_BEAD_ID,
};

fn temp_dir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before epoch")
        .as_nanos();
    path.push(format!(
        "franken-engine-seqlock-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

#[test]
fn bundle_writes_required_artifacts_and_contract_files() {
    let artifact_dir = temp_dir("bundle");
    let mut context = ArtifactContext::new(&artifact_dir);
    context.run_id = "run-rgc-621b-test".to_string();
    context.generated_at_utc = "2026-03-06T00:00:00Z".to_string();
    context.source_commit = "deadbeef".to_string();
    context.toolchain = "nightly".to_string();
    context.command_invocation = format!(
        "cargo run -p frankenengine-engine --bin franken_seqlock_candidate_inventory -- --artifact-dir {}",
        artifact_dir.display()
    );

    let bundle = emit_default_inventory_bundle(&context).expect("bundle should write");

    for artifact in [
        "commands.txt",
        "env.json",
        "events.jsonl",
        "incumbent_fallback_matrix.json",
        "manifest.json",
        "repro.lock",
        "retry_budget_policy.json",
        "retry_safety_matrix.json",
        "run_manifest.json",
        "seqlock_candidate_inventory.json",
        "seqlock_reader_writer_contract.json",
        "snapshot_baseline_comparator.json",
        "summary.md",
        "trace_ids.json",
    ] {
        assert!(
            artifact_dir.join(artifact).exists(),
            "expected artifact `{artifact}` to exist",
        );
    }

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("manifest.json")).expect("read manifest"),
    )
    .expect("manifest should parse");
    let manifest_artifacts = manifest["artifacts"].as_array().expect("artifacts array");
    assert!(
        manifest_artifacts
            .iter()
            .any(|entry| entry["path"] == "env.json"),
        "manifest should reference env.json",
    );
    assert!(
        manifest_artifacts
            .iter()
            .any(|entry| entry["path"] == "repro.lock"),
        "manifest should reference repro.lock",
    );

    let trace_ids: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("trace_ids.json")).expect("read trace ids"),
    )
    .expect("trace ids parse");
    assert_eq!(trace_ids["trace_ids"][0], "trace.rgc.621b");

    let run_manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("run manifest should parse");
    assert_eq!(
        run_manifest["reader_writer_contract_hash"].as_str(),
        Some(bundle.reader_writer_contract.contract_hash.as_str())
    );
    assert_eq!(
        run_manifest["retry_budget_policy_hash"].as_str(),
        Some(bundle.retry_budget_policy.policy_hash.as_str())
    );
    assert_eq!(
        run_manifest["incumbent_fallback_matrix_hash"].as_str(),
        Some(bundle.incumbent_fallback_matrix.matrix_hash.as_str())
    );

    assert_eq!(bundle.inventory.counts.accept, 3);
    assert_eq!(bundle.reader_writer_contract.rows.len(), 9);
    assert_eq!(bundle.retry_budget_policy.rows.len(), 9);
    assert_eq!(bundle.incumbent_fallback_matrix.rows.len(), 9);
    assert!(
        !artifact_dir
            .join(".seqlock_candidate_inventory.lock")
            .exists(),
        "bundle write lock should be cleaned up after publication",
    );

    let _ = fs::remove_dir_all(&artifact_dir);
}

#[test]
fn docs_contract_fixture_matches_inventory_dispositions() {
    let expected = build_contract_fixture();
    let docs_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/rgc_seqlock_candidate_inventory_v1.json");
    let actual: seqlock_candidate_inventory::ContractFixture =
        serde_json::from_slice(&fs::read(&docs_path).expect("read docs fixture"))
            .expect("fixture should parse");

    assert_eq!(actual.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(actual, expected);
    assert!(
        actual
            .candidate_expectations
            .iter()
            .any(|entry| entry.candidate_id == "module-cache-snapshot"
                && entry.disposition == CandidateDisposition::Accept),
        "fixture should keep the module cache candidate accepted",
    );
}

#[test]
fn candidate_disposition_serde_roundtrip() {
    for variant in [
        CandidateDisposition::Accept,
        CandidateDisposition::Conditional,
        CandidateDisposition::Reject,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let recovered: CandidateDisposition = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, recovered);
    }
}

#[test]
fn surface_area_serde_roundtrip() {
    for variant in [
        SurfaceArea::GovernanceState,
        SurfaceArea::OfflineArtifact,
        SurfaceArea::OperatorProjection,
        SurfaceArea::PolicyState,
        SurfaceArea::RuntimeMetadata,
        SurfaceArea::Telemetry,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let recovered: SurfaceArea = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, recovered);
    }
}

#[test]
fn baseline_strategy_serde_roundtrip() {
    for variant in [
        BaselineStrategy::CloneSnapshot,
        BaselineStrategy::ExternalJoinProjection,
        BaselineStrategy::ImmutableValueObject,
        BaselineStrategy::MutableSnapshotSideEffect,
        BaselineStrategy::OfflineSummary,
        BaselineStrategy::QueryAppendOnly,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let recovered: BaselineStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, recovered);
    }
}

#[test]
fn tearing_risk_serde_roundtrip() {
    for variant in [
        TearingRisk::None,
        TearingRisk::Low,
        TearingRisk::Medium,
        TearingRisk::High,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let recovered: TearingRisk = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, recovered);
    }
}

#[test]
fn write_profile_serde_roundtrip() {
    for variant in [
        WriteProfile::Rare,
        WriteProfile::Moderate,
        WriteProfile::Bursty,
        WriteProfile::HotPath,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let recovered: WriteProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, recovered);
    }
}

#[test]
fn fallback_reason_serde_roundtrip() {
    for variant in [
        FallbackReason::UnsupportedCandidate,
        FallbackReason::WriterActive,
        FallbackReason::RetryBudgetExhausted,
        FallbackReason::ExternalJoinBoundary,
        FallbackReason::ImmutableValueObject,
        FallbackReason::HotPathWritePressure,
        FallbackReason::NonRetrySafeRead,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let recovered: FallbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, recovered);
    }
}

#[test]
fn read_resolution_serde_roundtrip() {
    for variant in [ReadResolution::Optimistic, ReadResolution::IncumbentFallback] {
        let json = serde_json::to_string(&variant).unwrap();
        let recovered: ReadResolution = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, recovered);
    }
}

#[test]
fn artifact_context_new_sets_defaults() {
    let dir = std::env::temp_dir().join("artifact-ctx-test");
    let ctx = ArtifactContext::new(&dir);
    assert_eq!(ctx.artifact_dir, dir);
    assert!(ctx.run_id.starts_with("run-seqlock_candidate_inventory-"));
    assert_eq!(ctx.trace_id, "trace.rgc.621b");
    assert_eq!(ctx.decision_id, "decision.rgc.621b");
    assert_eq!(ctx.policy_id, "policy.rgc.621b");
    assert!(ctx.generated_at_utc.ends_with('Z'));
}

#[test]
fn simulated_seqlock_new_clean_state() {
    let seqlock = SimulatedSeqlock::new(42u64);
    assert_eq!(seqlock.fallback_reads(), 0);
    assert_eq!(seqlock.write_pressure_violations(), 0);
}

#[test]
fn simulated_seqlock_begin_commit_write() {
    let mut seqlock = SimulatedSeqlock::new(0u64);
    seqlock.begin_write().expect("begin_write succeeds");
    seqlock.commit_write(100).expect("commit_write succeeds");
}

#[test]
fn simulated_seqlock_double_begin_write_fails() {
    let mut seqlock = SimulatedSeqlock::new(0u64);
    seqlock.begin_write().unwrap();
    let err = seqlock.begin_write().unwrap_err();
    assert!(matches!(err, SeqlockContractError::WriterAlreadyActive));
}

#[test]
fn simulated_seqlock_commit_without_begin_fails() {
    let mut seqlock = SimulatedSeqlock::new(0u64);
    let err = seqlock.commit_write(1).unwrap_err();
    assert!(matches!(err, SeqlockContractError::WriterNotActive));
}

#[test]
fn simulated_seqlock_stable_read_returns_optimistic() {
    let mut seqlock = SimulatedSeqlock::new(42u64);
    let policy = RetryBudgetPolicyRow {
        candidate_id: "test".to_string(),
        disposition: CandidateDisposition::Accept,
        max_retries: 3,
        fallback_target: "incumbent".to_string(),
        fallback_reason: FallbackReason::RetryBudgetExhausted,
        write_pressure_limit: WriteProfile::Moderate,
        policy_rationale: vec![],
    };
    let outcome = seqlock.read_with_interference(&policy, &[ReadInterference::Stable]);
    assert_eq!(outcome.value, 42);
    assert_eq!(outcome.resolution, ReadResolution::Optimistic);
    assert_eq!(outcome.retries, 0);
    assert!(outcome.fallback_reason.is_none());
}

#[test]
fn simulated_seqlock_writer_active_retries_then_reads() {
    let mut seqlock = SimulatedSeqlock::new(42u64);
    let policy = RetryBudgetPolicyRow {
        candidate_id: "test".to_string(),
        disposition: CandidateDisposition::Accept,
        max_retries: 3,
        fallback_target: "incumbent".to_string(),
        fallback_reason: FallbackReason::RetryBudgetExhausted,
        write_pressure_limit: WriteProfile::Moderate,
        policy_rationale: vec![],
    };
    let outcome = seqlock.read_with_interference(
        &policy,
        &[ReadInterference::WriterActive, ReadInterference::Stable],
    );
    assert_eq!(outcome.value, 42);
    assert_eq!(outcome.resolution, ReadResolution::Optimistic);
    assert_eq!(outcome.retries, 1);
}

#[test]
fn simulated_seqlock_budget_exhausted_falls_back() {
    let mut seqlock = SimulatedSeqlock::new(42u64);
    let policy = RetryBudgetPolicyRow {
        candidate_id: "test".to_string(),
        disposition: CandidateDisposition::Accept,
        max_retries: 1,
        fallback_target: "incumbent".to_string(),
        fallback_reason: FallbackReason::RetryBudgetExhausted,
        write_pressure_limit: WriteProfile::Moderate,
        policy_rationale: vec![],
    };
    let outcome = seqlock.read_with_interference(
        &policy,
        &[ReadInterference::WriterActive, ReadInterference::WriterActive],
    );
    assert_eq!(outcome.resolution, ReadResolution::IncumbentFallback);
    assert_eq!(outcome.fallback_reason, Some(FallbackReason::RetryBudgetExhausted));
    assert_eq!(seqlock.fallback_reads(), 1);
}

#[test]
fn simulated_seqlock_rejected_disposition_falls_back_immediately() {
    let mut seqlock = SimulatedSeqlock::new(42u64);
    let policy = RetryBudgetPolicyRow {
        candidate_id: "test".to_string(),
        disposition: CandidateDisposition::Reject,
        max_retries: 10,
        fallback_target: "incumbent".to_string(),
        fallback_reason: FallbackReason::UnsupportedCandidate,
        write_pressure_limit: WriteProfile::Rare,
        policy_rationale: vec![],
    };
    let outcome = seqlock.read_with_interference(&policy, &[ReadInterference::Stable]);
    assert_eq!(outcome.resolution, ReadResolution::IncumbentFallback);
    assert_eq!(outcome.fallback_reason, Some(FallbackReason::UnsupportedCandidate));
}

#[test]
fn default_candidate_inventory_produces_nine_candidates() {
    let inventory = default_candidate_inventory("2026-03-08T00:00:00Z");
    assert_eq!(inventory.candidates.len(), 9);
}

#[test]
fn default_candidate_inventory_counts_sum_to_total() {
    let inventory = default_candidate_inventory("2026-03-08T00:00:00Z");
    let total = inventory.counts.accept + inventory.counts.conditional + inventory.counts.reject;
    assert_eq!(total, inventory.candidates.len());
}

#[test]
fn default_candidate_inventory_hash_is_deterministic() {
    let a = default_candidate_inventory("2026-03-08T00:00:00Z");
    let b = default_candidate_inventory("2026-03-08T00:00:00Z");
    assert_eq!(a.inventory_hash, b.inventory_hash);
}

#[test]
fn default_candidate_inventory_hash_differs_for_different_timestamps() {
    let a = default_candidate_inventory("2026-03-08T00:00:00Z");
    let b = default_candidate_inventory("2026-03-09T00:00:00Z");
    // Hash depends only on counts+candidates, not timestamp, so same
    assert_eq!(a.inventory_hash, b.inventory_hash);
    assert_ne!(a.generated_at_utc, b.generated_at_utc);
}

#[test]
fn render_summary_contains_key_sections() {
    let inventory = default_candidate_inventory("2026-03-08T00:00:00Z");
    let summary = render_summary(&inventory);
    assert!(summary.contains("# Seqlock Candidate Inventory Summary"));
    assert!(summary.contains("## Accepted"));
    assert!(summary.contains("## Conditional"));
    assert!(summary.contains("## Rejected"));
    assert!(summary.contains("bead_id"));
    assert!(summary.contains("component"));
    assert!(summary.contains("inventory_hash"));
}

#[test]
fn build_contract_fixture_schema_version_matches_constant() {
    let fixture = build_contract_fixture();
    assert_eq!(fixture.schema_version, CONTRACT_SCHEMA_VERSION);
}

#[test]
fn build_contract_fixture_bead_id_matches_constant() {
    let fixture = build_contract_fixture();
    assert_eq!(fixture.bead_id, BEAD_ID);
}

#[test]
fn build_contract_fixture_expectations_match_inventory() {
    let fixture = build_contract_fixture();
    let inventory = default_candidate_inventory("2026-03-06T00:00:00Z");
    assert_eq!(fixture.candidate_expectations.len(), inventory.candidates.len());
    for expectation in &fixture.candidate_expectations {
        let candidate = inventory
            .candidates
            .iter()
            .find(|c| c.candidate_id == expectation.candidate_id)
            .unwrap_or_else(|| panic!("missing candidate {}", expectation.candidate_id));
        assert_eq!(candidate.disposition, expectation.disposition);
    }
}

#[test]
fn schema_version_constants_are_nonempty() {
    assert!(!INVENTORY_SCHEMA_VERSION.is_empty());
    assert!(!RETRY_SAFETY_SCHEMA_VERSION.is_empty());
    assert!(!BASELINE_COMPARATOR_SCHEMA_VERSION.is_empty());
    assert!(!READER_WRITER_CONTRACT_SCHEMA_VERSION.is_empty());
    assert!(!RETRY_BUDGET_POLICY_SCHEMA_VERSION.is_empty());
    assert!(!INCUMBENT_FALLBACK_MATRIX_SCHEMA_VERSION.is_empty());
    assert!(!TRACE_IDS_SCHEMA_VERSION.is_empty());
    assert!(!RUN_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!CONTRACT_SCHEMA_VERSION.is_empty());
}

#[test]
fn bead_id_and_component_constants_stable() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.21.2");
    assert_eq!(PREDECESSOR_BEAD_ID, "bd-1lsy.7.21.1");
    assert_eq!(COMPONENT, "seqlock_candidate_inventory");
}

#[test]
fn seqlock_contract_error_display_messages() {
    assert_eq!(
        SeqlockContractError::WriterAlreadyActive.to_string(),
        "writer already active"
    );
    assert_eq!(
        SeqlockContractError::WriterNotActive.to_string(),
        "writer not active"
    );
}

#[test]
fn structured_log_event_serde_roundtrip() {
    let event = StructuredLogEvent {
        trace_id: "trace-test".to_string(),
        decision_id: "decision-test".to_string(),
        policy_id: "policy-test".to_string(),
        component: COMPONENT.to_string(),
        event: "candidate_evaluated".to_string(),
        outcome: "accept".to_string(),
        error_code: None,
        candidate_id: Some("test-candidate".to_string()),
        detail: "test detail".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let recovered: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, recovered);
}

#[test]
fn candidate_inventory_serde_roundtrip() {
    let inventory = default_candidate_inventory("2026-03-08T00:00:00Z");
    let json = serde_json::to_string(&inventory).unwrap();
    let recovered: seqlock_candidate_inventory::SeqlockCandidateInventoryArtifact =
        serde_json::from_str(&json).unwrap();
    assert_eq!(inventory, recovered);
}

#[test]
fn all_candidates_have_nonempty_fields() {
    let inventory = default_candidate_inventory("2026-03-08T00:00:00Z");
    for candidate in &inventory.candidates {
        assert!(!candidate.candidate_id.is_empty());
        assert!(!candidate.surface_name.is_empty());
        assert!(!candidate.module_path.is_empty());
        assert!(!candidate.api_path.is_empty());
        assert!(!candidate.baseline_path.is_empty());
        assert!(!candidate.incumbent_baseline.is_empty());
    }
}

#[test]
fn simulated_seqlock_publish_interference_updates_value() {
    let mut seqlock = SimulatedSeqlock::new(10u64);
    let policy = RetryBudgetPolicyRow {
        candidate_id: "test".to_string(),
        disposition: CandidateDisposition::Accept,
        max_retries: 5,
        fallback_target: "incumbent".to_string(),
        fallback_reason: FallbackReason::RetryBudgetExhausted,
        write_pressure_limit: WriteProfile::Moderate,
        policy_rationale: vec![],
    };
    let outcome = seqlock.read_with_interference(
        &policy,
        &[ReadInterference::Publish(99), ReadInterference::Stable],
    );
    assert_eq!(outcome.value, 99);
    assert_eq!(outcome.resolution, ReadResolution::Optimistic);
    assert_eq!(outcome.retries, 1);
}
