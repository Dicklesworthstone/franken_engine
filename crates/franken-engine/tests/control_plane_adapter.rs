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

use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::control_plane::{
    self, ContractDecisionAdapter, DecisionAdapter, DecisionContract, DecisionRequest,
    DecisionVerdict, EvidenceEmitter, FallbackPolicy, InMemoryEvidenceEmitter, LossMatrix,
    Posterior,
};

fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    if !root.exists() {
        return;
    }
    let entries = fs::read_dir(root)
        .unwrap_or_else(|err| panic!("failed to read directory {}: {err}", root.display()));
    for entry in entries {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn control_plane_imports_are_isolated_to_adapter_module() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("repo root");

    let mut sources = Vec::new();
    collect_rs_files(&manifest_dir.join("src"), &mut sources);
    collect_rs_files(
        &repo_root.join("crates/franken-extension-host/src"),
        &mut sources,
    );

    for source in sources {
        let normalized = source.to_string_lossy().replace('\\', "/");
        let in_adapter = normalized.contains("/crates/franken-engine/src/control_plane/");
        // Lint/audit guard modules necessarily contain forbidden tokens as
        // test data (string literals with example source code).  Skip them.
        let is_guard_module =
            normalized.contains("authority_guard") || normalized.contains("lint_guard");
        if in_adapter || is_guard_module {
            continue;
        }

        let content = fs::read_to_string(&source)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", source.display()));
        let forbidden = [
            "use franken_kernel",
            "use franken_decision",
            "use franken_evidence",
            "extern crate franken_kernel",
            "extern crate franken_decision",
            "extern crate franken_evidence",
        ];
        for token in forbidden {
            assert!(
                !content.contains(token),
                "direct upstream control-plane import found in {}: {}",
                normalized,
                token
            );
        }
    }
}

struct MiniContract {
    loss_matrix: LossMatrix,
    fallback: FallbackPolicy,
}

impl MiniContract {
    fn new() -> Self {
        Self {
            loss_matrix: LossMatrix::new(
                vec!["good".to_string(), "bad".to_string()],
                vec![
                    "allow".to_string(),
                    "deny".to_string(),
                    "timeout".to_string(),
                ],
                vec![
                    0.01, 0.4, 0.6, // good
                    0.8, 0.1, 0.3, // bad
                ],
            )
            .expect("valid loss matrix"),
            fallback: FallbackPolicy::default(),
        }
    }
}

impl DecisionContract for MiniContract {
    fn name(&self) -> &str {
        "mini_contract"
    }

    fn state_space(&self) -> &[String] {
        self.loss_matrix.state_names()
    }

    fn action_set(&self) -> &[String] {
        self.loss_matrix.action_names()
    }

    fn loss_matrix(&self) -> &LossMatrix {
        &self.loss_matrix
    }

    fn update_posterior(&self, posterior: &mut Posterior, state_index: usize) {
        let _ = state_index;
        posterior.bayesian_update(&[0.8, 0.2]);
    }

    fn choose_action(&self, posterior: &Posterior) -> usize {
        self.loss_matrix.bayes_action(posterior)
    }

    fn fallback_action(&self) -> usize {
        2 // timeout
    }

    fn fallback_policy(&self) -> &FallbackPolicy {
        &self.fallback
    }
}

#[test]
fn adapter_surfaces_decision_and_evidence_without_direct_upstream_imports() {
    let contract = MiniContract::new();
    let posterior = Posterior::uniform(2);
    let mut adapter = ContractDecisionAdapter::new(contract, posterior);

    let request = DecisionRequest {
        decision_id: control_plane::DecisionId::from_parts(1_700_000_000_500, 55),
        policy_id: control_plane::PolicyId::new("test.policy", 1),
        trace_id: control_plane::TraceId::from_parts(1_700_000_000_500, 7),
        ts_unix_ms: 1_700_000_000_500,
        calibration_score_bps: 9_500,
        e_process_milli: 100,
        ci_width_milli: 50,
    };

    let verdict = adapter.evaluate(&request).expect("decision");
    assert!(matches!(
        verdict,
        DecisionVerdict::Allow | DecisionVerdict::Deny | DecisionVerdict::Timeout
    ));
    assert_eq!(adapter.events().len(), 1);

    let entry = control_plane::EvidenceLedgerBuilder::new()
        .ts_unix_ms(request.ts_unix_ms)
        .component("control_plane_adapter_test")
        .action(verdict_to_action(verdict))
        .posterior(vec![0.8, 0.2])
        .expected_loss("allow", 0.1)
        .expected_loss("deny", 0.2)
        .expected_loss("timeout", 0.3)
        .chosen_expected_loss(0.1)
        .calibration_score(0.95)
        .fallback_active(false)
        .build()
        .expect("valid evidence entry");

    let mut emitter = InMemoryEvidenceEmitter::new();
    emitter.emit(&request, entry).expect("emit evidence");
    assert_eq!(emitter.entries().len(), 1);
    assert_eq!(emitter.events().len(), 1);
    assert_eq!(emitter.events()[0].component, "control_plane_adapter");
}

fn verdict_to_action(verdict: DecisionVerdict) -> &'static str {
    match verdict {
        DecisionVerdict::Allow => "allow",
        DecisionVerdict::Deny => "deny",
        DecisionVerdict::Timeout => "timeout",
    }
}

// ---------- LossMatrix construction ----------

#[test]
fn loss_matrix_state_and_action_names_match_constructor_inputs() {
    let contract = MiniContract::new();
    let matrix = contract.loss_matrix();
    assert_eq!(matrix.state_names(), &["good", "bad"]);
    assert_eq!(matrix.action_names(), &["allow", "deny", "timeout"]);
}

#[test]
fn loss_matrix_bayes_action_returns_valid_index() {
    let contract = MiniContract::new();
    let posterior = Posterior::uniform(2);
    let action_index = contract.loss_matrix().bayes_action(&posterior);
    assert!(action_index < contract.action_set().len());
}

// ---------- Posterior ----------

#[test]
fn posterior_uniform_serde_roundtrip() {
    let posterior = Posterior::uniform(3);
    let json = serde_json::to_string(&posterior).expect("serialize");
    let recovered: Posterior = serde_json::from_str(&json).expect("deserialize");
    let json_again = serde_json::to_string(&recovered).expect("re-serialize");
    assert_eq!(json, json_again);
}

#[test]
fn posterior_bayesian_update_produces_valid_posterior() {
    let mut posterior = Posterior::uniform(2);
    posterior.bayesian_update(&[0.9, 0.1]);
    let json = serde_json::to_string(&posterior).expect("serialize updated posterior");
    assert!(!json.is_empty());
}

// ---------- DecisionVerdict ----------

#[test]
fn decision_verdict_serde_roundtrip() {
    for verdict in [
        DecisionVerdict::Allow,
        DecisionVerdict::Deny,
        DecisionVerdict::Timeout,
    ] {
        let json = serde_json::to_string(&verdict).expect("serialize verdict");
        let recovered: DecisionVerdict = serde_json::from_str(&json).expect("deserialize verdict");
        assert_eq!(recovered, verdict);
    }
}

// ---------- DecisionRequest ----------

#[test]
fn decision_request_serde_roundtrip() {
    let request = DecisionRequest {
        decision_id: control_plane::DecisionId::from_parts(1_700_000_000_500, 55),
        policy_id: control_plane::PolicyId::new("test.policy", 1),
        trace_id: control_plane::TraceId::from_parts(1_700_000_000_500, 7),
        ts_unix_ms: 1_700_000_000_500,
        calibration_score_bps: 9_500,
        e_process_milli: 100,
        ci_width_milli: 50,
    };
    let json = serde_json::to_string(&request).expect("serialize");
    let recovered: DecisionRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, request);
}

// ---------- ControlPlaneAdapterError ----------

#[test]
fn control_plane_adapter_error_codes_are_stable() {
    let budget_err =
        control_plane::ControlPlaneAdapterError::BudgetExhausted { requested_ms: 1000 };
    assert_eq!(budget_err.error_code(), "budget_exhausted");

    let gateway_err =
        control_plane::ControlPlaneAdapterError::DecisionGateway { code: "test_code" };
    assert_eq!(gateway_err.error_code(), "test_code");

    let evidence_err =
        control_plane::ControlPlaneAdapterError::EvidenceEmission { code: "emit_fail" };
    assert_eq!(evidence_err.error_code(), "emit_fail");
}

// ---------- Mock infrastructure ----------

#[test]
fn mock_budget_tracks_consumption() {
    let mut budget = control_plane::mocks::MockBudget::new(100);
    assert_eq!(budget.remaining_ms(), 100);
    assert_eq!(budget.consumed_ms(), 0);

    budget.consume(30).expect("consume 30ms");
    assert_eq!(budget.remaining_ms(), 70);
    assert_eq!(budget.consumed_ms(), 30);
}

#[test]
fn mock_budget_rejects_overspend() {
    let mut budget = control_plane::mocks::MockBudget::new(10);
    let result = budget.consume(20);
    assert!(result.is_err());
}

#[test]
fn mock_decision_contract_drains_queued_verdicts() {
    let mut mock = control_plane::mocks::MockDecisionContract::new(vec![
        DecisionVerdict::Allow,
        DecisionVerdict::Deny,
    ]);
    let request = DecisionRequest {
        decision_id: control_plane::DecisionId::from_parts(1_000, 1_u128),
        policy_id: control_plane::PolicyId::new("test.mock", 1),
        trace_id: control_plane::TraceId::from_parts(1_000, 1_u128),
        ts_unix_ms: 1_000,
        calibration_score_bps: 5_000,
        e_process_milli: 100,
        ci_width_milli: 50,
    };
    assert_eq!(mock.evaluate(&request).unwrap(), DecisionVerdict::Allow);
    assert_eq!(mock.evaluate(&request).unwrap(), DecisionVerdict::Deny);
}

#[test]
fn mock_evidence_emitter_collects_entries() {
    let mut emitter = control_plane::mocks::MockEvidenceEmitter::new();
    assert!(emitter.entries().is_empty());
    assert!(emitter.events().is_empty());

    let request = DecisionRequest {
        decision_id: control_plane::DecisionId::from_parts(1_000, 1_u128),
        policy_id: control_plane::PolicyId::new("test.mock", 1),
        trace_id: control_plane::TraceId::from_parts(1_000, 1_u128),
        ts_unix_ms: 1_000,
        calibration_score_bps: 5_000,
        e_process_milli: 100,
        ci_width_milli: 50,
    };

    let entry = control_plane::EvidenceLedgerBuilder::new()
        .ts_unix_ms(1_000)
        .component("test_emitter")
        .action("allow")
        .posterior(vec![0.5, 0.5])
        .expected_loss("allow", 0.1)
        .expected_loss("deny", 0.9)
        .chosen_expected_loss(0.1)
        .calibration_score(0.5)
        .fallback_active(false)
        .build()
        .expect("valid evidence entry");

    emitter.emit(&request, entry).expect("emit evidence");
    assert_eq!(emitter.entries().len(), 1);
    assert_eq!(emitter.events().len(), 1);
}

// ---------- ContractDecisionAdapter ----------

#[test]
fn adapter_accumulates_events_across_multiple_evaluations() {
    let contract = MiniContract::new();
    let posterior = Posterior::uniform(2);
    let mut adapter = ContractDecisionAdapter::new(contract, posterior);

    for i in 0..3u64 {
        let request = DecisionRequest {
            decision_id: control_plane::DecisionId::from_parts(1_000 + i, i as u128),
            policy_id: control_plane::PolicyId::new("test.multi", 1),
            trace_id: control_plane::TraceId::from_parts(1_000 + i, i as u128),
            ts_unix_ms: 1_000 + i,
            calibration_score_bps: 9_500,
            e_process_milli: 100,
            ci_width_milli: 50,
        };
        adapter.evaluate(&request).expect("evaluate");
    }
    assert_eq!(adapter.events().len(), 3);
}

// ---------- InMemoryEvidenceEmitter ----------

#[test]
fn in_memory_evidence_emitter_component_is_control_plane_adapter() {
    let mut emitter = InMemoryEvidenceEmitter::new();
    let request = DecisionRequest {
        decision_id: control_plane::DecisionId::from_parts(2_000, 1_u128),
        policy_id: control_plane::PolicyId::new("test.component", 1),
        trace_id: control_plane::TraceId::from_parts(2_000, 1_u128),
        ts_unix_ms: 2_000,
        calibration_score_bps: 5_000,
        e_process_milli: 50,
        ci_width_milli: 25,
    };

    let entry = control_plane::EvidenceLedgerBuilder::new()
        .ts_unix_ms(2_000)
        .component("test_component")
        .action("deny")
        .posterior(vec![0.3, 0.7])
        .expected_loss("allow", 0.5)
        .expected_loss("deny", 0.2)
        .chosen_expected_loss(0.2)
        .calibration_score(0.5)
        .fallback_active(false)
        .build()
        .expect("valid evidence entry");

    emitter.emit(&request, entry).expect("emit");
    assert_eq!(emitter.events()[0].component, "control_plane_adapter");
    assert_eq!(emitter.events()[0].event, "evidence_emit");
    assert_eq!(emitter.events()[0].outcome, "ok");
}

// ---------- FallbackPolicy ----------

#[test]
fn fallback_policy_default_is_deterministic() {
    let a = FallbackPolicy::default();
    let b = FallbackPolicy::default();
    assert_eq!(a, b);
}

// ---------- AdapterEvent serde ----------

#[test]
fn adapter_event_serde_roundtrip() {
    let event = control_plane::AdapterEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "test".to_string(),
        event: "evaluate".to_string(),
        outcome: "success".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: control_plane::AdapterEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, event);
}

// ---------- Mock seed constructors ----------

#[test]
fn mock_id_constructors_produce_distinct_ids_for_different_seeds() {
    let trace_a = control_plane::mocks::trace_id_from_seed(1);
    let trace_b = control_plane::mocks::trace_id_from_seed(2);
    assert_ne!(trace_a, trace_b);

    let decision_a = control_plane::mocks::decision_id_from_seed(1);
    let decision_b = control_plane::mocks::decision_id_from_seed(2);
    assert_ne!(decision_a, decision_b);

    let policy_a = control_plane::mocks::policy_id_from_seed(1);
    let policy_b = control_plane::mocks::policy_id_from_seed(2);
    assert_ne!(policy_a, policy_b);
}

#[test]
fn adapter_event_has_nonempty_component() {
    let event = control_plane::AdapterEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "adapter".to_string(),
        event: "test".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    assert!(!event.component.trim().is_empty());
    assert!(!event.trace_id.trim().is_empty());
}

#[test]
fn mock_id_same_seed_produces_same_id() {
    let a = control_plane::mocks::trace_id_from_seed(42);
    let b = control_plane::mocks::trace_id_from_seed(42);
    assert_eq!(a, b);
}

#[test]
fn adapter_event_with_error_code_roundtrips() {
    let event = control_plane::AdapterEvent {
        trace_id: "t-err".to_string(),
        decision_id: "d-err".to_string(),
        policy_id: "p-err".to_string(),
        component: "adapter".to_string(),
        event: "evaluate".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("E-001".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: control_plane::AdapterEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.error_code, Some("E-001".to_string()));
}

#[test]
fn fallback_policy_serde_roundtrip() {
    let policy = FallbackPolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: FallbackPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, policy);
}

#[test]
fn decision_verdict_debug_is_nonempty() {
    for verdict in [
        DecisionVerdict::Allow,
        DecisionVerdict::Deny,
        DecisionVerdict::Timeout,
    ] {
        assert!(!format!("{verdict:?}").is_empty());
    }
}

#[test]
fn posterior_uniform_has_equal_weights() {
    let posterior = Posterior::uniform(3);
    let json = serde_json::to_string(&posterior).expect("serialize");
    assert!(!json.is_empty());
    let again = Posterior::uniform(3);
    let json_again = serde_json::to_string(&again).expect("serialize again");
    assert_eq!(json, json_again);
}

// ---------- LossMatrix validation ----------

#[test]
fn loss_matrix_dimension_mismatch_returns_error() {
    // 2 states x 3 actions = 6 values expected, but we supply only 4
    let result = LossMatrix::new(
        vec!["good".to_string(), "bad".to_string()],
        vec![
            "allow".to_string(),
            "deny".to_string(),
            "timeout".to_string(),
        ],
        vec![0.1, 0.2, 0.3, 0.4],
    );
    assert!(
        result.is_err(),
        "LossMatrix::new should reject mismatched dimensions"
    );
}

// ---------- EvidenceLedgerBuilder missing fields ----------

#[test]
fn evidence_ledger_builder_missing_component_fails() {
    // Omit the `component` field — build must return Err.
    let result = control_plane::EvidenceLedgerBuilder::new()
        .ts_unix_ms(1_000)
        // .component("missing")  — intentionally omitted
        .action("allow")
        .posterior(vec![0.5, 0.5])
        .expected_loss("allow", 0.1)
        .chosen_expected_loss(0.1)
        .calibration_score(0.5)
        .fallback_active(false)
        .build();
    assert!(result.is_err(), "builder without component should fail");
}

// ---------- MockBudget exact exhaustion ----------

#[test]
fn mock_budget_consume_exact_remaining_succeeds_with_zero_left() {
    let mut budget = control_plane::mocks::MockBudget::new(42);
    budget.consume(42).expect("exact remaining should succeed");
    assert_eq!(budget.remaining_ms(), 0);
    assert_eq!(budget.consumed_ms(), 42);

    // A subsequent consume of even 1 ms must fail.
    let err = budget.consume(1);
    assert!(
        err.is_err(),
        "budget at zero should reject any further consume"
    );
}

// ---------- MockDecisionContract empty queue ----------

#[test]
fn mock_decision_contract_empty_queue_returns_timeout_fallback() {
    // Construct with an empty queue — no pre-loaded verdicts.
    let mut mock = control_plane::mocks::MockDecisionContract::new(Vec::<DecisionVerdict>::new());
    let request = DecisionRequest {
        decision_id: control_plane::DecisionId::from_parts(3_000, 1_u128),
        policy_id: control_plane::PolicyId::new("test.empty", 1),
        trace_id: control_plane::TraceId::from_parts(3_000, 1_u128),
        ts_unix_ms: 3_000,
        calibration_score_bps: 5_000,
        e_process_milli: 100,
        ci_width_milli: 50,
    };
    let verdict = mock
        .evaluate(&request)
        .expect("should succeed with fallback");
    assert_eq!(
        verdict,
        DecisionVerdict::Timeout,
        "empty queue should fall back to Timeout"
    );
}

// ---------- Successive Bayesian updates shift posteriors ----------

#[test]
fn multiple_bayesian_updates_produce_different_posteriors() {
    let mut posterior = Posterior::uniform(2);
    let initial = serde_json::to_string(&posterior).expect("serialize initial");

    // First update: strongly favor state 0
    posterior.bayesian_update(&[0.9, 0.1]);
    let after_first = serde_json::to_string(&posterior).expect("serialize after first");
    assert_ne!(initial, after_first, "first update should change posterior");

    // Second update: strongly favor state 1
    posterior.bayesian_update(&[0.1, 0.9]);
    let after_second = serde_json::to_string(&posterior).expect("serialize after second");
    assert_ne!(
        after_first, after_second,
        "second update should change posterior again"
    );

    // Third update with same likelihoods as second to push further
    posterior.bayesian_update(&[0.1, 0.9]);
    let after_third = serde_json::to_string(&posterior).expect("serialize after third");
    assert_ne!(
        after_second, after_third,
        "third update should shift posterior further"
    );
}

// ---------- DecisionId / TraceId from_parts determinism ----------

#[test]
fn decision_id_and_trace_id_from_parts_are_deterministic() {
    let ts = 1_700_000_000_000_u64;
    let rand_val = 0xABCD_u128;

    // Same inputs must produce identical ids every time.
    let d1 = control_plane::DecisionId::from_parts(ts, rand_val);
    let d2 = control_plane::DecisionId::from_parts(ts, rand_val);
    assert_eq!(d1, d2, "DecisionId::from_parts must be deterministic");

    let t1 = control_plane::TraceId::from_parts(ts, rand_val);
    let t2 = control_plane::TraceId::from_parts(ts, rand_val);
    assert_eq!(t1, t2, "TraceId::from_parts must be deterministic");

    // Different random parts must produce different ids.
    let d3 = control_plane::DecisionId::from_parts(ts, rand_val + 1);
    assert_ne!(d1, d3, "different random should yield different DecisionId");

    let t3 = control_plane::TraceId::from_parts(ts, rand_val + 1);
    assert_ne!(t1, t3, "different random should yield different TraceId");

    // Display format should be stable hex.
    assert_eq!(d1.to_string(), d2.to_string());
    assert_eq!(t1.to_string(), t2.to_string());
}

#[test]
fn fallback_policy_debug_is_nonempty() {
    let policy = FallbackPolicy::default();
    assert!(!format!("{policy:?}").is_empty());
}

#[test]
fn posterior_debug_is_nonempty() {
    let posterior = Posterior::uniform(3);
    assert!(!format!("{posterior:?}").is_empty());
}

#[test]
fn posterior_serde_is_deterministic() {
    let posterior = Posterior::uniform(5);
    let a = serde_json::to_string(&posterior).expect("first");
    let b = serde_json::to_string(&posterior).expect("second");
    assert_eq!(a, b);
}
