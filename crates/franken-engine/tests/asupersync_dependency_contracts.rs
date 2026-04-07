#![cfg(feature = "asupersync-integration")]
#![forbid(unsafe_code)]

use franken_decision;
use franken_evidence;
use franken_kernel;
use frankenengine_engine::control_plane;

#[derive(Clone)]
struct ContractHarness {
    loss_matrix: control_plane::LossMatrix,
    fallback_policy: control_plane::FallbackPolicy,
}

impl ContractHarness {
    fn new() -> Self {
        Self {
            loss_matrix: control_plane::LossMatrix::new(
                vec!["benign".to_string(), "risky".to_string()],
                vec!["allow".to_string(), "deny".to_string()],
                vec![
                    0.10, 0.60, // benign
                    0.80, 0.40, // risky
                ],
            )
            .expect("valid loss matrix"),
            fallback_policy: control_plane::FallbackPolicy::default(),
        }
    }
}

impl control_plane::DecisionContract for ContractHarness {
    fn name(&self) -> &str {
        "control_plane_contract_harness"
    }

    fn state_space(&self) -> &[String] {
        self.loss_matrix.state_names()
    }

    fn action_set(&self) -> &[String] {
        self.loss_matrix.action_names()
    }

    fn loss_matrix(&self) -> &control_plane::LossMatrix {
        &self.loss_matrix
    }

    fn update_posterior(&self, posterior: &mut control_plane::Posterior, state_index: usize) {
        match state_index {
            0 => posterior.bayesian_update(&[0.90, 0.10]),
            1 => posterior.bayesian_update(&[0.10, 0.90]),
            _ => posterior.bayesian_update(&[0.50, 0.50]),
        }
    }

    fn choose_action(&self, posterior: &control_plane::Posterior) -> usize {
        self.loss_matrix.bayes_action(posterior)
    }

    fn fallback_action(&self) -> usize {
        1
    }

    fn fallback_policy(&self) -> &control_plane::FallbackPolicy {
        &self.fallback_policy
    }
}

fn require_kernel_capability_set<C: franken_kernel::CapabilitySet>(_: &C) {}

#[test]
fn franken_kernel_reexports_preserve_type_identity() {
    let trace_id: franken_kernel::TraceId =
        control_plane::TraceId::from_parts(1_700_000_000_000, 7);
    let decision_id: franken_kernel::DecisionId =
        control_plane::DecisionId::from_parts(1_700_000_000_000, 9);
    let policy_id: franken_kernel::PolicyId =
        control_plane::PolicyId::new("control_plane.contract", 1);
    let schema_version: franken_kernel::SchemaVersion = control_plane::SchemaVersion::new(1, 2, 3);
    let budget: franken_kernel::Budget = control_plane::Budget::new(500);
    let caps = control_plane::NoCaps;
    require_kernel_capability_set(&caps);

    let cx: franken_kernel::Cx<'_, franken_kernel::NoCaps> =
        control_plane::Cx::new(trace_id, budget, caps);

    assert_eq!(trace_id.timestamp_ms(), 1_700_000_000_000);
    assert_eq!(decision_id.timestamp_ms(), 1_700_000_000_000);
    assert_eq!(policy_id.name(), "control_plane.contract");
    assert_eq!(policy_id.version(), 1);
    assert!(schema_version.is_compatible(&franken_kernel::SchemaVersion::new(1, 9, 0)));
    assert_eq!(cx.trace_id(), trace_id);
    assert_eq!(cx.budget().remaining_ms(), 500);
    assert_eq!(cx.depth(), 0);
}

#[test]
fn franken_decision_reexports_and_evaluate_signature_match_upstream() {
    let contract = ContractHarness::new();
    let _: &dyn franken_decision::DecisionContract = &contract;

    let loss_matrix: franken_decision::LossMatrix = control_plane::LossMatrix::new(
        vec!["benign".to_string(), "risky".to_string()],
        vec!["allow".to_string(), "deny".to_string()],
        vec![
            0.10, 0.60, // benign
            0.80, 0.40, // risky
        ],
    )
    .expect("valid decision loss matrix");
    let posterior: franken_decision::Posterior = control_plane::Posterior::uniform(2);
    let _fallback_policy: franken_decision::FallbackPolicy =
        control_plane::FallbackPolicy::default();

    let eval_context: franken_decision::EvalContext = control_plane::EvalContext {
        calibration_score: 0.95,
        e_process: 0.10,
        ci_width: 0.05,
        decision_id: control_plane::DecisionId::from_parts(1_700_000_000_100, 11),
        trace_id: control_plane::TraceId::from_parts(1_700_000_000_100, 13),
        ts_unix_ms: 1_700_000_000_100,
    };

    let evaluator: fn(
        &ContractHarness,
        &franken_decision::Posterior,
        &franken_decision::EvalContext,
    ) -> franken_decision::DecisionOutcome = control_plane::evaluate_contract::<ContractHarness>;

    let outcome = evaluator(&contract, &posterior, &eval_context);

    assert_eq!(loss_matrix.n_states(), 2);
    assert_eq!(loss_matrix.n_actions(), 2);
    assert_eq!(outcome.action_name, "allow");
    assert!(!outcome.fallback_active);
    assert_eq!(
        outcome.audit_entry.contract_name,
        "control_plane_contract_harness"
    );
}

#[test]
fn franken_evidence_reexports_preserve_builder_and_entry_types() {
    let builder: franken_evidence::EvidenceLedgerBuilder =
        control_plane::EvidenceLedgerBuilder::new();
    let entry: franken_evidence::EvidenceLedger = builder
        .ts_unix_ms(1_700_000_000_200)
        .component("control_plane_contracts")
        .action("allow")
        .posterior(vec![0.75, 0.25])
        .expected_loss("allow", 0.45)
        .expected_loss("deny", 0.50)
        .chosen_expected_loss(0.45)
        .calibration_score(0.95)
        .fallback_active(false)
        .build()
        .expect("valid evidence ledger");

    assert_eq!(entry.component, "control_plane_contracts");
    assert_eq!(entry.action, "allow");
    assert_eq!(entry.expected_loss_by_action["allow"], 0.45);
    assert_eq!(entry.expected_loss_by_action["deny"], 0.50);
    assert!(!entry.fallback_active);
}
