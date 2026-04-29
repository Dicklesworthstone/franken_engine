#![forbid(unsafe_code)]

//! Contract tests for external crate API surfaces.
//!
//! These tests verify that FrankenEngine's approved control-plane import
//! boundary still maps to the concrete upstream `/dp/asupersync` crates when the
//! integration feature is enabled, and to functional local fallbacks otherwise.

#[cfg(feature = "asupersync-integration")]
mod asupersync_contracts {
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
            "dependency_contract_harness"
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
    fn franken_kernel_contract_uses_real_upstream_types() {
        let trace_id: franken_kernel::TraceId =
            control_plane::TraceId::from_parts(1_700_000_000_000, 7);
        let decision_id: franken_kernel::DecisionId =
            control_plane::DecisionId::from_parts(1_700_000_000_000, 9);
        let policy_id: franken_kernel::PolicyId =
            control_plane::PolicyId::new("dependency.contract", 1);
        let schema_version: franken_kernel::SchemaVersion =
            control_plane::SchemaVersion::new(1, 2, 3);
        let budget: franken_kernel::Budget = control_plane::Budget::new(500);
        let caps = control_plane::NoCaps;
        require_kernel_capability_set(&caps);

        let mut cx: franken_kernel::Cx<'_, franken_kernel::NoCaps> =
            control_plane::Cx::new(trace_id, budget, caps);
        assert_eq!(trace_id.timestamp_ms(), 1_700_000_000_000);
        assert_eq!(decision_id.timestamp_ms(), 1_700_000_000_000);
        assert_eq!(policy_id.name(), "dependency.contract");
        assert_eq!(policy_id.version(), 1);
        assert!(schema_version.is_compatible(&franken_kernel::SchemaVersion::new(1, 9, 0)));
        assert_eq!(cx.trace_id(), trace_id);
        assert_eq!(cx.budget().remaining_ms(), 500);
        assert!(cx.consume_budget(125));
        assert_eq!(cx.budget().remaining_ms(), 375);
        assert!(!cx.consume_budget(500));
        assert_eq!(cx.budget().remaining_ms(), 375);
    }

    #[test]
    fn franken_decision_contract_evaluates_real_upstream_surface() {
        let contract = ContractHarness::new();
        let _: &dyn franken_decision::DecisionContract = &contract;

        let posterior: franken_decision::Posterior =
            control_plane::Posterior::new(vec![0.75, 0.25]).expect("normalized posterior");
        let eval_context: franken_decision::EvalContext = control_plane::EvalContext {
            calibration_score: 0.95,
            e_process: 0.10,
            ci_width: 0.05,
            decision_id: control_plane::DecisionId::from_parts(1_700_000_000_100, 11),
            trace_id: control_plane::TraceId::from_parts(1_700_000_000_100, 13),
            ts_unix_ms: 1_700_000_000_100,
        };

        let outcome: franken_decision::DecisionOutcome =
            control_plane::evaluate_contract(&contract, &posterior, &eval_context);

        assert_eq!(outcome.action_name, "allow");
        assert!(!outcome.fallback_active);
        assert_eq!(
            outcome.audit_entry.contract_name,
            "dependency_contract_harness"
        );
        assert_eq!(outcome.audit_entry.decision_id, eval_context.decision_id);
        assert_eq!(outcome.audit_entry.trace_id, eval_context.trace_id);
    }

    #[test]
    fn franken_evidence_contract_builds_valid_deterministic_ledger() {
        let builder: franken_evidence::EvidenceLedgerBuilder =
            control_plane::EvidenceLedgerBuilder::new();
        let entry: franken_evidence::EvidenceLedger = builder
            .ts_unix_ms(1_700_000_000_200)
            .component("dependency_contracts")
            .action("allow")
            .posterior(vec![0.75, 0.25])
            .expected_loss("allow", 0.45)
            .expected_loss("deny", 0.50)
            .chosen_expected_loss(0.45)
            .calibration_score(0.95)
            .fallback_active(false)
            .top_feature("calibration", 0.70)
            .build()
            .expect("valid evidence ledger");

        assert!(entry.is_valid(), "evidence ledger validation must succeed");
        assert_eq!(entry.component, "dependency_contracts");
        assert_eq!(entry.action, "allow");
        assert_eq!(entry.expected_loss_by_action.len(), 2);
        assert!((entry.expected_loss_by_action["allow"] - 0.45).abs() < f64::EPSILON);
        assert!((entry.expected_loss_by_action["deny"] - 0.50).abs() < f64::EPSILON);
        assert!(!entry.fallback_active);

        let serialized_once = serde_json::to_string(&entry).expect("serialize evidence ledger");
        let serialized_twice =
            serde_json::to_string(&entry).expect("serialize evidence ledger again");
        assert_eq!(serialized_once, serialized_twice);
        let serialized_value: serde_json::Value =
            serde_json::from_str(&serialized_once).expect("serialized ledger is valid JSON");
        assert_eq!(
            serialized_value.get("c").and_then(|value| value.as_str()),
            Some("dependency_contracts")
        );
        let allow_position = serialized_once
            .find("\"allow\"")
            .expect("serialized evidence ledger contains allow action");
        let deny_position = serialized_once
            .find("\"deny\"")
            .expect("serialized evidence ledger contains deny action");
        assert!(
            allow_position < deny_position,
            "expected-loss map serialization should remain key-ordered"
        );
    }
}

#[cfg(not(feature = "asupersync-integration"))]
mod standalone_contracts {
    use frankenengine_engine::control_plane;

    #[test]
    fn standalone_kernel_fallback_contract_is_functional() {
        let trace_id = control_plane::TraceId::from_parts(1_700_000_000_000, 7);
        let budget = control_plane::Budget::new(100);
        let mut cx = control_plane::Cx::new(trace_id, budget, control_plane::NoCaps);

        assert_eq!(cx.trace_id(), trace_id);
        assert_eq!(cx.budget().remaining_ms(), 100);
        assert!(cx.consume_budget(40));
        assert_eq!(cx.budget().remaining_ms(), 60);
        assert!(!cx.consume_budget(80));
        assert_eq!(cx.budget().remaining_ms(), 60);
    }

    #[test]
    fn standalone_evidence_fallback_contract_validates_and_serializes() {
        let entry = control_plane::EvidenceLedgerBuilder::new()
            .ts_unix_ms(1_700_000_000_200)
            .component("standalone_dependency_contracts")
            .action("deny")
            .posterior(vec![0.25, 0.75])
            .expected_loss("allow", 0.80)
            .expected_loss("deny", 0.40)
            .chosen_expected_loss(0.40)
            .calibration_score(0.90)
            .fallback_active(true)
            .build()
            .expect("valid standalone evidence ledger");

        assert!(entry.is_valid(), "standalone evidence ledger must validate");
        assert_eq!(entry.component, "standalone_dependency_contracts");
        assert_eq!(entry.action, "deny");

        let serialized_once = serde_json::to_string(&entry).expect("serialize standalone ledger");
        let serialized_twice =
            serde_json::to_string(&entry).expect("serialize standalone ledger again");
        assert_eq!(serialized_once, serialized_twice);
        let serialized_value: serde_json::Value =
            serde_json::from_str(&serialized_once).expect("serialized ledger is valid JSON");
        assert_eq!(
            serialized_value.get("fb").and_then(|value| value.as_bool()),
            Some(true)
        );
    }
}
