#![forbid(unsafe_code)]

pub mod control_plane {
    use std::collections::VecDeque;
    use std::thread;
    use std::time::Duration;

    use frankenengine_engine::control_plane::{
        AdapterEvent, Budget, ContextAdapter, ControlPlaneAdapterError, DecisionAdapter,
        DecisionId, DecisionRequest, DecisionVerdict, EvidenceEmitter, EvidenceLedger, PolicyId,
        SchemaVersion, TraceId,
    };

    const MOCK_TS_MS: u64 = 1_700_000_000_000;

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub enum MockFailureMode {
        #[default]
        Never,
        FailAlways {
            code: &'static str,
        },
        FailAfterN {
            remaining_successes: u32,
            code: &'static str,
        },
        LatencyInjection {
            millis: u64,
        },
        PanicOnCall,
    }

    fn apply_failure_mode(mode: &mut MockFailureMode) -> Result<(), &'static str> {
        match mode {
            MockFailureMode::Never => Ok(()),
            MockFailureMode::FailAlways { code } => Err(code),
            MockFailureMode::FailAfterN {
                remaining_successes,
                code,
            } => {
                if *remaining_successes == 0 {
                    Err(code)
                } else {
                    *remaining_successes -= 1;
                    Ok(())
                }
            }
            MockFailureMode::LatencyInjection { millis } => {
                thread::sleep(Duration::from_millis(*millis));
                Ok(())
            }
            MockFailureMode::PanicOnCall => panic!("mock configured to panic"),
        }
    }

    fn decision_outcome(verdict: DecisionVerdict) -> &'static str {
        match verdict {
            DecisionVerdict::Allow => "allow",
            DecisionVerdict::Deny => "deny",
            DecisionVerdict::Timeout => "timeout",
        }
    }

    fn new_event(
        request: &DecisionRequest,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
    ) -> AdapterEvent {
        AdapterEvent {
            trace_id: request.trace_id.to_string(),
            decision_id: request.decision_id.to_string(),
            policy_id: request.policy_id.to_string(),
            component: "control_plane_adapter".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(str::to_string),
        }
    }

    /// Deterministic test-only trace-id constructor.
    pub fn trace_id_from_seed(seed: u64) -> TraceId {
        TraceId::from_parts(MOCK_TS_MS + seed, u128::from(seed))
    }

    /// Deterministic test-only decision-id constructor.
    pub fn decision_id_from_seed(seed: u64) -> DecisionId {
        DecisionId::from_parts(MOCK_TS_MS + seed, u128::from(seed) << 1)
    }

    /// Deterministic test-only policy-id constructor.
    pub fn policy_id_from_seed(seed: u64) -> PolicyId {
        PolicyId::new(format!("mock.policy.{seed}"), 1)
    }

    /// Deterministic test-only schema-version constructor.
    pub fn schema_version_from_seed(seed: u64) -> SchemaVersion {
        SchemaVersion::new(1, (seed % 10) as u32, (seed % 1_000) as u32)
    }

    /// Mutable mock budget with deterministic consumption tracking.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MockBudget {
        remaining_ms: u64,
        consumed_ms: u64,
        panic_on_overspend: bool,
    }

    impl MockBudget {
        pub fn new(remaining_ms: u64) -> Self {
            Self {
                remaining_ms,
                consumed_ms: 0,
                panic_on_overspend: false,
            }
        }

        pub fn panic_on_overspend(mut self, enabled: bool) -> Self {
            self.panic_on_overspend = enabled;
            self
        }

        pub fn remaining_ms(&self) -> u64 {
            self.remaining_ms
        }

        pub fn consumed_ms(&self) -> u64 {
            self.consumed_ms
        }

        pub fn consume(&mut self, requested_ms: u64) -> Result<(), ControlPlaneAdapterError> {
            if requested_ms > self.remaining_ms {
                if self.panic_on_overspend {
                    panic!("mock budget overspend requested={requested_ms}");
                }
                return Err(ControlPlaneAdapterError::BudgetExhausted { requested_ms });
            }
            self.remaining_ms -= requested_ms;
            self.consumed_ms += requested_ms;
            Ok(())
        }

        pub fn as_budget(&self) -> Budget {
            Budget::new(self.remaining_ms)
        }
    }

    /// Mock context (`Cx`) that can panic on overspend if requested.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MockCx {
        trace_id: TraceId,
        budget: MockBudget,
    }

    impl MockCx {
        pub fn new(trace_id: TraceId, budget: MockBudget) -> Self {
            Self { trace_id, budget }
        }

        pub fn budget_state(&self) -> &MockBudget {
            &self.budget
        }
    }

    impl ContextAdapter for MockCx {
        fn trace_id(&self) -> TraceId {
            self.trace_id
        }

        fn budget(&self) -> Budget {
            self.budget.as_budget()
        }

        fn consume_budget(&mut self, requested_ms: u64) -> Result<(), ControlPlaneAdapterError> {
            self.budget.consume(requested_ms)
        }
    }

    /// Mock decision adapter with configurable allow/deny/timeout responses.
    #[derive(Debug, Clone)]
    pub struct MockDecisionContract {
        responses: VecDeque<DecisionVerdict>,
        failure_mode: MockFailureMode,
        events: Vec<AdapterEvent>,
    }

    impl MockDecisionContract {
        pub fn new(responses: impl IntoIterator<Item = DecisionVerdict>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                failure_mode: MockFailureMode::Never,
                events: Vec::new(),
            }
        }

        pub fn with_failure_mode(mut self, failure_mode: MockFailureMode) -> Self {
            self.failure_mode = failure_mode;
            self
        }
    }

    impl DecisionAdapter for MockDecisionContract {
        fn evaluate(
            &mut self,
            request: &DecisionRequest,
        ) -> Result<DecisionVerdict, ControlPlaneAdapterError> {
            if let Err(code) = apply_failure_mode(&mut self.failure_mode) {
                self.events.push(new_event(
                    request,
                    "mock_decision_eval",
                    "error",
                    Some(code),
                ));
                return Err(ControlPlaneAdapterError::DecisionGateway { code });
            }

            let verdict = self
                .responses
                .pop_front()
                .unwrap_or(DecisionVerdict::Timeout);
            self.events.push(new_event(
                request,
                "mock_decision_eval",
                decision_outcome(verdict),
                None,
            ));
            Ok(verdict)
        }

        fn events(&self) -> &[AdapterEvent] {
            &self.events
        }
    }

    /// Mock evidence emitter with deterministic in-memory sink and failure
    /// injection support.
    #[derive(Debug, Clone, Default)]
    pub struct MockEvidenceEmitter {
        entries: Vec<EvidenceLedger>,
        failure_mode: MockFailureMode,
        events: Vec<AdapterEvent>,
    }

    impl MockEvidenceEmitter {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn with_failure_mode(mut self, failure_mode: MockFailureMode) -> Self {
            self.failure_mode = failure_mode;
            self
        }

        pub fn entries(&self) -> &[EvidenceLedger] {
            &self.entries
        }
    }

    impl EvidenceEmitter for MockEvidenceEmitter {
        fn emit(
            &mut self,
            request: &DecisionRequest,
            entry: EvidenceLedger,
        ) -> Result<(), ControlPlaneAdapterError> {
            if let Err(code) = apply_failure_mode(&mut self.failure_mode) {
                self.events.push(new_event(
                    request,
                    "mock_evidence_emit",
                    "error",
                    Some(code),
                ));
                return Err(ControlPlaneAdapterError::EvidenceEmission { code });
            }

            self.entries.push(entry);
            self.events
                .push(new_event(request, "mock_evidence_emit", "ok", None));
            Ok(())
        }

        fn events(&self) -> &[AdapterEvent] {
            &self.events
        }
    }
}
