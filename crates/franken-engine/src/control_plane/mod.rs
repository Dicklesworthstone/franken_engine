//! Narrow control-plane adapter surface for `/dp/asupersync` primitives.
//!
//! This module is the only approved import boundary for control-plane crates:
//! - `franken-kernel` (`franken_kernel`)
//! - `franken-decision` (`franken_decision`)
//! - `franken-evidence` (`franken_evidence`)
//!
//! It intentionally exposes a constrained API for extension-host integration:
//! context/budget threading, decision contract evaluation, and evidence
//! emission. Callers should import these symbols from this module rather than
//! directly from upstream crates.

use serde::{Deserialize, Serialize};

pub use franken_decision::{
    DecisionContract, DecisionOutcome, EvalContext, FallbackPolicy, LossMatrix, Posterior,
};
pub use franken_evidence::{EvidenceLedger, EvidenceLedgerBuilder};
pub use franken_kernel::{
    Budget, CapabilitySet, Cx, DecisionId, NoCaps, PolicyId, SchemaVersion, TraceId,
};

const ADAPTER_COMPONENT: &str = "control_plane_adapter";

/// Runtime verdict expected by extension-host policy boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionVerdict {
    Allow,
    Deny,
    Timeout,
}

impl DecisionVerdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Timeout => "timeout",
        }
    }
}

/// Structured decision request routed through the adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRequest {
    pub decision_id: DecisionId,
    pub policy_id: PolicyId,
    pub trace_id: TraceId,
    pub ts_unix_ms: u64,
    pub calibration_score_bps: u16,
    pub e_process_milli: u32,
    pub ci_width_milli: u32,
}

impl DecisionRequest {
    #[allow(clippy::cast_precision_loss)]
    fn calibration_score(&self) -> f64 {
        f64::from(self.calibration_score_bps) / 10_000.0
    }

    #[allow(clippy::cast_precision_loss)]
    fn e_process(&self) -> f64 {
        f64::from(self.e_process_milli) / 1_000.0
    }

    #[allow(clippy::cast_precision_loss)]
    fn ci_width(&self) -> f64 {
        f64::from(self.ci_width_milli) / 1_000.0
    }
}

/// Structured event emitted by adapter operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Adapter-level errors exposed to extension-host callers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlPlaneAdapterError {
    #[error("budget exhausted while consuming {requested_ms}ms")]
    BudgetExhausted { requested_ms: u64 },
    #[error("decision gateway failure ({code})")]
    DecisionGateway { code: &'static str },
    #[error("evidence emission failure ({code})")]
    EvidenceEmission { code: &'static str },
}

impl ControlPlaneAdapterError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::BudgetExhausted { .. } => "budget_exhausted",
            Self::DecisionGateway { code } => code,
            Self::EvidenceEmission { code } => code,
        }
    }
}

/// Adapter boundary for threaded context and budget operations.
pub trait ContextAdapter {
    fn trace_id(&self) -> TraceId;
    fn budget(&self) -> Budget;
    fn consume_budget(&mut self, requested_ms: u64) -> Result<(), ControlPlaneAdapterError>;
}

/// Wrapper over canonical `franken_kernel::Cx` to keep imports centralized.
#[derive(Debug)]
pub struct KernelContext<'a, C: CapabilitySet = NoCaps> {
    cx: Cx<'a, C>,
}

impl<'a, C: CapabilitySet> KernelContext<'a, C> {
    pub fn new(cx: Cx<'a, C>) -> Self {
        Self { cx }
    }

    pub fn as_cx(&self) -> &Cx<'a, C> {
        &self.cx
    }

    pub fn into_inner(self) -> Cx<'a, C> {
        self.cx
    }
}

impl<C: CapabilitySet> ContextAdapter for KernelContext<'_, C> {
    fn trace_id(&self) -> TraceId {
        self.cx.trace_id()
    }

    fn budget(&self) -> Budget {
        self.cx.budget()
    }

    fn consume_budget(&mut self, requested_ms: u64) -> Result<(), ControlPlaneAdapterError> {
        if self.cx.consume_budget(requested_ms) {
            Ok(())
        } else {
            Err(ControlPlaneAdapterError::BudgetExhausted { requested_ms })
        }
    }
}

/// Adapter boundary for decision contract evaluation.
pub trait DecisionAdapter {
    fn evaluate(
        &mut self,
        request: &DecisionRequest,
    ) -> Result<DecisionVerdict, ControlPlaneAdapterError>;
    fn events(&self) -> &[AdapterEvent];
}

/// Canonical decision adapter backed by `franken_decision::evaluate`.
#[derive(Debug, Clone)]
pub struct ContractDecisionAdapter<C: DecisionContract> {
    contract: C,
    posterior: Posterior,
    events: Vec<AdapterEvent>,
}

impl<C: DecisionContract> ContractDecisionAdapter<C> {
    pub fn new(contract: C, posterior: Posterior) -> Self {
        Self {
            contract,
            posterior,
            events: Vec::new(),
        }
    }
}

impl<C: DecisionContract> DecisionAdapter for ContractDecisionAdapter<C> {
    fn evaluate(
        &mut self,
        request: &DecisionRequest,
    ) -> Result<DecisionVerdict, ControlPlaneAdapterError> {
        let ctx = EvalContext {
            calibration_score: request.calibration_score(),
            e_process: request.e_process(),
            ci_width: request.ci_width(),
            decision_id: request.decision_id,
            trace_id: request.trace_id,
            ts_unix_ms: request.ts_unix_ms,
        };
        let outcome = franken_decision::evaluate(&self.contract, &self.posterior, &ctx);
        let verdict = action_to_verdict(&outcome.action_name).ok_or_else(|| {
            self.events.push(new_event(
                request,
                "decision_eval",
                "error",
                Some("unknown_action"),
            ));
            ControlPlaneAdapterError::DecisionGateway {
                code: "unknown_action",
            }
        })?;
        self.events
            .push(new_event(request, "decision_eval", verdict.as_str(), None));
        Ok(verdict)
    }

    fn events(&self) -> &[AdapterEvent] {
        &self.events
    }
}

/// Adapter boundary for evidence emission.
pub trait EvidenceEmitter {
    fn emit(
        &mut self,
        request: &DecisionRequest,
        entry: EvidenceLedger,
    ) -> Result<(), ControlPlaneAdapterError>;
    fn events(&self) -> &[AdapterEvent];
}

/// Minimal in-memory evidence sink used by integration and test harnesses.
#[derive(Debug, Clone, Default)]
pub struct InMemoryEvidenceEmitter {
    entries: Vec<EvidenceLedger>,
    events: Vec<AdapterEvent>,
}

impl InMemoryEvidenceEmitter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &[EvidenceLedger] {
        &self.entries
    }
}

impl EvidenceEmitter for InMemoryEvidenceEmitter {
    fn emit(
        &mut self,
        request: &DecisionRequest,
        entry: EvidenceLedger,
    ) -> Result<(), ControlPlaneAdapterError> {
        self.entries.push(entry);
        self.events
            .push(new_event(request, "evidence_emit", "ok", None));
        Ok(())
    }

    fn events(&self) -> &[AdapterEvent] {
        &self.events
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
        component: ADAPTER_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code: error_code.map(std::string::ToString::to_string),
    }
}

fn action_to_verdict(action: &str) -> Option<DecisionVerdict> {
    match action.to_ascii_lowercase().as_str() {
        "allow" | "permit" | "continue" => Some(DecisionVerdict::Allow),
        "deny" | "reject" | "block" => Some(DecisionVerdict::Deny),
        "timeout" | "challenge" | "defer" => Some(DecisionVerdict::Timeout),
        _ => None,
    }
}

/// Test helper mock types used by integration suites without reaching into
/// upstream control-plane crates directly.
pub mod mocks {
    use std::collections::VecDeque;
    use std::thread;
    use std::time::Duration;

    use super::*;

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
                verdict.as_str(),
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

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};

    use super::mocks::{
        MockBudget, MockCx, MockDecisionContract, MockEvidenceEmitter, MockFailureMode,
        decision_id_from_seed, policy_id_from_seed, trace_id_from_seed,
    };
    use super::*;

    fn request(seed: u64) -> DecisionRequest {
        DecisionRequest {
            decision_id: decision_id_from_seed(seed),
            policy_id: policy_id_from_seed(seed),
            trace_id: trace_id_from_seed(seed),
            ts_unix_ms: 1_700_000_000_000 + seed,
            calibration_score_bps: 9_400,
            e_process_milli: 110,
            ci_width_milli: 45,
        }
    }

    fn evidence(ts: u64, action: &str) -> EvidenceLedger {
        let chosen_loss = match action {
            "allow" => 0.1,
            "deny" => 0.2,
            "timeout" => 0.3,
            _ => 0.1, // default for unknown actions
        };
        EvidenceLedgerBuilder::new()
            .ts_unix_ms(ts)
            .component("control_plane_adapter_test")
            .action(action)
            .posterior(vec![0.7, 0.3])
            .expected_loss("allow", 0.1)
            .expected_loss("deny", 0.2)
            .expected_loss("timeout", 0.3)
            .chosen_expected_loss(chosen_loss)
            .calibration_score(0.94)
            .fallback_active(false)
            .build()
            .expect("valid evidence")
    }

    #[test]
    fn mock_context_tracks_budget_and_can_panic_on_overspend() {
        let trace_id = trace_id_from_seed(1);
        let mut cx = MockCx::new(trace_id, MockBudget::new(20));
        cx.consume_budget(5).expect("consume");
        assert_eq!(cx.trace_id(), trace_id);
        assert_eq!(cx.budget().remaining_ms(), 15);

        let mut panic_cx = MockCx::new(
            trace_id_from_seed(2),
            MockBudget::new(1).panic_on_overspend(true),
        );
        let panicked = panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = panic_cx.consume_budget(2);
        }));
        assert!(panicked.is_err(), "overspend panic mode must panic");
    }

    #[test]
    fn mock_decision_contract_supports_allow_deny_timeout_and_fail_after_n() {
        let req = request(10);
        let mut decision = MockDecisionContract::new([
            DecisionVerdict::Allow,
            DecisionVerdict::Deny,
            DecisionVerdict::Timeout,
        ]);
        assert_eq!(
            decision.evaluate(&req).expect("allow"),
            DecisionVerdict::Allow
        );
        assert_eq!(
            decision.evaluate(&req).expect("deny"),
            DecisionVerdict::Deny
        );
        assert_eq!(
            decision.evaluate(&req).expect("timeout"),
            DecisionVerdict::Timeout
        );

        let mut fail_after_n = MockDecisionContract::new([DecisionVerdict::Allow])
            .with_failure_mode(MockFailureMode::FailAfterN {
                remaining_successes: 1,
                code: "mock_fail_after_n",
            });
        assert_eq!(
            fail_after_n.evaluate(&req).expect("first call passes"),
            DecisionVerdict::Allow
        );
        let err = fail_after_n
            .evaluate(&req)
            .expect_err("second call should fail");
        assert!(matches!(
            err,
            ControlPlaneAdapterError::DecisionGateway {
                code: "mock_fail_after_n"
            }
        ));
    }

    #[test]
    fn mock_evidence_emitter_supports_fail_always_and_records_events() {
        let req = request(20);
        let mut emitter = MockEvidenceEmitter::new();
        emitter
            .emit(&req, evidence(req.ts_unix_ms, "allow"))
            .expect("emit success");
        assert_eq!(emitter.entries().len(), 1);
        assert_eq!(emitter.events().len(), 1);
        assert_eq!(emitter.events()[0].outcome, "ok");

        let mut fail_always =
            MockEvidenceEmitter::new().with_failure_mode(MockFailureMode::FailAlways {
                code: "mock_evidence_fail_always",
            });
        let err = fail_always
            .emit(&req, evidence(req.ts_unix_ms + 1, "deny"))
            .expect_err("fail always should error");
        assert!(matches!(
            err,
            ControlPlaneAdapterError::EvidenceEmission {
                code: "mock_evidence_fail_always"
            }
        ));
    }

    // ── DecisionVerdict ────────────────────────────────────────────

    #[test]
    fn decision_verdict_as_str() {
        assert_eq!(DecisionVerdict::Allow.as_str(), "allow");
        assert_eq!(DecisionVerdict::Deny.as_str(), "deny");
        assert_eq!(DecisionVerdict::Timeout.as_str(), "timeout");
    }

    #[test]
    fn decision_verdict_serde_round_trip() {
        for variant in [
            DecisionVerdict::Allow,
            DecisionVerdict::Deny,
            DecisionVerdict::Timeout,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: DecisionVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // ── DecisionRequest conversion helpers ─────────────────────────

    #[test]
    fn decision_request_calibration_score() {
        let req = request(1);
        assert!((req.calibration_score() - 0.94).abs() < 1e-9);
    }

    #[test]
    fn decision_request_e_process() {
        let req = request(1);
        assert!((req.e_process() - 0.110).abs() < 1e-9);
    }

    #[test]
    fn decision_request_ci_width() {
        let req = request(1);
        assert!((req.ci_width() - 0.045).abs() < 1e-9);
    }

    #[test]
    fn decision_request_serde_round_trip() {
        let req = request(42);
        let json = serde_json::to_string(&req).unwrap();
        let back: DecisionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    // ── ControlPlaneAdapterError ───────────────────────────────────

    #[test]
    fn error_code_values() {
        assert_eq!(
            ControlPlaneAdapterError::BudgetExhausted { requested_ms: 10 }.error_code(),
            "budget_exhausted"
        );
        assert_eq!(
            ControlPlaneAdapterError::DecisionGateway { code: "gw_fail" }.error_code(),
            "gw_fail"
        );
        assert_eq!(
            ControlPlaneAdapterError::EvidenceEmission { code: "emit_fail" }.error_code(),
            "emit_fail"
        );
    }

    #[test]
    fn error_display_budget_exhausted() {
        let err = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 50 };
        assert!(err.to_string().contains("50"));
    }

    #[test]
    fn error_display_decision_gateway() {
        let err = ControlPlaneAdapterError::DecisionGateway {
            code: "gateway_err",
        };
        assert!(err.to_string().contains("gateway_err"));
    }

    #[test]
    fn error_display_evidence_emission() {
        let err = ControlPlaneAdapterError::EvidenceEmission { code: "emit_err" };
        assert!(err.to_string().contains("emit_err"));
    }

    // ── action_to_verdict ──────────────────────────────────────────

    #[test]
    fn action_to_verdict_allow_synonyms() {
        assert_eq!(action_to_verdict("allow"), Some(DecisionVerdict::Allow));
        assert_eq!(action_to_verdict("permit"), Some(DecisionVerdict::Allow));
        assert_eq!(action_to_verdict("continue"), Some(DecisionVerdict::Allow));
        assert_eq!(action_to_verdict("ALLOW"), Some(DecisionVerdict::Allow));
    }

    #[test]
    fn action_to_verdict_deny_synonyms() {
        assert_eq!(action_to_verdict("deny"), Some(DecisionVerdict::Deny));
        assert_eq!(action_to_verdict("reject"), Some(DecisionVerdict::Deny));
        assert_eq!(action_to_verdict("block"), Some(DecisionVerdict::Deny));
    }

    #[test]
    fn action_to_verdict_timeout_synonyms() {
        assert_eq!(action_to_verdict("timeout"), Some(DecisionVerdict::Timeout));
        assert_eq!(
            action_to_verdict("challenge"),
            Some(DecisionVerdict::Timeout)
        );
        assert_eq!(action_to_verdict("defer"), Some(DecisionVerdict::Timeout));
    }

    #[test]
    fn action_to_verdict_unknown_returns_none() {
        assert_eq!(action_to_verdict("unknown_action"), None);
        assert_eq!(action_to_verdict(""), None);
    }

    // ── InMemoryEvidenceEmitter ────────────────────────────────────

    #[test]
    fn in_memory_evidence_emitter_records_entries_and_events() {
        let req = request(30);
        let mut emitter = InMemoryEvidenceEmitter::new();
        assert!(emitter.entries().is_empty());
        assert!(emitter.events().is_empty());

        emitter
            .emit(&req, evidence(req.ts_unix_ms, "allow"))
            .unwrap();
        assert_eq!(emitter.entries().len(), 1);
        assert_eq!(emitter.events().len(), 1);
        assert_eq!(emitter.events()[0].event, "evidence_emit");
        assert_eq!(emitter.events()[0].outcome, "ok");
        assert_eq!(emitter.events()[0].component, ADAPTER_COMPONENT);
    }

    // ── AdapterEvent serde ─────────────────────────────────────────

    #[test]
    fn adapter_event_serde_round_trip() {
        let event = AdapterEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "test".to_string(),
            event: "eval".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: AdapterEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // ── MockDecisionContract exhausted responses ───────────────────

    #[test]
    fn mock_decision_contract_defaults_to_timeout_when_exhausted() {
        let req = request(40);
        let mut decision = MockDecisionContract::new([DecisionVerdict::Allow]);
        assert_eq!(decision.evaluate(&req).unwrap(), DecisionVerdict::Allow);
        // Second call exhausts the queue, should default to Timeout
        assert_eq!(decision.evaluate(&req).unwrap(), DecisionVerdict::Timeout);
    }

    // -- Enrichment: error trait --

    #[test]
    fn control_plane_adapter_error_is_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ControlPlaneAdapterError::BudgetExhausted { requested_ms: 100 }),
            Box::new(ControlPlaneAdapterError::DecisionGateway { code: "DG_TIMEOUT" }),
            Box::new(ControlPlaneAdapterError::EvidenceEmission { code: "EE_FAIL" }),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: default --

    #[test]
    fn mock_failure_mode_default_is_never() {
        assert_eq!(MockFailureMode::default(), MockFailureMode::Never);
    }

    #[test]
    fn in_memory_evidence_emitter_default_is_empty() {
        let emitter = InMemoryEvidenceEmitter::default();
        assert_eq!(emitter.entries().len(), 0);
        assert_eq!(emitter.events().len(), 0);
    }

    // -- Enrichment: error code uniqueness --

    #[test]
    fn error_codes_are_distinct() {
        let codes = [
            ControlPlaneAdapterError::BudgetExhausted { requested_ms: 1 }.error_code(),
            ControlPlaneAdapterError::DecisionGateway { code: "x" }.error_code(),
            ControlPlaneAdapterError::EvidenceEmission { code: "y" }.error_code(),
        ];
        let set: std::collections::BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(set.len(), codes.len());
    }

    // -- Enrichment: adapter event with error_code --

    #[test]
    fn adapter_event_with_error_code_serde() {
        let event = AdapterEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "test".to_string(),
            event: "eval".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("DG_TIMEOUT".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: AdapterEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
        assert_eq!(back.error_code.as_deref(), Some("DG_TIMEOUT"));
    }

    // -- Enrichment: MockBudget --

    #[test]
    fn mock_budget_zero_consume_succeeds_on_zero_budget() {
        let mut b = MockBudget::new(0);
        b.consume(0)
            .expect("zero consume on zero budget should succeed");
        assert_eq!(b.remaining_ms(), 0);
        assert_eq!(b.consumed_ms(), 0);
    }

    #[test]
    fn mock_budget_tracks_cumulative_consumption() {
        let mut b = MockBudget::new(100);
        b.consume(30).unwrap();
        b.consume(20).unwrap();
        assert_eq!(b.remaining_ms(), 50);
        assert_eq!(b.consumed_ms(), 50);
    }

    #[test]
    fn mock_budget_returns_error_on_overspend_without_panic() {
        let mut b = MockBudget::new(10);
        let err = b.consume(11).unwrap_err();
        assert!(matches!(
            err,
            ControlPlaneAdapterError::BudgetExhausted { requested_ms: 11 }
        ));
    }

    // -- Enrichment: MockCx --

    #[test]
    fn mock_cx_budget_state_accessor() {
        let trace = trace_id_from_seed(99);
        let cx = MockCx::new(trace, MockBudget::new(42));
        assert_eq!(cx.budget_state().remaining_ms(), 42);
        assert_eq!(cx.budget_state().consumed_ms(), 0);
    }

    // -- Enrichment: mock helpers --

    #[test]
    fn trace_id_from_different_seeds_differ() {
        let t1 = trace_id_from_seed(1);
        let t2 = trace_id_from_seed(2);
        assert_ne!(t1, t2);
    }

    #[test]
    fn decision_id_from_different_seeds_differ() {
        let d1 = decision_id_from_seed(1);
        let d2 = decision_id_from_seed(2);
        assert_ne!(d1, d2);
    }

    #[test]
    fn policy_id_from_seed_deterministic() {
        let p1 = policy_id_from_seed(5);
        let p2 = policy_id_from_seed(5);
        assert_eq!(p1, p2);
    }

    // -- Enrichment: MockDecisionContract panic mode --

    #[test]
    fn mock_decision_contract_panic_on_call() {
        let req = request(50);
        let mut contract = MockDecisionContract::new([DecisionVerdict::Allow])
            .with_failure_mode(MockFailureMode::PanicOnCall);
        let panicked = panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = contract.evaluate(&req);
        }));
        assert!(panicked.is_err());
    }

    // -- Enrichment: MockEvidenceEmitter fail_after_n --

    #[test]
    fn mock_evidence_emitter_fail_after_n() {
        let req = request(60);
        let mut emitter =
            MockEvidenceEmitter::new().with_failure_mode(MockFailureMode::FailAfterN {
                remaining_successes: 1,
                code: "emit_fail_after_1",
            });
        emitter
            .emit(&req, evidence(req.ts_unix_ms, "allow"))
            .expect("first emit should pass");
        let err = emitter
            .emit(&req, evidence(req.ts_unix_ms + 1, "deny"))
            .unwrap_err();
        assert!(matches!(
            err,
            ControlPlaneAdapterError::EvidenceEmission {
                code: "emit_fail_after_1"
            }
        ));
    }

    // -- Enrichment: DecisionVerdict equality --

    #[test]
    fn decision_verdict_equality_and_clone() {
        let v = DecisionVerdict::Allow;
        let v2 = v;
        assert_eq!(v, v2);
    }

    // -- Enrichment: DecisionRequest same seed identical --

    #[test]
    fn decision_request_same_seed_identical() {
        let r1 = request(100);
        let r2 = request(100);
        assert_eq!(r1, r2);
    }

    // -- Enrichment batch 2: Display uniqueness, serde, determinism --

    #[test]
    fn decision_verdict_display_uniqueness() {
        let variants = [
            DecisionVerdict::Allow,
            DecisionVerdict::Deny,
            DecisionVerdict::Timeout,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            seen.insert(v.as_str());
        }
        assert_eq!(seen.len(), 3, "all 3 verdicts have unique as_str values");
    }

    #[test]
    fn decision_request_different_seeds_differ() {
        let r1 = request(1);
        let r2 = request(2);
        assert_ne!(r1, r2);
    }

    #[test]
    fn decision_request_conversion_boundary_zero() {
        let req = DecisionRequest {
            decision_id: decision_id_from_seed(0),
            policy_id: policy_id_from_seed(0),
            trace_id: trace_id_from_seed(0),
            ts_unix_ms: 0,
            calibration_score_bps: 0,
            e_process_milli: 0,
            ci_width_milli: 0,
        };
        assert!((req.calibration_score() - 0.0).abs() < 1e-12);
        assert!((req.e_process() - 0.0).abs() < 1e-12);
        assert!((req.ci_width() - 0.0).abs() < 1e-12);
    }

    #[test]
    fn decision_request_conversion_boundary_max_bps() {
        let req = DecisionRequest {
            decision_id: decision_id_from_seed(0),
            policy_id: policy_id_from_seed(0),
            trace_id: trace_id_from_seed(0),
            ts_unix_ms: 0,
            calibration_score_bps: 10_000,
            e_process_milli: u32::MAX,
            ci_width_milli: u32::MAX,
        };
        assert!((req.calibration_score() - 1.0).abs() < 1e-9);
        assert!(req.e_process() > 4_000_000.0);
        assert!(req.ci_width() > 4_000_000.0);
    }

    #[test]
    fn action_to_verdict_case_insensitive_mixed() {
        assert_eq!(action_to_verdict("Allow"), Some(DecisionVerdict::Allow));
        assert_eq!(action_to_verdict("DENY"), Some(DecisionVerdict::Deny));
        assert_eq!(action_to_verdict("Timeout"), Some(DecisionVerdict::Timeout));
        assert_eq!(action_to_verdict("PERMIT"), Some(DecisionVerdict::Allow));
        assert_eq!(action_to_verdict("REJECT"), Some(DecisionVerdict::Deny));
        assert_eq!(action_to_verdict("DEFER"), Some(DecisionVerdict::Timeout));
    }

    #[test]
    fn in_memory_evidence_emitter_multiple_entries() {
        let mut emitter = InMemoryEvidenceEmitter::new();
        for seed in 1..=5 {
            let req = request(seed);
            emitter
                .emit(&req, evidence(req.ts_unix_ms, "allow"))
                .unwrap();
        }
        assert_eq!(emitter.entries().len(), 5);
        assert_eq!(emitter.events().len(), 5);
    }

    #[test]
    fn new_event_helper_populates_all_fields() {
        let req = request(77);
        let event = new_event(&req, "test_event", "test_outcome", Some("err_code"));
        assert_eq!(event.event, "test_event");
        assert_eq!(event.outcome, "test_outcome");
        assert_eq!(event.error_code.as_deref(), Some("err_code"));
        assert_eq!(event.component, ADAPTER_COMPONENT);
    }

    #[test]
    fn new_event_helper_none_error_code() {
        let req = request(88);
        let event = new_event(&req, "ev", "ok", None);
        assert!(event.error_code.is_none());
    }

    #[test]
    fn mock_budget_exact_boundary_consume() {
        let mut b = MockBudget::new(10);
        b.consume(10).expect("exact boundary should succeed");
        assert_eq!(b.remaining_ms(), 0);
        assert_eq!(b.consumed_ms(), 10);
        // Next consume of 1 should fail
        let err = b.consume(1).unwrap_err();
        assert!(matches!(
            err,
            ControlPlaneAdapterError::BudgetExhausted { requested_ms: 1 }
        ));
    }

    #[test]
    fn schema_version_from_seed_deterministic() {
        use super::mocks::schema_version_from_seed;
        let v1 = schema_version_from_seed(5);
        let v2 = schema_version_from_seed(5);
        assert_eq!(v1, v2);
    }

    // -- Enrichment batch 3: clone equality, JSON field presence, serde, Display, error::source --

    #[test]
    fn decision_verdict_clone_eq_allow() {
        let v = DecisionVerdict::Allow;
        let cloned = v;
        assert_eq!(v, cloned);
    }

    #[test]
    fn decision_verdict_clone_eq_deny() {
        let v = DecisionVerdict::Deny;
        let cloned = v;
        assert_eq!(v, cloned);
    }

    #[test]
    fn decision_request_clone_eq() {
        let req = request(200);
        let cloned = req.clone();
        assert_eq!(req, cloned);
    }

    #[test]
    fn adapter_event_clone_eq() {
        let event = AdapterEvent {
            trace_id: "trace_clone".to_string(),
            decision_id: "dec_clone".to_string(),
            policy_id: "pol_clone".to_string(),
            component: "comp_clone".to_string(),
            event: "evt_clone".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("ec_clone".to_string()),
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    #[test]
    fn control_plane_adapter_error_clone_eq() {
        let e1 = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 42 };
        let c1 = e1.clone();
        assert_eq!(e1, c1);

        let e2 = ControlPlaneAdapterError::DecisionGateway { code: "gw" };
        let c2 = e2.clone();
        assert_eq!(e2, c2);

        let e3 = ControlPlaneAdapterError::EvidenceEmission { code: "ee" };
        let c3 = e3.clone();
        assert_eq!(e3, c3);
    }

    #[test]
    fn decision_request_json_field_presence() {
        let req = request(300);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"ts_unix_ms\""));
        assert!(json.contains("\"calibration_score_bps\""));
        assert!(json.contains("\"e_process_milli\""));
        assert!(json.contains("\"ci_width_milli\""));
    }

    #[test]
    fn adapter_event_json_field_presence() {
        let event = AdapterEvent {
            trace_id: "t_fp".to_string(),
            decision_id: "d_fp".to_string(),
            policy_id: "p_fp".to_string(),
            component: "c_fp".to_string(),
            event: "e_fp".to_string(),
            outcome: "o_fp".to_string(),
            error_code: Some("ec_fp".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"event\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"error_code\""));
    }

    #[test]
    fn decision_verdict_json_values_are_quoted_strings() {
        let allow_json = serde_json::to_string(&DecisionVerdict::Allow).unwrap();
        let deny_json = serde_json::to_string(&DecisionVerdict::Deny).unwrap();
        let timeout_json = serde_json::to_string(&DecisionVerdict::Timeout).unwrap();
        assert!(allow_json.contains("Allow"));
        assert!(deny_json.contains("Deny"));
        assert!(timeout_json.contains("Timeout"));
        // Each serialized form must be distinct
        let mut set = std::collections::BTreeSet::new();
        set.insert(allow_json);
        set.insert(deny_json);
        set.insert(timeout_json);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn adapter_event_none_error_code_serde_roundtrip() {
        let event = AdapterEvent {
            trace_id: "t_rt".to_string(),
            decision_id: "d_rt".to_string(),
            policy_id: "p_rt".to_string(),
            component: "c_rt".to_string(),
            event: "e_rt".to_string(),
            outcome: "o_rt".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: AdapterEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
        assert!(back.error_code.is_none());
    }

    #[test]
    fn error_display_messages_are_unique_across_variants() {
        let msgs: Vec<String> = vec![
            ControlPlaneAdapterError::BudgetExhausted { requested_ms: 1 }.to_string(),
            ControlPlaneAdapterError::DecisionGateway { code: "gw_unique" }.to_string(),
            ControlPlaneAdapterError::EvidenceEmission { code: "ee_unique" }.to_string(),
        ];
        let set: std::collections::BTreeSet<&str> = msgs.iter().map(|s| s.as_str()).collect();
        assert_eq!(set.len(), 3, "all error Display strings must be unique");
    }

    #[test]
    fn error_source_is_none_for_all_variants() {
        use std::error::Error;
        let variants: Vec<ControlPlaneAdapterError> = vec![
            ControlPlaneAdapterError::BudgetExhausted { requested_ms: 5 },
            ControlPlaneAdapterError::DecisionGateway { code: "src_test" },
            ControlPlaneAdapterError::EvidenceEmission { code: "src_test" },
        ];
        for e in &variants {
            assert!(e.source().is_none(), "source() should be None for {e}");
        }
    }

    #[test]
    fn mock_budget_as_budget_remaining_matches() {
        let b = MockBudget::new(999);
        let kernel_budget = b.as_budget();
        assert_eq!(kernel_budget.remaining_ms(), b.remaining_ms());
    }

    // ── Batch 4: Copy semantics ─────────────────────────────────────

    #[test]
    fn decision_verdict_copy_semantics() {
        // DecisionVerdict is Copy; moving it should leave original usable.
        let v = DecisionVerdict::Deny;
        let v2 = v; // copy, not move
        assert_eq!(v, v2);
        // Both still usable after "move"
        assert_eq!(v, DecisionVerdict::Deny);
        assert_eq!(v2, DecisionVerdict::Deny);
    }

    #[test]
    fn decision_verdict_copy_allow_and_timeout() {
        let a = DecisionVerdict::Allow;
        let t = DecisionVerdict::Timeout;
        let a2 = a;
        let t2 = t;
        assert_eq!(a, a2);
        assert_eq!(t, t2);
    }

    // ── Batch 4: Debug distinctness ─────────────────────────────────

    #[test]
    fn decision_verdict_debug_strings_are_distinct() {
        let allow_dbg = format!("{:?}", DecisionVerdict::Allow);
        let deny_dbg = format!("{:?}", DecisionVerdict::Deny);
        let timeout_dbg = format!("{:?}", DecisionVerdict::Timeout);
        assert_ne!(allow_dbg, deny_dbg);
        assert_ne!(allow_dbg, timeout_dbg);
        assert_ne!(deny_dbg, timeout_dbg);
    }

    #[test]
    fn decision_verdict_debug_nonempty() {
        assert!(!format!("{:?}", DecisionVerdict::Allow).is_empty());
        assert!(!format!("{:?}", DecisionVerdict::Deny).is_empty());
        assert!(!format!("{:?}", DecisionVerdict::Timeout).is_empty());
    }

    #[test]
    fn decision_request_debug_nonempty() {
        let req = request(500);
        let dbg = format!("{req:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("DecisionRequest"));
    }

    #[test]
    fn adapter_event_debug_nonempty() {
        let event = AdapterEvent {
            trace_id: "dbg_t".to_string(),
            decision_id: "dbg_d".to_string(),
            policy_id: "dbg_p".to_string(),
            component: "dbg_c".to_string(),
            event: "dbg_ev".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let dbg = format!("{event:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("AdapterEvent"));
    }

    #[test]
    fn control_plane_adapter_error_debug_nonempty() {
        let e1 = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 7 };
        let e2 = ControlPlaneAdapterError::DecisionGateway { code: "gw_dbg" };
        let e3 = ControlPlaneAdapterError::EvidenceEmission { code: "ee_dbg" };
        for dbg in [format!("{e1:?}"), format!("{e2:?}"), format!("{e3:?}")] {
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn control_plane_adapter_error_debug_distinct_variants() {
        let e1 = format!(
            "{:?}",
            ControlPlaneAdapterError::BudgetExhausted { requested_ms: 1 }
        );
        let e2 = format!(
            "{:?}",
            ControlPlaneAdapterError::DecisionGateway { code: "a" }
        );
        let e3 = format!(
            "{:?}",
            ControlPlaneAdapterError::EvidenceEmission { code: "b" }
        );
        let mut set = std::collections::BTreeSet::new();
        set.insert(e1);
        set.insert(e2);
        set.insert(e3);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn mock_budget_debug_nonempty() {
        let b = MockBudget::new(77);
        assert!(!format!("{b:?}").is_empty());
    }

    #[test]
    fn mock_cx_debug_nonempty() {
        let cx = MockCx::new(trace_id_from_seed(42), MockBudget::new(10));
        assert!(!format!("{cx:?}").is_empty());
    }

    // ── Batch 4: Serde variant distinctness ────────────────────────

    #[test]
    fn decision_verdict_serde_all_distinct() {
        let jsons: Vec<String> = [
            DecisionVerdict::Allow,
            DecisionVerdict::Deny,
            DecisionVerdict::Timeout,
        ]
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
        let set: std::collections::BTreeSet<&str> = jsons.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            set.len(),
            3,
            "all 3 verdict JSON serializations must differ"
        );
    }

    #[test]
    fn decision_verdict_serde_roundtrip_deny() {
        let v = DecisionVerdict::Deny;
        let json = serde_json::to_string(&v).unwrap();
        let back: DecisionVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn decision_verdict_serde_roundtrip_timeout() {
        let v = DecisionVerdict::Timeout;
        let json = serde_json::to_string(&v).unwrap();
        let back: DecisionVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // ── Batch 4: Clone independence ─────────────────────────────────

    #[test]
    fn adapter_event_clone_independence() {
        let original = AdapterEvent {
            trace_id: "orig_t".to_string(),
            decision_id: "orig_d".to_string(),
            policy_id: "orig_p".to_string(),
            component: "orig_c".to_string(),
            event: "orig_ev".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let mut cloned = original.clone();
        cloned.outcome = "mutated".to_string();
        assert_eq!(original.outcome, "ok");
        assert_eq!(cloned.outcome, "mutated");
    }

    #[test]
    fn decision_request_clone_independence() {
        let original = request(600);
        let mut cloned = original.clone();
        cloned.calibration_score_bps = 0;
        assert_eq!(original.calibration_score_bps, 9_400);
        assert_eq!(cloned.calibration_score_bps, 0);
    }

    #[test]
    fn control_plane_adapter_error_clone_independence() {
        let original = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 10 };
        let cloned = original.clone();
        assert_eq!(original, cloned);
        // Different requested_ms must not be equal after independent mutation (structural)
        let other = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 99 };
        assert_ne!(original, other);
    }

    #[test]
    fn in_memory_evidence_emitter_clone_independence() {
        let req = request(700);
        let mut original = InMemoryEvidenceEmitter::new();
        original
            .emit(&req, evidence(req.ts_unix_ms, "allow"))
            .unwrap();
        let cloned = original.clone();
        // After clone, emitting into original doesn't affect clone
        original
            .emit(&req, evidence(req.ts_unix_ms + 1, "deny"))
            .unwrap();
        assert_eq!(original.entries().len(), 2);
        assert_eq!(cloned.entries().len(), 1);
    }

    // ── Batch 4: JSON field-name stability ──────────────────────────

    #[test]
    fn adapter_event_json_field_names_stable() {
        let event = AdapterEvent {
            trace_id: "fs_t".to_string(),
            decision_id: "fs_d".to_string(),
            policy_id: "fs_p".to_string(),
            component: "fs_c".to_string(),
            event: "fs_ev".to_string(),
            outcome: "fs_out".to_string(),
            error_code: Some("fs_ec".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        // All six mandatory fields must appear by name
        for field in &[
            "trace_id",
            "decision_id",
            "policy_id",
            "component",
            "event",
            "outcome",
            "error_code",
        ] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "field {field} missing from JSON"
            );
        }
    }

    #[test]
    fn decision_request_json_field_names_stable_keys() {
        let req = request(800);
        let json = serde_json::to_string(&req).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = value.as_object().unwrap();
        for key in &[
            "decision_id",
            "policy_id",
            "trace_id",
            "ts_unix_ms",
            "calibration_score_bps",
            "e_process_milli",
            "ci_width_milli",
        ] {
            assert!(obj.contains_key(*key), "key {key} not found");
        }
    }

    // ── Batch 4: Display format checks ──────────────────────────────

    #[test]
    fn error_display_budget_exhausted_contains_ms_value() {
        let err = ControlPlaneAdapterError::BudgetExhausted {
            requested_ms: 12345,
        };
        let msg = err.to_string();
        assert!(msg.contains("12345"), "display must include requested_ms");
    }

    #[test]
    fn error_display_decision_gateway_contains_code() {
        let err = ControlPlaneAdapterError::DecisionGateway {
            code: "specific_gw_code",
        };
        let msg = err.to_string();
        assert!(
            msg.contains("specific_gw_code"),
            "display must contain the error code"
        );
    }

    #[test]
    fn error_display_evidence_emission_contains_code() {
        let err = ControlPlaneAdapterError::EvidenceEmission {
            code: "specific_ee_code",
        };
        let msg = err.to_string();
        assert!(
            msg.contains("specific_ee_code"),
            "display must contain the error code"
        );
    }

    #[test]
    fn error_display_budget_exhausted_zero_ms() {
        let err = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 0 };
        let msg = err.to_string();
        assert!(msg.contains("0"), "display must include 0ms");
    }

    // ── Batch 4: Hash-like consistency (via serde JSON) ────────────

    #[test]
    fn decision_verdict_json_consistent_allow() {
        // Serializing the same variant twice must produce identical JSON.
        let j1 = serde_json::to_string(&DecisionVerdict::Allow).unwrap();
        let j2 = serde_json::to_string(&DecisionVerdict::Allow).unwrap();
        assert_eq!(j1, j2);
    }

    #[test]
    fn decision_verdict_json_consistent_deny_and_timeout() {
        let j_deny_1 = serde_json::to_string(&DecisionVerdict::Deny).unwrap();
        let j_deny_2 = serde_json::to_string(&DecisionVerdict::Deny).unwrap();
        assert_eq!(j_deny_1, j_deny_2);
        let j_t1 = serde_json::to_string(&DecisionVerdict::Timeout).unwrap();
        let j_t2 = serde_json::to_string(&DecisionVerdict::Timeout).unwrap();
        assert_eq!(j_t1, j_t2);
    }

    // ── Batch 4: Boundary / edge cases ──────────────────────────────

    #[test]
    fn decision_request_ts_unix_ms_max_serde() {
        let req = DecisionRequest {
            decision_id: decision_id_from_seed(0),
            policy_id: policy_id_from_seed(0),
            trace_id: trace_id_from_seed(0),
            ts_unix_ms: u64::MAX,
            calibration_score_bps: 1,
            e_process_milli: 1,
            ci_width_milli: 1,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: DecisionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn action_to_verdict_whitespace_not_mapped() {
        assert_eq!(action_to_verdict(" allow"), None);
        assert_eq!(action_to_verdict("allow "), None);
        assert_eq!(action_to_verdict(" "), None);
    }

    #[test]
    fn action_to_verdict_numeric_string_returns_none() {
        assert_eq!(action_to_verdict("0"), None);
        assert_eq!(action_to_verdict("1"), None);
        assert_eq!(action_to_verdict("allow1"), None);
    }

    #[test]
    fn mock_budget_consume_exactly_zero_on_nonempty() {
        let mut b = MockBudget::new(50);
        b.consume(0)
            .expect("zero consume on non-zero budget must succeed");
        assert_eq!(b.remaining_ms(), 50);
        assert_eq!(b.consumed_ms(), 0);
    }

    #[test]
    fn in_memory_evidence_emitter_events_match_emit_count() {
        let mut emitter = InMemoryEvidenceEmitter::new();
        for seed in 1..=3 {
            let req = request(seed * 1000);
            emitter
                .emit(&req, evidence(req.ts_unix_ms, "deny"))
                .unwrap();
        }
        assert_eq!(emitter.entries().len(), emitter.events().len());
    }

    #[test]
    fn adapter_event_error_code_none_vs_some_differ() {
        let base = AdapterEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let mut with_code = base.clone();
        with_code.error_code = Some("some_code".to_string());
        assert_ne!(base, with_code);
    }

    // ── Batch 4: Serde roundtrips (additional) ──────────────────────

    #[test]
    fn decision_request_roundtrip_seed_zero() {
        let req = request(0);
        let json = serde_json::to_string(&req).unwrap();
        let back: DecisionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn decision_request_roundtrip_large_seed() {
        let req = request(u64::MAX / 2);
        let json = serde_json::to_string(&req).unwrap();
        let back: DecisionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn adapter_event_serde_roundtrip_all_fields_valued() {
        let event = AdapterEvent {
            trace_id: "rt_t".to_string(),
            decision_id: "rt_d".to_string(),
            policy_id: "rt_p".to_string(),
            component: "rt_c".to_string(),
            event: "rt_ev".to_string(),
            outcome: "rt_out".to_string(),
            error_code: Some("rt_ec".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: AdapterEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // ── Batch 4: error_code passthrough checks ──────────────────────

    #[test]
    fn error_code_budget_exhausted_independent_of_ms() {
        let e1 = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 1 };
        let e2 = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 999 };
        assert_eq!(e1.error_code(), e2.error_code());
        assert_eq!(e1.error_code(), "budget_exhausted");
    }

    #[test]
    fn error_code_decision_gateway_reflects_code_field() {
        let e = ControlPlaneAdapterError::DecisionGateway { code: "my_gw_code" };
        assert_eq!(e.error_code(), "my_gw_code");
    }

    #[test]
    fn error_code_evidence_emission_reflects_code_field() {
        let e = ControlPlaneAdapterError::EvidenceEmission { code: "my_ee_code" };
        assert_eq!(e.error_code(), "my_ee_code");
    }

    // ── Batch 4: mock event presence after evaluate ──────────────────

    #[test]
    fn mock_decision_contract_records_event_per_evaluate() {
        let req = request(900);
        let mut contract = MockDecisionContract::new([
            DecisionVerdict::Allow,
            DecisionVerdict::Deny,
            DecisionVerdict::Timeout,
        ]);
        assert!(contract.events().is_empty());
        contract.evaluate(&req).unwrap();
        assert_eq!(contract.events().len(), 1);
        contract.evaluate(&req).unwrap();
        assert_eq!(contract.events().len(), 2);
        contract.evaluate(&req).unwrap();
        assert_eq!(contract.events().len(), 3);
    }

    #[test]
    fn mock_decision_contract_event_outcome_matches_verdict() {
        let req = request(950);
        let mut contract = MockDecisionContract::new([DecisionVerdict::Deny]);
        contract.evaluate(&req).unwrap();
        assert_eq!(contract.events()[0].outcome, "deny");
    }

    #[test]
    fn mock_decision_contract_fail_always_records_error_event() {
        let req = request(960);
        let mut contract = MockDecisionContract::new([])
            .with_failure_mode(MockFailureMode::FailAlways { code: "fa_code" });
        let _ = contract.evaluate(&req);
        assert_eq!(contract.events().len(), 1);
        assert_eq!(contract.events()[0].outcome, "error");
        assert_eq!(contract.events()[0].error_code.as_deref(), Some("fa_code"));
    }

    #[test]
    fn mock_evidence_emitter_event_component_is_adapter() {
        let req = request(970);
        let mut emitter = MockEvidenceEmitter::new();
        emitter
            .emit(&req, evidence(req.ts_unix_ms, "allow"))
            .unwrap();
        assert_eq!(emitter.events()[0].component, ADAPTER_COMPONENT);
    }

    // ── Batch 4: MockFailureMode ────────────────────────────────────

    #[test]
    fn mock_failure_mode_clone_never() {
        let m = MockFailureMode::Never;
        let m2 = m.clone();
        assert_eq!(m, m2);
    }

    #[test]
    fn mock_failure_mode_clone_fail_always() {
        let m = MockFailureMode::FailAlways { code: "fa" };
        let m2 = m.clone();
        assert_eq!(m, m2);
    }

    #[test]
    fn mock_failure_mode_clone_fail_after_n() {
        let m = MockFailureMode::FailAfterN {
            remaining_successes: 5,
            code: "fan",
        };
        let m2 = m.clone();
        assert_eq!(m, m2);
    }

    #[test]
    fn mock_failure_mode_clone_panic_on_call() {
        let m = MockFailureMode::PanicOnCall;
        let m2 = m.clone();
        assert_eq!(m, m2);
    }

    #[test]
    fn mock_failure_mode_debug_nonempty() {
        for m in &[
            MockFailureMode::Never,
            MockFailureMode::FailAlways { code: "x" },
            MockFailureMode::PanicOnCall,
        ] {
            assert!(!format!("{m:?}").is_empty());
        }
    }

    #[test]
    fn mock_budget_clone_eq() {
        let b = MockBudget::new(123).panic_on_overspend(true);
        let b2 = b.clone();
        assert_eq!(b, b2);
    }

    #[test]
    fn mock_cx_clone_eq() {
        let cx = MockCx::new(trace_id_from_seed(7), MockBudget::new(77));
        let cx2 = cx.clone();
        assert_eq!(cx, cx2);
    }
}
