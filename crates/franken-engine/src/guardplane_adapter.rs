//! Instruction-level Probabilistic Guardplane adapter.
//!
//! This module bridges the baseline interpreter hook surface to the existing
//! Bayesian posterior updater, expected-loss selector, and containment
//! threshold policy. The adapter is intentionally metadata-driven for now:
//! execution packages do not yet carry a first-class capability-witness object,
//! so the hook layer reads witness summaries from package metadata using
//! `capability_witness.*` / `guardplane.*` keys.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::baseline_interpreter::{
    AllocKind, ChallengeToken, FunctionRef, HookAction, HookContext, InterpreterHook, ObjectRef,
    PropertyKey, Value,
};
use crate::bayesian_posterior::{BayesianPosteriorUpdater, Evidence, Posterior, RiskState};
use crate::expected_loss_selector::{
    ContainmentAction as SelectorContainmentAction, ExpectedLossSelector, LossMatrix,
};
use crate::fleet_convergence::ContainmentThresholds;
use crate::fleet_immune_protocol::ContainmentAction as ThresholdContainmentAction;
use crate::runtime_config::RuntimeConfig;
use crate::security_epoch::SecurityEpoch;

const MILLION: i64 = 1_000_000;
const WITNESS_CONFIDENCE_FLOOR_MILLIONTHS: i64 = 900_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardplaneTrustLevel {
    Trusted,
    Established,
    Provisional,
    Unknown,
    Suspicious,
    Compromised,
    Revoked,
}

impl GuardplaneTrustLevel {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "trusted" | "signed" | "signed_supply_chain" => Self::Trusted,
            "established" => Self::Established,
            "provisional" | "development" => Self::Provisional,
            "unknown" => Self::Unknown,
            "unsigned" => Self::Suspicious,
            "suspicious" | "untrusted" => Self::Suspicious,
            "compromised" => Self::Compromised,
            "revoked" => Self::Revoked,
            _ => Self::Unknown,
        }
    }

    fn risk_penalty_millionths(self) -> i64 {
        match self {
            Self::Trusted => 0,
            Self::Established => 50_000,
            Self::Provisional => 150_000,
            Self::Unknown => 300_000,
            Self::Suspicious => 550_000,
            Self::Compromised => 800_000,
            Self::Revoked => 950_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardplaneExtensionContext {
    pub extension_id: String,
    pub declared_capabilities: BTreeSet<String>,
    pub metadata: BTreeMap<String, String>,
    pub trust_level: GuardplaneTrustLevel,
    pub witness_confidence_millionths: i64,
    pub required_capabilities: BTreeSet<String>,
    pub denied_capabilities: BTreeSet<String>,
}

impl GuardplaneExtensionContext {
    pub fn new(
        extension_id: impl Into<String>,
        declared_capabilities: BTreeSet<String>,
        metadata: BTreeMap<String, String>,
    ) -> Self {
        let trust_level = metadata_lookup(
            &metadata,
            &[
                "capability_witness.trust_level",
                "guardplane.trust_level",
                "trust_level",
            ],
        )
        .map(GuardplaneTrustLevel::parse)
        .unwrap_or(GuardplaneTrustLevel::Unknown);

        let witness_confidence_millionths = metadata_lookup(
            &metadata,
            &[
                "capability_witness.confidence_millionths",
                "guardplane.witness_confidence_millionths",
            ],
        )
        .and_then(|value| value.parse::<i64>().ok())
        .map(|value| value.clamp(0, MILLION))
        .unwrap_or(0);

        let required_capabilities = parse_capability_csv(
            metadata_lookup(
                &metadata,
                &[
                    "capability_witness.required_capabilities",
                    "guardplane.required_capabilities",
                ],
            )
            .unwrap_or(""),
        );
        let denied_capabilities = parse_capability_csv(
            metadata_lookup(
                &metadata,
                &[
                    "capability_witness.denied_capabilities",
                    "guardplane.denied_capabilities",
                ],
            )
            .unwrap_or(""),
        );

        Self {
            extension_id: extension_id.into(),
            declared_capabilities,
            metadata,
            trust_level,
            witness_confidence_millionths,
            required_capabilities,
            denied_capabilities,
        }
    }

    pub fn instruction_hooks_enabled(&self) -> bool {
        if metadata_lookup(
            &self.metadata,
            &[
                "guardplane.enable_instruction_hooks",
                "capability_witness.enable_hooks",
            ],
        )
        .is_some_and(parse_boolish)
            || self.witness_declared()
        {
            return true;
        }

        matches!(
            self.trust_level,
            GuardplaneTrustLevel::Provisional
                | GuardplaneTrustLevel::Suspicious
                | GuardplaneTrustLevel::Compromised
                | GuardplaneTrustLevel::Revoked
        )
    }

    fn witness_declared(&self) -> bool {
        !self.required_capabilities.is_empty()
            || !self.denied_capabilities.is_empty()
            || self.witness_confidence_millionths > 0
    }

    fn distinct_capability_count(&self) -> u32 {
        let count = if !self.required_capabilities.is_empty() {
            self.required_capabilities.len()
        } else {
            self.declared_capabilities.len()
        };
        u32::try_from(count.max(1)).unwrap_or(u32::MAX)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardplaneOperation {
    PropertyAccess {
        key: String,
    },
    Call {
        callee_name: Option<String>,
        arg_count: usize,
    },
    Allocation {
        kind: AllocKind,
        size_hint: usize,
    },
    Import {
        specifier: String,
    },
}

impl GuardplaneOperation {
    fn capability_label(&self) -> &'static str {
        match self {
            Self::PropertyAccess { .. } => "object.property",
            Self::Call { .. } => "function.call",
            Self::Allocation { kind, .. } => match kind {
                AllocKind::Object => "alloc.object",
                AllocKind::Array => "alloc.array",
                AllocKind::Function => "alloc.function",
                AllocKind::Closure => "alloc.closure",
                AllocKind::RegExp => "alloc.regexp",
            },
            Self::Import { .. } => "module.import",
        }
    }

    fn suspicion_millionths(&self) -> i64 {
        match self {
            Self::PropertyAccess { key } => match key.as_str() {
                "__proto__" | "prototype" | "constructor" => 850_000,
                "globalThis" | "process" | "require" | "module" => 700_000,
                _ if key.starts_with('_') => 200_000,
                _ => 75_000,
            },
            Self::Call {
                callee_name,
                arg_count,
            } => {
                let base = match callee_name.as_deref() {
                    Some("eval") | Some("Function") => 900_000,
                    Some(name) if name.contains("eval") || name.contains("constructor") => 700_000,
                    Some(_) => 125_000,
                    None => 250_000,
                };
                (base
                    + i64::try_from(*arg_count)
                        .unwrap_or(i64::MAX)
                        .saturating_mul(20_000))
                .clamp(0, MILLION)
            }
            Self::Allocation { kind, size_hint } => {
                let base = match kind {
                    AllocKind::Object => 80_000,
                    AllocKind::Array => 100_000,
                    AllocKind::Function => 175_000,
                    AllocKind::Closure => 300_000,
                    AllocKind::RegExp => 450_000,
                };
                let size_penalty = i64::try_from(*size_hint)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(15_000);
                (base + size_penalty).clamp(0, MILLION)
            }
            Self::Import { specifier } => {
                if specifier.starts_with("node:")
                    || specifier.contains("child_process")
                    || specifier.contains("fs")
                {
                    950_000
                } else if specifier.starts_with('.') {
                    200_000
                } else {
                    400_000
                }
            }
        }
    }

    fn rate_millionths(&self, operation_index: u64) -> i64 {
        let base = match self {
            Self::PropertyAccess { .. } => 40_000_000,
            Self::Call { .. } => 65_000_000,
            Self::Allocation { .. } => 55_000_000,
            Self::Import { .. } => 120_000_000,
        };
        let burst_penalty = i64::try_from(operation_index.saturating_sub(1))
            .unwrap_or(i64::MAX)
            .saturating_mul(25_000_000);
        (base + burst_penalty).clamp(0, 600_000_000)
    }

    fn label(&self) -> &'static str {
        match self {
            Self::PropertyAccess { .. } => "property_access",
            Self::Call { .. } => "call",
            Self::Allocation { .. } => "allocation",
            Self::Import { .. } => "import",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardplaneDecisionRecord {
    pub hook_context: HookContext,
    pub operation: GuardplaneOperation,
    pub posterior: Posterior,
    pub risk_state: RiskState,
    pub posterior_delta_millionths: i64,
    pub log_likelihood_ratio_millionths: i64,
    pub selected_action: SelectorContainmentAction,
    pub threshold_action: ThresholdContainmentAction,
    pub action: HookAction,
    pub expected_loss_millionths: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardplaneExecutionSummary {
    pub decision_count: usize,
    pub last_action: Option<HookAction>,
    pub last_selected_action: Option<SelectorContainmentAction>,
    pub last_threshold_action: Option<ThresholdContainmentAction>,
    pub last_expected_loss_millionths: Option<i64>,
    pub last_posterior_delta_millionths: Option<i64>,
    pub last_log_likelihood_ratio_millionths: Option<i64>,
    pub last_posterior: Option<Posterior>,
    pub last_risk_state: Option<RiskState>,
}

#[derive(Debug)]
struct GuardplaneAdapterState {
    updater: BayesianPosteriorUpdater,
    selector: ExpectedLossSelector,
    thresholds: ContainmentThresholds,
    operation_count: u64,
    decisions: Vec<GuardplaneDecisionRecord>,
}

pub struct GuardplaneAdapter {
    context: GuardplaneExtensionContext,
    epoch: SecurityEpoch,
    state: Mutex<GuardplaneAdapterState>,
}

impl GuardplaneAdapter {
    pub fn from_runtime_config(
        context: GuardplaneExtensionContext,
        loss_matrix: LossMatrix,
        runtime_config: &RuntimeConfig,
        epoch: SecurityEpoch,
    ) -> Self {
        let mut updater = BayesianPosteriorUpdater::new(
            Posterior::from_prior_config(&runtime_config.guardplane.priors),
            context.extension_id.clone(),
        );
        updater.set_epoch(epoch);
        Self {
            context,
            epoch,
            state: Mutex::new(GuardplaneAdapterState {
                updater,
                selector: ExpectedLossSelector::new(loss_matrix),
                thresholds: ContainmentThresholds::default(),
                operation_count: 0,
                decisions: Vec::new(),
            }),
        }
    }

    pub fn summary(&self) -> GuardplaneExecutionSummary {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let last = state.decisions.last();
        GuardplaneExecutionSummary {
            decision_count: state.decisions.len(),
            last_action: last.map(|decision| decision.action.clone()),
            last_selected_action: last.map(|decision| decision.selected_action),
            last_threshold_action: last.map(|decision| decision.threshold_action),
            last_expected_loss_millionths: last.map(|decision| decision.expected_loss_millionths),
            last_posterior_delta_millionths: last
                .map(|decision| decision.posterior_delta_millionths),
            last_log_likelihood_ratio_millionths: last
                .map(|decision| decision.log_likelihood_ratio_millionths),
            last_posterior: last.map(|decision| decision.posterior.clone()),
            last_risk_state: last.map(|decision| decision.risk_state),
        }
    }

    pub fn decision_records(&self) -> Vec<GuardplaneDecisionRecord> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .decisions
            .clone()
    }

    pub fn diagnostic_records(&self) -> &[GuardplaneDiagnosticRecord] {
        &self.context.diagnostics
    }

    fn evaluate_operation(
        &self,
        hook_context: &HookContext,
        operation: GuardplaneOperation,
    ) -> HookAction {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.operation_count = state.operation_count.saturating_add(1);

        let evidence = self.build_evidence(&operation, state.operation_count);
        let update = state.updater.update(&evidence);
        let decision = state.selector.select(&update.posterior);
        let posterior_delta_millionths = posterior_delta(&update.posterior);
        let threshold_action = state.thresholds.evaluate(posterior_delta_millionths);
        let action = hook_action_from_decisions(
            &operation,
            decision.action,
            threshold_action,
            &update.posterior,
            posterior_delta_millionths,
        );

        state.decisions.push(GuardplaneDecisionRecord {
            hook_context: hook_context.clone(),
            operation,
            posterior: update.posterior.clone(),
            risk_state: update.posterior.map_estimate(),
            posterior_delta_millionths,
            log_likelihood_ratio_millionths: update.cumulative_llr_millionths,
            selected_action: decision.action,
            threshold_action,
            action: action.clone(),
            expected_loss_millionths: decision.expected_loss_millionths,
        });

        action
    }

    fn build_evidence(&self, operation: &GuardplaneOperation, operation_index: u64) -> Evidence {
        let suspicion_millionths = operation.suspicion_millionths();
        let trust_penalty_millionths = self.context.trust_level.risk_penalty_millionths();
        let confidence_penalty_millionths = if self.context.witness_declared() {
            (WITNESS_CONFIDENCE_FLOOR_MILLIONTHS - self.context.witness_confidence_millionths)
                .max(0)
        } else {
            0
        };
        let capability_penalty_millionths =
            self.capability_penalty_millionths(operation.capability_label());

        let resource_score_millionths = (suspicion_millionths / 2
            + trust_penalty_millionths / 3
            + confidence_penalty_millionths / 4
            + capability_penalty_millionths / 3)
            .clamp(0, MILLION);
        let timing_anomaly_millionths =
            (suspicion_millionths + confidence_penalty_millionths / 2).clamp(0, MILLION);
        let denial_rate_millionths = (capability_penalty_millionths
            + trust_penalty_millionths / 2
            + suspicion_millionths / 4)
            .clamp(0, MILLION);

        Evidence {
            extension_id: self.context.extension_id.clone(),
            hostcall_rate_millionths: operation.rate_millionths(operation_index),
            distinct_capabilities: self.context.distinct_capability_count(),
            resource_score_millionths,
            timing_anomaly_millionths,
            denial_rate_millionths,
            epoch: self.epoch,
        }
    }

    fn capability_penalty_millionths(&self, capability_label: &str) -> i64 {
        if !self.context.witness_declared() {
            return 0;
        }
        if self.context.denied_capabilities.contains(capability_label) {
            return 900_000;
        }
        if !self.context.required_capabilities.is_empty()
            && !self
                .context
                .required_capabilities
                .contains(capability_label)
        {
            return 450_000;
        }
        0
    }
}

impl InterpreterHook for GuardplaneAdapter {
    fn pre_property_access(
        &self,
        ctx: &HookContext,
        _target: &ObjectRef,
        key: &PropertyKey,
    ) -> HookAction {
        self.evaluate_operation(
            ctx,
            GuardplaneOperation::PropertyAccess { key: key.clone() },
        )
    }

    fn pre_call(&self, ctx: &HookContext, callee: &FunctionRef, args: &[Value]) -> HookAction {
        let callee_name = match callee {
            FunctionRef::Function { name, .. } | FunctionRef::Closure { name, .. } => name.clone(),
        };
        self.evaluate_operation(
            ctx,
            GuardplaneOperation::Call {
                callee_name,
                arg_count: args.len(),
            },
        )
    }

    fn pre_allocation(&self, ctx: &HookContext, kind: AllocKind, size_hint: usize) -> HookAction {
        self.evaluate_operation(ctx, GuardplaneOperation::Allocation { kind, size_hint })
    }

    fn pre_import(&self, ctx: &HookContext, specifier: &str) -> HookAction {
        self.evaluate_operation(
            ctx,
            GuardplaneOperation::Import {
                specifier: specifier.to_string(),
            },
        )
    }
}

fn metadata_lookup<'a>(metadata: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| metadata.get(*key).map(String::as_str))
}

fn parse_capability_csv(raw: &str) -> BTreeSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_boolish(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn posterior_delta(posterior: &Posterior) -> i64 {
    (posterior.p_malicious + posterior.p_anomalous / 2 + posterior.p_unknown / 4).clamp(0, MILLION)
}

fn selector_action_rank(action: SelectorContainmentAction) -> u8 {
    match action {
        SelectorContainmentAction::Allow => 0,
        SelectorContainmentAction::Challenge => 1,
        SelectorContainmentAction::Sandbox => 2,
        SelectorContainmentAction::Suspend => 3,
        SelectorContainmentAction::Terminate => 4,
        SelectorContainmentAction::Quarantine => 5,
    }
}

fn threshold_action_to_selector(action: ThresholdContainmentAction) -> SelectorContainmentAction {
    match action {
        ThresholdContainmentAction::Allow => SelectorContainmentAction::Allow,
        ThresholdContainmentAction::Sandbox => SelectorContainmentAction::Sandbox,
        ThresholdContainmentAction::Suspend => SelectorContainmentAction::Suspend,
        ThresholdContainmentAction::Terminate => SelectorContainmentAction::Terminate,
        ThresholdContainmentAction::Quarantine => SelectorContainmentAction::Quarantine,
    }
}

fn hook_action_from_decisions(
    operation: &GuardplaneOperation,
    selected_action: SelectorContainmentAction,
    threshold_action: ThresholdContainmentAction,
    posterior: &Posterior,
    posterior_delta_millionths: i64,
) -> HookAction {
    let threshold_as_selector = threshold_action_to_selector(threshold_action);
    let effective_action =
        if selector_action_rank(threshold_as_selector) > selector_action_rank(selected_action) {
            threshold_as_selector
        } else {
            selected_action
        };

    match effective_action {
        SelectorContainmentAction::Allow => HookAction::Allow,
        SelectorContainmentAction::Challenge => HookAction::Challenge(ChallengeToken {
            token: format!(
                "guardplane:{}:{}:{}",
                operation.label(),
                posterior.p_malicious,
                posterior_delta_millionths
            ),
        }),
        SelectorContainmentAction::Sandbox => HookAction::Sandbox,
        SelectorContainmentAction::Suspend => HookAction::Suspend,
        SelectorContainmentAction::Terminate => HookAction::Terminate(format!(
            "guardplane {} denied (malicious={}, delta={})",
            operation.label(),
            posterior.p_malicious,
            posterior_delta_millionths
        )),
        SelectorContainmentAction::Quarantine => HookAction::Quarantine(format!(
            "guardplane {} quarantined (malicious={}, delta={})",
            operation.label(),
            posterior.p_malicious,
            posterior_delta_millionths
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::baseline_interpreter::ObjectId;

    fn test_hook_context(instruction_count: u64) -> HookContext {
        HookContext {
            extension_id: "ext:test".to_string(),
            instruction_count,
            current_ip: instruction_count.saturating_sub(1) as usize,
        }
    }

    fn context_with_metadata(meta: &[(&str, &str)]) -> GuardplaneExtensionContext {
        let metadata = meta
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<BTreeMap<_, _>>();
        GuardplaneExtensionContext::new("ext:test", BTreeSet::new(), metadata)
    }

    fn adapter_with_metadata(meta: &[(&str, &str)]) -> GuardplaneAdapter {
        GuardplaneAdapter::from_runtime_config(
            context_with_metadata(meta),
            LossMatrix::balanced(),
            &RuntimeConfig::default(),
            SecurityEpoch::from_raw(1),
        )
    }

    #[test]
    fn low_risk_allows() {
        let adapter = adapter_with_metadata(&[
            ("guardplane.enable_instruction_hooks", "true"),
            ("capability_witness.trust_level", "trusted"),
            ("capability_witness.confidence_millionths", "990000"),
        ]);

        let action =
            adapter.pre_property_access(&test_hook_context(1), &ObjectId(7), &"value".to_string());

        assert_eq!(action, HookAction::Allow);
        let summary = adapter.summary();
        assert_eq!(summary.decision_count, 1);
        assert_eq!(summary.last_action, Some(HookAction::Allow));
    }

    #[test]
    fn high_risk_escalates_after_repeated_suspicious_operations() {
        let adapter = adapter_with_metadata(&[
            ("guardplane.enable_instruction_hooks", "true"),
            ("capability_witness.trust_level", "suspicious"),
            ("capability_witness.confidence_millionths", "200000"),
            ("capability_witness.denied_capabilities", "module.import"),
        ]);

        let mut final_action = HookAction::Allow;
        for i in 0..8 {
            final_action = adapter.pre_import(&test_hook_context(i + 1), "node:child_process");
            if matches!(
                final_action,
                HookAction::Suspend | HookAction::Terminate(_) | HookAction::Quarantine(_)
            ) {
                break;
            }
        }

        assert!(matches!(
            final_action,
            HookAction::Suspend | HookAction::Terminate(_) | HookAction::Quarantine(_)
        ));
        let summary = adapter.summary();
        assert!(summary.last_posterior_delta_millionths.unwrap() >= 500_000);
    }

    #[test]
    fn threshold_mapping_surfaces_in_decision_records() {
        let adapter = adapter_with_metadata(&[
            ("guardplane.enable_instruction_hooks", "true"),
            ("capability_witness.trust_level", "untrusted"),
            ("capability_witness.confidence_millionths", "250000"),
            ("capability_witness.denied_capabilities", "module.import"),
        ]);

        let _ = adapter.pre_import(&test_hook_context(1), "node:fs");
        let records = adapter.decision_records();
        let last = records.last().expect("decision should be recorded");
        assert_ne!(last.threshold_action, ThresholdContainmentAction::Allow);
    }

    #[test]
    fn risk_accumulation_increases_with_repeated_operations() {
        let one = adapter_with_metadata(&[
            ("guardplane.enable_instruction_hooks", "true"),
            ("capability_witness.trust_level", "development"),
            ("capability_witness.confidence_millionths", "700000"),
        ]);
        let ten = adapter_with_metadata(&[
            ("guardplane.enable_instruction_hooks", "true"),
            ("capability_witness.trust_level", "development"),
            ("capability_witness.confidence_millionths", "700000"),
        ]);

        let _ = one.pre_property_access(&test_hook_context(1), &ObjectId(1), &"value".to_string());
        for i in 0..10 {
            let _ = ten.pre_property_access(
                &test_hook_context(i + 1),
                &ObjectId(1),
                &"value".to_string(),
            );
        }

        let one_delta = one
            .summary()
            .last_posterior_delta_millionths
            .expect("single op delta");
        let ten_delta = ten
            .summary()
            .last_posterior_delta_millionths
            .expect("repeated op delta");
        assert!(
            ten_delta > one_delta,
            "{ten_delta} should exceed {one_delta}"
        );
    }

    #[test]
    fn metadata_presence_enables_instruction_hooks() {
        let disabled = context_with_metadata(&[]);
        assert!(!disabled.instruction_hooks_enabled());

        let trusted = context_with_metadata(&[("capability_witness.trust_level", "signed")]);
        assert!(!trusted.instruction_hooks_enabled());

        let suspicious = context_with_metadata(&[("capability_witness.trust_level", "suspicious")]);
        assert!(suspicious.instruction_hooks_enabled());

        let explicit = context_with_metadata(&[
            ("guardplane.enable_instruction_hooks", "true"),
            ("capability_witness.trust_level", "signed"),
        ]);
        assert!(explicit.instruction_hooks_enabled());
    }
}
