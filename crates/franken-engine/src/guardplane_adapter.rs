//! Instruction-level Probabilistic Guardplane adapter.
//!
//! This module bridges the baseline interpreter hook surface to the existing
//! Bayesian posterior updater, expected-loss selector, and containment
//! threshold policy. The adapter is intentionally metadata-driven for now:
//! execution packages do not yet carry a first-class capability-witness object,
//! so the hook layer reads witness summaries from package metadata using
//! `capability_witness.*` / `guardplane.*` keys.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::baseline_interpreter::{
    AllocKind, ChallengeToken, FunctionRef, HookAction, HookContext, HookPropertyKey,
    HookPropertyKeyCompatibilityError, InterpreterHook, ObjectRef, PropertyKey, Value,
};
use crate::bayesian_posterior::{BayesianPosteriorUpdater, Evidence, Posterior, RiskState};
use crate::eprocess_guardrail::{
    EProcessGuardrail, ExpectedLossMatrix, GuardrailRegistry, ThresholdLikelihoodRatio,
};
use crate::expected_loss_selector::{
    ContainmentAction as SelectorContainmentAction, ExpectedLossSelector, LossMatrix,
};
use crate::fleet_convergence::ContainmentThresholds;
use crate::fleet_immune_protocol::ContainmentAction as ThresholdContainmentAction;
use crate::martingale_decision_ledger::StoppingThreshold;
use crate::runtime_config::RuntimeConfig;
use crate::security_epoch::SecurityEpoch;

const MILLION: i64 = 1_000_000;
const UNIFIED_ACTION_BLOCK_THRESHOLD_MILLIONTHS: i64 = 800_000;
const WITNESS_CONFIDENCE_FLOOR_MILLIONTHS: i64 = 900_000;
/// Operations at or above this suspicion are security-relevant; only they feed
/// the burst-rate signal (bd-9vouw.60). Ordinary allocations, calls, and
/// property reads are not a burst no matter how many a program performs.
const SUSPICIOUS_OPERATION_FLOOR_MILLIONTHS: i64 = 500_000;
const TRUST_LEVEL_METADATA_KEYS: &[&str] = &[
    "capability_witness.trust_level",
    "guardplane.trust_level",
    "trust_level",
];

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
    fn parse_with_status(raw: &str) -> (Self, bool) {
        match raw.trim().to_ascii_lowercase().as_str() {
            "trusted" | "signed" | "signed_supply_chain" => (Self::Trusted, true),
            "established" => (Self::Established, true),
            "provisional" | "development" => (Self::Provisional, true),
            "unknown" => (Self::Unknown, true),
            "unsigned" => (Self::Suspicious, true),
            "suspicious" | "untrusted" => (Self::Suspicious, true),
            "compromised" => (Self::Compromised, true),
            "revoked" => (Self::Revoked, true),
            _ => (Self::Unknown, false),
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
pub struct GuardplaneDiagnosticRecord {
    pub code: String,
    pub metadata_key: String,
    pub metadata_value: String,
    pub message: String,
}

impl GuardplaneDiagnosticRecord {
    fn metadata_parse_error(key: &str, value: &str, message: &str) -> Self {
        Self {
            code: "guardplane.metadata_parse_error".to_string(),
            metadata_key: key.to_string(),
            metadata_value: value.to_string(),
            message: message.to_string(),
        }
    }

    fn metadata_clamped(key: &str, value: &str, message: &str) -> Self {
        Self {
            code: "guardplane.metadata_clamped".to_string(),
            metadata_key: key.to_string(),
            metadata_value: value.to_string(),
            message: message.to_string(),
        }
    }

    fn state_lock_poisoned(operation: &str) -> Self {
        Self {
            code: "guardplane.state_lock_poisoned".to_string(),
            metadata_key: "operation".to_string(),
            metadata_value: operation.to_string(),
            message: "guardplane adapter state lock was poisoned; recovered inner state"
                .to_string(),
        }
    }

    fn guardrail_update_failed(detail: &str) -> Self {
        Self {
            code: "guardplane.guardrail_update_failed".to_string(),
            metadata_key: "guardrail_errors".to_string(),
            metadata_value: detail.to_string(),
            message: "unified guardrail update failed; operation was contained".to_string(),
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
    /// Whether the metadata declared a witness confidence at all. A missing
    /// confidence is not a zero confidence (bd-9vouw.60).
    #[serde(default)]
    pub witness_confidence_declared: bool,
    pub required_capabilities: BTreeSet<String>,
    pub denied_capabilities: BTreeSet<String>,
    pub diagnostics: Vec<GuardplaneDiagnosticRecord>,
}

impl GuardplaneExtensionContext {
    pub fn new(
        extension_id: impl Into<String>,
        declared_capabilities: BTreeSet<String>,
        metadata: BTreeMap<String, String>,
    ) -> Self {
        let mut diagnostics = Vec::new();

        let trust_level = metadata_lookup_with_key(&metadata, TRUST_LEVEL_METADATA_KEYS)
            .map(|(key, value)| {
                let (level, parsed) = GuardplaneTrustLevel::parse_with_status(value);
                if !parsed {
                    diagnostics.push(GuardplaneDiagnosticRecord::metadata_parse_error(
                        key,
                        value,
                        "failed to parse trust level",
                    ));
                }
                level
            })
            .unwrap_or(GuardplaneTrustLevel::Unknown);

        let declared_witness_confidence = metadata_lookup_with_key(
            &metadata,
            &[
                "capability_witness.confidence_millionths",
                "guardplane.witness_confidence_millionths",
            ],
        )
        .map(|(key, value)| match value.parse::<i64>() {
            Ok(parsed) => {
                let clamped = parsed.clamp(0, MILLION);
                if clamped != parsed {
                    diagnostics.push(GuardplaneDiagnosticRecord::metadata_clamped(
                        key,
                        value,
                        "clamped witness confidence to [0, 1000000]",
                    ));
                }
                clamped
            }
            Err(_) => {
                diagnostics.push(GuardplaneDiagnosticRecord::metadata_parse_error(
                    key,
                    value,
                    "failed to parse witness confidence",
                ));
                // Fail closed: a malformed confidence counts as declared
                // with zero confidence, not as absent.
                0
            }
        });
        let witness_confidence_declared = declared_witness_confidence.is_some();
        let witness_confidence_millionths = declared_witness_confidence.unwrap_or(0);

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
            witness_confidence_declared,
            required_capabilities,
            denied_capabilities,
            diagnostics,
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
            || self.monitoring_witness_declared()
            || self.malformed_trust_metadata_declared()
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

    fn monitoring_witness_declared(&self) -> bool {
        !self.required_capabilities.is_empty() || !self.denied_capabilities.is_empty()
    }

    fn malformed_trust_metadata_declared(&self) -> bool {
        self.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "guardplane.metadata_parse_error"
                && TRUST_LEVEL_METADATA_KEYS.contains(&diagnostic.metadata_key.as_str())
        })
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
    /// A Symbol-keyed property access (`obj[Symbol.iterator]`, spread,
    /// destructuring). Recorded by symbol identity so it never reads as a
    /// string key (bd-9vouw.60: the string-only hook refused these and
    /// stopped benign destructuring).
    SymbolPropertyAccess {
        symbol_id: u32,
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
    Hostcall {
        capability: String,
        allowed: bool,
    },
}

impl GuardplaneOperation {
    fn capability_label(&self) -> &str {
        match self {
            Self::PropertyAccess { .. } | Self::SymbolPropertyAccess { .. } => "object.property",
            Self::Call { .. } => "function.call",
            Self::Allocation { kind, .. } => match kind {
                AllocKind::Object => "alloc.object",
                AllocKind::Array => "alloc.array",
                AllocKind::Function => "alloc.function",
                AllocKind::Closure => "alloc.closure",
                AllocKind::RegExp => "alloc.regexp",
            },
            Self::Import { .. } => "module.import",
            Self::Hostcall { capability, .. } => capability,
        }
    }

    fn suspicion_millionths(&self) -> i64 {
        match self {
            Self::PropertyAccess { key } => match key.as_str() {
                "__proto__" => 850_000,
                // Ubiquitous in benign code (`Array.prototype.slice.call`,
                // `x.constructor === Array`); the escape that abuses them
                // (`constructor.constructor(src)()`) is caught at its
                // Function-constructor call (bd-9vouw.60).
                "prototype" | "constructor" => 300_000,
                "globalThis" | "process" | "require" | "module" => 700_000,
                _ if key.starts_with('_') => 200_000,
                _ => 75_000,
            },
            Self::SymbolPropertyAccess { .. } => 75_000,
            Self::Call {
                callee_name,
                arg_count,
            } => {
                // Match the called function's own name exactly: substring
                // matching flagged benign names such as `retrieval` or
                // `evaluateRow` as eval (bd-9vouw.60).
                let base: i64 = match callee_name.as_deref().map(callee_simple_name) {
                    Some("eval" | "Function" | "GeneratorFunction" | "AsyncFunction") => 900_000,
                    Some("constructor") => 700_000,
                    Some(_) => 125_000,
                    None => 250_000,
                };
                base.saturating_add(
                    i64::try_from(*arg_count)
                        .unwrap_or(i64::MAX)
                        .saturating_mul(20_000),
                )
                .clamp(0, MILLION)
            }
            Self::Allocation { kind, size_hint } => {
                let base: i64 = match kind {
                    AllocKind::Object => 80_000,
                    AllocKind::Array => 100_000,
                    AllocKind::Function => 175_000,
                    AllocKind::Closure => 300_000,
                    AllocKind::RegExp => 250_000,
                };
                // Size matters only at scale: a 40-element literal is not an
                // anomaly, a million-element allocation is (bd-9vouw.60).
                let size_penalty = i64::try_from(*size_hint)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000);
                base.saturating_add(size_penalty).clamp(0, MILLION)
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
            // Possessing authority is not evidence of abuse. A real denied
            // attempt is evidence, regardless of the spelling of its tag.
            Self::Hostcall { allowed, .. } => {
                if *allowed {
                    0
                } else {
                    MILLION
                }
            }
        }
    }

    /// Deterministic rate proxy. `suspicious_index` counts security-relevant
    /// operations so far (0 for an ordinary operation): the burst penalty
    /// grows only with repeated suspicious operations, never with the
    /// program's ordinary work (bd-9vouw.60).
    fn rate_millionths(&self, suspicious_index: u64) -> i64 {
        let base: i64 = match self {
            Self::PropertyAccess { .. } | Self::SymbolPropertyAccess { .. } => 40_000_000,
            Self::Call { .. } => 65_000_000,
            Self::Allocation { .. } => 55_000_000,
            // Relative imports are ordinary; a suspicious specifier carries
            // its own signal through `suspicion_millionths`.
            Self::Import { .. } => 60_000_000,
            Self::Hostcall { .. } => 60_000_000,
        };
        let burst_penalty = i64::try_from(suspicious_index.saturating_sub(1))
            .unwrap_or(i64::MAX)
            .saturating_mul(25_000_000);
        base.saturating_add(burst_penalty).clamp(0, 600_000_000)
    }

    fn label(&self) -> &'static str {
        match self {
            Self::PropertyAccess { .. } | Self::SymbolPropertyAccess { .. } => "property_access",
            Self::Call { .. } => "call",
            Self::Allocation { .. } => "allocation",
            Self::Import { .. } => "import",
            Self::Hostcall { .. } => "hostcall",
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
    // Legacy fields for backward compatibility during migration
    updater: BayesianPosteriorUpdater,
    selector: ExpectedLossSelector,
    // Unified substrate from AA.1/AA.2
    unified_guardrail_registry: GuardrailRegistry,
    thresholds: ContainmentThresholds,
    operation_count: u64,
    /// Operations at or above [`SUSPICIOUS_OPERATION_FLOOR_MILLIONTHS`].
    suspicious_operation_count: u64,
    decisions: Vec<GuardplaneDecisionRecord>,
    diagnostics: Vec<GuardplaneDiagnosticRecord>,
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
        // The extension's static context (trust level, declared witness
        // confidence, capability breadth) is ONE observation about the
        // extension, folded into the prior before any operation. Feeding it
        // into every hooked operation counted the same metadata as fresh
        // evidence each time (bd-9vouw.60).
        updater.update(&context_evidence(&context, epoch));
        let mut selector = ExpectedLossSelector::new(loss_matrix);
        selector.set_epoch(epoch);

        // Create unified guardrail registry with martingale substrate
        let mut unified_guardrail_registry = GuardrailRegistry::new();

        // Convert existing LossMatrix to ExpectedLossMatrix for unified substrate
        let mut action_losses = std::collections::BTreeMap::new();
        // LossMatrix doesn't have action_losses() method, use a default mapping
        action_losses.insert("Allow".to_string(), 0);
        action_losses.insert("Challenge".to_string(), 100_000);
        action_losses.insert("Sandbox".to_string(), 300_000);
        action_losses.insert("Suspend".to_string(), 500_000);
        action_losses.insert("Terminate".to_string(), 800_000);
        action_losses.insert("Quarantine".to_string(), 900_000);
        let expected_loss_matrix =
            ExpectedLossMatrix::new(action_losses, UNIFIED_ACTION_BLOCK_THRESHOLD_MILLIONTHS);

        // Create stopping threshold: log(1/0.05) ≈ 2.996 in millionths
        let stopping_threshold = StoppingThreshold::try_from_log_millionths(2_996_000)
            .unwrap_or_else(|_| StoppingThreshold::try_from_log_millionths(1_000_000).unwrap());

        // Create unified guardrail consuming martingale substrate
        let unified_guardrail = EProcessGuardrail::new(
            format!("unified-{}", context.extension_id),
            "guardplane-decisions",
            "unified guardplane decision substrate",
            stopping_threshold,
            expected_loss_matrix,
            epoch,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 500_000,    // 0.5 risk threshold
                high_ratio_millionths: 2_000_000, // 2.0 ratio when above threshold
                low_ratio_millionths: 500_000,    // 0.5 ratio when below threshold
            }),
        );
        unified_guardrail_registry.add(unified_guardrail);

        Self {
            context,
            epoch,
            state: Mutex::new(GuardplaneAdapterState {
                updater,
                selector,
                unified_guardrail_registry,
                thresholds: ContainmentThresholds::default(),
                operation_count: 0,
                suspicious_operation_count: 0,
                decisions: Vec::new(),
                diagnostics: Vec::new(),
            }),
        }
    }

    fn lock_state(&self, operation: &'static str) -> MutexGuard<'_, GuardplaneAdapterState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state
                    .diagnostics
                    .push(GuardplaneDiagnosticRecord::state_lock_poisoned(operation));
                state
            }
        }
    }

    pub fn summary(&self) -> GuardplaneExecutionSummary {
        let state = self.lock_state("summary");
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
        self.lock_state("decision_records").decisions.clone()
    }

    pub fn diagnostic_records(&self) -> Vec<GuardplaneDiagnosticRecord> {
        let mut diagnostics = self.context.diagnostics.clone();
        diagnostics.extend(self.lock_state("diagnostic_records").diagnostics.clone());
        diagnostics
    }

    fn evaluate_operation(
        &self,
        hook_context: &HookContext,
        operation: GuardplaneOperation,
    ) -> HookAction {
        let mut state = self.lock_state("evaluate_operation");
        state.operation_count = state.operation_count.saturating_add(1);
        let suspicious_index = if operation.suspicion_millionths()
            >= SUSPICIOUS_OPERATION_FLOOR_MILLIONTHS
        {
            state.suspicious_operation_count = state.suspicious_operation_count.saturating_add(1);
            state.suspicious_operation_count
        } else {
            0
        };
        let evidence = self.build_evidence(&operation, suspicious_index);

        // Legacy decision path (maintained for compatibility)
        let update = state.updater.update(&evidence);
        let decision = state.selector.select(&update.posterior);
        // An operation whose own evidence is neutral leaves the posterior
        // where it was. The expected-loss selector can still prefer Challenge
        // over Allow at an unchanged, uncertain posterior (the prior tax), and
        // every non-Allow hook action stops execution, so letting it act on
        // no evidence stopped benign programs at their first operation
        // (bd-9vouw.60). Such an operation is judged by the posterior
        // threshold policy alone: an extension whose posterior already sits
        // past a containment threshold is still contained.
        let operation_evidence_neutral = update.likelihoods.iter().all(|&l| l == MILLION);
        let posterior_delta_millionths = posterior_delta(&update.posterior);
        let threshold_action = state.thresholds.evaluate(posterior_delta_millionths);

        // Unified substrate decision path (AA.1/AA.2).
        let observation_millionths = (evidence.resource_score_millionths
            + evidence.timing_anomaly_millionths
            + evidence.denial_rate_millionths)
            / 3;

        // Update unified guardrail registry with observation
        let guardrail_errors = state
            .unified_guardrail_registry
            .update_stream("guardplane-decisions", observation_millionths);

        // A failed security-control update is not equivalent to a clean
        // observation. Record the failure and contain rather than silently
        // allowing the legacy path to decide alone.
        let unified_blocked_actions = state.unified_guardrail_registry.blocked_actions();
        let unified_action = if !guardrail_errors.is_empty() {
            let detail = guardrail_errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            state
                .diagnostics
                .push(GuardplaneDiagnosticRecord::guardrail_update_failed(&detail));
            HookAction::Terminate("unified guardrail update failed closed".to_string())
        } else if !unified_blocked_actions.is_empty() {
            HookAction::Terminate("unified guardrails triggered".to_string()) // Block if any unified guardrails triggered
        } else {
            HookAction::Allow
        };

        // Derive the legacy action, then combine it with the unified action by
        // containment severity so neither path can weaken the other.
        let effective_selector_action = if operation_evidence_neutral {
            SelectorContainmentAction::Allow
        } else {
            decision.action
        };
        let action = hook_action_from_decisions(
            &operation,
            effective_selector_action,
            threshold_action,
            &update.posterior,
            posterior_delta_millionths,
        );

        let final_action = stricter_hook_action(action, unified_action);

        state.decisions.push(GuardplaneDecisionRecord {
            hook_context: hook_context.clone(),
            operation,
            posterior: update.posterior.clone(),
            risk_state: update.posterior.map_estimate(),
            posterior_delta_millionths,
            log_likelihood_ratio_millionths: update.cumulative_llr_millionths,
            selected_action: decision.action,
            threshold_action,
            action: final_action.clone(), // Use combined decision from unified substrate
            expected_loss_millionths: decision.expected_loss_millionths,
        });

        final_action
    }

    /// Evidence for one hooked operation: its own suspicion, capability use,
    /// and the suspicious-operation burst rate. The static context is already
    /// in the prior (see [`context_evidence`]); capability breadth is static
    /// too, so per-operation evidence reports a neutral breadth of one.
    fn build_evidence(&self, operation: &GuardplaneOperation, suspicious_index: u64) -> Evidence {
        let suspicion_millionths = operation.suspicion_millionths();
        let capability_penalty_millionths = self.capability_penalty_millionths(operation);

        let resource_score_millionths =
            (suspicion_millionths / 2 + capability_penalty_millionths / 3).clamp(0, MILLION);
        let timing_anomaly_millionths = suspicion_millionths.clamp(0, MILLION);
        // Only a security-relevant operation adds its suspicion to the denial
        // channel. A quarter of ANY operation's suspicion used to land here,
        // and closures, RegExps and `prototype` reads (300k) crossed the 5%
        // benign denial ceiling, so benign programs were sandboxed within
        // their first statements (bd-9vouw.60). Below the floor an
        // operation's evidence is neutral on every channel.
        let suspicious_denial_millionths =
            if suspicion_millionths >= SUSPICIOUS_OPERATION_FLOOR_MILLIONTHS {
                suspicion_millionths / 4
            } else {
                0
            };
        let denial_rate_millionths =
            (capability_penalty_millionths + suspicious_denial_millionths).clamp(0, MILLION);

        Evidence {
            extension_id: self.context.extension_id.clone(),
            hostcall_rate_millionths: operation.rate_millionths(suspicious_index),
            distinct_capabilities: 1,
            resource_score_millionths,
            timing_anomaly_millionths,
            denial_rate_millionths,
            epoch: self.epoch,
        }
    }

    fn hostcall_is_witness_denied(&self, capability: &str) -> bool {
        if self.context.denied_capabilities.is_empty() {
            return false;
        }
        self.context.denied_capabilities.contains(capability)
            || crate::capability::hostcall_registry_row(capability)
                .and_then(|row| row.authority)
                .is_some_and(|authority| {
                    self.context
                        .denied_capabilities
                        .contains(&authority.to_string())
                })
    }

    fn capability_penalty_millionths(&self, operation: &GuardplaneOperation) -> i64 {
        if !self.context.witness_declared() {
            return 0;
        }
        let capability_label = operation.capability_label();
        // Only real hostcalls have an authenticated registry authority. Accept
        // both an exact operation tag (fs:write) and its authority (fs_write),
        // without reinterpreting property/callee/import witness heuristics.
        let denied = match operation {
            GuardplaneOperation::Hostcall { capability, .. } => {
                self.hostcall_is_witness_denied(capability)
            }
            _ => self.context.denied_capabilities.contains(capability_label),
        };
        if denied {
            return 900_000;
        }
        if is_runtime_capability_label(capability_label)
            && !self.context.required_capabilities.is_empty()
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

/// Trust penalty of an extension's static context. Confidence above 0.6
/// earns credit; confidence below it earns none (it used to go negative and
/// raise the penalty, bd-9vouw.60).
fn context_trust_penalty_millionths(context: &GuardplaneExtensionContext) -> i64 {
    let base = context.trust_level.risk_penalty_millionths();
    if !context.witness_declared() {
        return base;
    }
    let confidence_credit = context
        .witness_confidence_millionths
        .saturating_sub(600_000)
        .max(0);
    base.saturating_sub(confidence_credit).max(0)
}

/// Penalty for a DECLARED low witness confidence. A missing confidence is not
/// a zero confidence (bd-9vouw.60); a malformed one is recorded as declared
/// zero when the context is parsed.
fn context_confidence_penalty_millionths(context: &GuardplaneExtensionContext) -> i64 {
    if context.witness_confidence_declared {
        (WITNESS_CONFIDENCE_FLOOR_MILLIONTHS - context.witness_confidence_millionths).max(0)
    } else {
        0
    }
}

/// The extension's static context as a single observation, folded into the
/// guardplane prior once at construction (bd-9vouw.60). It carries the
/// channels the context used to add to every operation, and no operation
/// signal.
fn context_evidence(context: &GuardplaneExtensionContext, epoch: SecurityEpoch) -> Evidence {
    let trust_penalty_millionths = context_trust_penalty_millionths(context);
    let confidence_penalty_millionths = context_confidence_penalty_millionths(context);
    Evidence {
        extension_id: context.extension_id.clone(),
        hostcall_rate_millionths: 0,
        distinct_capabilities: context.distinct_capability_count(),
        resource_score_millionths: (trust_penalty_millionths / 3
            + confidence_penalty_millionths / 4)
            .clamp(0, MILLION),
        timing_anomaly_millionths: (confidence_penalty_millionths / 2).clamp(0, MILLION),
        denial_rate_millionths: (trust_penalty_millionths / 2).clamp(0, MILLION),
        epoch,
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

    /// Symbol keys are judged as their own operation (bd-9vouw.60): the
    /// default adapter refused them for this string-only hook, which failed
    /// every sandboxed program that spreads, destructures or iterates. A
    /// non-well-formed string key still takes the default fail-closed path.
    fn pre_property_access_typed(
        &self,
        ctx: &HookContext,
        target: &ObjectRef,
        key: &HookPropertyKey,
    ) -> Result<HookAction, HookPropertyKeyCompatibilityError> {
        match key {
            HookPropertyKey::Symbol(symbol) => Ok(self.evaluate_operation(
                ctx,
                GuardplaneOperation::SymbolPropertyAccess {
                    symbol_id: symbol.0,
                },
            )),
            HookPropertyKey::String(_) => {
                let legacy_key = key.to_legacy_property_key()?;
                Ok(self.pre_property_access(ctx, target, &legacy_key))
            }
        }
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

    fn pre_hostcall(&self, ctx: &HookContext, capability: &str, allowed: bool) -> HookAction {
        // Native guest computations have no external effect. Their ordinary
        // calls must not expand the risk transcript once per loop iteration.
        // Real denials and explicitly denied witness capabilities still reach
        // the adapter, including pure builtin calls. Witness declarations are
        // evidence only; they cannot turn the live `allowed` bit into a grant.
        if allowed
            && !self.hostcall_is_witness_denied(capability)
            && crate::capability::hostcall_registry_row(capability).is_some_and(|row| {
                matches!(
                    row.authority,
                    None | Some(crate::capability::RuntimeCapability::Builtin)
                )
            })
        {
            return HookAction::Allow;
        }
        self.evaluate_operation(
            ctx,
            GuardplaneOperation::Hostcall {
                capability: capability.to_string(),
                allowed,
            },
        )
    }
}

fn metadata_lookup<'a>(metadata: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| metadata.get(*key).map(String::as_str))
}

fn metadata_lookup_with_key<'a>(
    metadata: &'a BTreeMap<String, String>,
    keys: &[&'static str],
) -> Option<(&'static str, &'a str)> {
    keys.iter()
        .find_map(|key| metadata.get(*key).map(|value| (*key, value.as_str())))
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

/// Last segment of a possibly qualified callee name (`a.b.eval` -> `eval`).
fn callee_simple_name(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

fn is_runtime_capability_label(capability_label: &str) -> bool {
    matches!(capability_label, "module.import")
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

fn hook_action_rank(action: &HookAction) -> u8 {
    match action {
        HookAction::Allow => 0,
        HookAction::Challenge(_) => 1,
        HookAction::Sandbox => 2,
        HookAction::Suspend => 3,
        HookAction::Terminate(_) => 4,
        HookAction::Quarantine(_) => 5,
    }
}

fn stricter_hook_action(left: HookAction, right: HookAction) -> HookAction {
    if hook_action_rank(&left) >= hook_action_rank(&right) {
        left
    } else {
        right
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
    fn expected_loss_decisions_use_the_adapter_epoch() {
        let epoch = SecurityEpoch::from_raw(41);
        let adapter = GuardplaneAdapter::from_runtime_config(
            context_with_metadata(&[]),
            LossMatrix::balanced(),
            &RuntimeConfig::default(),
            epoch,
        );
        let decision = adapter
            .lock_state("test_expected_loss_epoch")
            .selector
            .select(&Posterior::default_prior());
        assert_eq!(decision.epoch, epoch);
        assert_eq!(
            adapter
                .lock_state("test_unified_guardrail_epoch")
                .unified_guardrail_registry
                .get("unified-ext:test")
                .expect("unified guardrail should be registered")
                .config_epoch(),
            epoch
        );
    }

    #[test]
    fn extreme_operation_sizes_saturate_guardplane_scores() {
        let call = GuardplaneOperation::Call {
            callee_name: None,
            arg_count: usize::MAX,
        };
        let allocation = GuardplaneOperation::Allocation {
            kind: AllocKind::Array,
            size_hint: usize::MAX,
        };

        assert_eq!(call.suspicion_millionths(), MILLION);
        assert_eq!(allocation.suspicion_millionths(), MILLION);
        assert_eq!(call.rate_millionths(u64::MAX), 600_000_000);
    }

    #[test]
    fn unified_guardrail_terminal_policy_has_reachable_blocked_actions() {
        let adapter = adapter_with_metadata(&[]);
        let mut state = adapter.lock_state("test_unified_terminal_policy");

        for _ in 0..5 {
            let errors = state
                .unified_guardrail_registry
                .update_stream("guardplane-decisions", MILLION);
            assert!(errors.is_empty(), "unexpected guardrail errors: {errors:?}");
        }

        assert_eq!(
            state.unified_guardrail_registry.blocked_actions(),
            BTreeSet::from(["Quarantine".to_string(), "Terminate".to_string()]),
            "a stopped unified guardrail must have a non-empty terminal policy"
        );
    }

    #[test]
    fn stricter_action_combination_never_downgrades_quarantine() {
        let quarantine = HookAction::Quarantine("quarantine evidence".to_string());
        let terminate = HookAction::Terminate("terminate evidence".to_string());

        assert_eq!(
            stricter_hook_action(quarantine.clone(), terminate.clone()),
            quarantine
        );
        assert_eq!(
            stricter_hook_action(terminate, quarantine.clone()),
            quarantine
        );
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
        // SAFETY: Test has processed observations that update posterior,
        // so last_posterior_delta_millionths field must be Some.
        assert!(
            summary
                .last_posterior_delta_millionths
                .expect("test fixture should have posterior delta")
                >= 500_000
        );
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
        // SAFETY: pre_import above records exactly one guardplane decision for this adapter.
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

        // Risk accumulates with repeated EVIDENCE. An ordinary read carries
        // none (bd-9vouw.60: re-counting static context per operation was the
        // defect), so the repeated operation is a suspicious one.
        let _ = one.pre_property_access(
            &test_hook_context(1),
            &ObjectId(1),
            &"__proto__".to_string(),
        );
        for i in 0..10 {
            let _ = ten.pre_property_access(
                &test_hook_context(i + 1),
                &ObjectId(1),
                &"__proto__".to_string(),
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

        let trusted_with_confidence = context_with_metadata(&[
            ("capability_witness.trust_level", "signed"),
            ("capability_witness.confidence_millionths", "995000"),
        ]);
        assert!(!trusted_with_confidence.instruction_hooks_enabled());

        let suspicious = context_with_metadata(&[("capability_witness.trust_level", "suspicious")]);
        assert!(suspicious.instruction_hooks_enabled());

        let explicit = context_with_metadata(&[
            ("guardplane.enable_instruction_hooks", "true"),
            ("capability_witness.trust_level", "signed"),
        ]);
        assert!(explicit.instruction_hooks_enabled());
    }

    #[test]
    fn missing_required_package_capability_does_not_penalize_internal_property_hook() {
        let adapter = adapter_with_metadata(&[
            ("guardplane.enable_instruction_hooks", "true"),
            ("capability_witness.trust_level", "trusted"),
            ("capability_witness.confidence_millionths", "990000"),
            (
                "capability_witness.required_capabilities",
                "module.import,network.fetch",
            ),
        ]);

        let action =
            adapter.pre_property_access(&test_hook_context(1), &ObjectId(7), &"value".to_string());

        assert_eq!(action, HookAction::Allow);
    }

    #[test]
    fn high_confidence_provisional_witness_offsets_provisional_trust_penalty() {
        let adapter = adapter_with_metadata(&[
            ("guardplane.enable_instruction_hooks", "true"),
            ("capability_witness.trust_level", "provisional"),
            ("capability_witness.confidence_millionths", "750000"),
            ("capability_witness.required_capabilities", "network.fetch"),
            ("capability_witness.denied_capabilities", "system.exec"),
        ]);

        let action =
            adapter.pre_property_access(&test_hook_context(1), &ObjectId(7), &"value".to_string());

        assert_eq!(action, HookAction::Allow);
    }

    #[test]
    fn malformed_guardplane_metadata_emits_diagnostics() {
        let context = context_with_metadata(&[
            ("capability_witness.trust_level", "mostly-trusted"),
            ("capability_witness.confidence_millionths", "high"),
        ]);

        assert_eq!(context.trust_level, GuardplaneTrustLevel::Unknown);
        assert_eq!(context.witness_confidence_millionths, 0);
        assert!(context.instruction_hooks_enabled());
        assert_eq!(context.diagnostics.len(), 2);
        assert!(context.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "guardplane.metadata_parse_error"
                && diagnostic.metadata_key == "capability_witness.trust_level"
        }));
        assert!(context.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "guardplane.metadata_parse_error"
                && diagnostic.metadata_key == "capability_witness.confidence_millionths"
        }));

        let adapter = GuardplaneAdapter::from_runtime_config(
            context.clone(),
            LossMatrix::balanced(),
            &RuntimeConfig::default(),
            SecurityEpoch::from_raw(1),
        );
        let adapter_diagnostics = adapter.diagnostic_records();
        assert_eq!(
            adapter_diagnostics.as_slice(),
            context.diagnostics.as_slice()
        );
    }

    #[test]
    fn out_of_range_guardplane_confidence_emits_clamp_diagnostic() {
        let context = context_with_metadata(&[
            ("capability_witness.trust_level", "trusted"),
            ("capability_witness.confidence_millionths", "1200000"),
        ]);

        assert_eq!(context.witness_confidence_millionths, MILLION);
        assert_eq!(context.diagnostics.len(), 1);
        assert_eq!(context.diagnostics[0].code, "guardplane.metadata_clamped");
        assert_eq!(
            context.diagnostics[0].metadata_key,
            "capability_witness.confidence_millionths"
        );
    }

    #[test]
    fn poisoned_guardplane_state_lock_emits_diagnostic() {
        let adapter = adapter_with_metadata(&[
            ("guardplane.enable_instruction_hooks", "true"),
            ("capability_witness.trust_level", "trusted"),
        ]);

        let poison_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _state = adapter
                .state
                .lock()
                .expect("state lock should be available");
            // SAFETY: Test-only panic to intentionally poison adapter state for recovery testing
            panic!("poison guardplane adapter state");
        }));
        assert!(poison_result.is_err());

        let _ = adapter.summary();
        let diagnostics = adapter.diagnostic_records();
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "guardplane.state_lock_poisoned"
                && diagnostic.metadata_value == "summary"
        }));
    }

    // -----------------------------------------------------------------------
    // Calibration (bd-9vouw.60): ordinary JavaScript must not read as attack
    // evidence; security-relevant operations must still escalate.
    // -----------------------------------------------------------------------

    /// The metadata `frankenctl agent-sandbox` derives for a manifest that
    /// grants file reads: hooks forced on, default `provisional` trust,
    /// required capabilities surfaced, no witness confidence declared.
    fn agent_sandbox_adapter() -> GuardplaneAdapter {
        adapter_with_metadata(&[
            ("guardplane.enable_instruction_hooks", "true"),
            ("guardplane.trust_level", "provisional"),
            (
                "capability_witness.required_capabilities",
                "fs_read,console,builtin,timer",
            ),
        ])
    }

    fn named_call(name: &str) -> FunctionRef {
        FunctionRef::Function {
            function_index: 1,
            name: Some(name.to_string()),
        }
    }

    /// One round of ordinary work: literals, closures, prototype-aware
    /// property reads, and named calls, including names that merely contain
    /// "eval".
    fn ordinary_round(adapter: &GuardplaneAdapter, step: u64) -> Vec<HookAction> {
        let ctx = test_hook_context(step);
        vec![
            adapter.pre_allocation(&ctx, AllocKind::Object, 4),
            adapter.pre_allocation(&ctx, AllocKind::Array, 40),
            adapter.pre_allocation(&ctx, AllocKind::Function, 0),
            adapter.pre_allocation(&ctx, AllocKind::Closure, 0),
            adapter.pre_allocation(&ctx, AllocKind::RegExp, 12),
            adapter.pre_property_access(&ctx, &ObjectId(3), &"prototype".to_string()),
            adapter.pre_property_access(&ctx, &ObjectId(3), &"constructor".to_string()),
            adapter.pre_property_access(&ctx, &ObjectId(3), &"length".to_string()),
            adapter.pre_call(&ctx, &named_call("map"), &[Value::Int(1), Value::Int(2)]),
            adapter.pre_call(&ctx, &named_call("retrieval"), &[]),
            adapter.pre_call(&ctx, &named_call("evaluateRow"), &[Value::Int(1)]),
        ]
    }

    #[test]
    fn ordinary_operation_stream_under_agent_sandbox_metadata_is_never_contained() {
        let adapter = agent_sandbox_adapter();
        for step in 1..=200 {
            for action in ordinary_round(&adapter, step) {
                assert!(
                    hook_action_rank(&action) < hook_action_rank(&HookAction::Suspend),
                    "ordinary operation contained at step {step}: {action:?}"
                );
            }
        }
        assert_eq!(adapter.summary().decision_count, 200 * 11);
    }

    #[test]
    fn symbol_keyed_access_is_judged_not_refused() {
        // The string-only default adapter refused Symbol keys, which failed
        // every sandboxed spread or destructuring. The guardplane judges them
        // as ordinary property reads and records the symbol identity.
        let adapter = agent_sandbox_adapter();
        let action = adapter
            .pre_property_access_typed(
                &test_hook_context(1),
                &ObjectId(3),
                &HookPropertyKey::Symbol(crate::object_model::SymbolId(7)),
            )
            .expect("a Symbol key is judged, not refused");
        assert_eq!(action, HookAction::Allow);
        assert_eq!(
            adapter.decision_records()[0].operation,
            GuardplaneOperation::SymbolPropertyAccess { symbol_id: 7 }
        );
        // A string key still takes the string path.
        adapter
            .pre_property_access_typed(
                &test_hook_context(2),
                &ObjectId(3),
                &HookPropertyKey::String(crate::js_string::JsString::from("__proto__")),
            )
            .expect("a well-formed string key is judged");
        assert_eq!(
            adapter.decision_records()[1].operation,
            GuardplaneOperation::PropertyAccess {
                key: "__proto__".to_string()
            }
        );
    }

    #[test]
    fn undeclared_module_import_is_escalated_after_ordinary_work() {
        // Positive control for the neutral-operation rule: the agent manifest
        // declares fs_read/console/builtin/timer, so a module import is an
        // undeclared capability use and carries evidence.
        let adapter = agent_sandbox_adapter();
        for step in 1..=20 {
            ordinary_round(&adapter, step);
        }
        let action = adapter.pre_import(&test_hook_context(21), "./lib/util.js");
        assert!(
            hook_action_rank(&action) >= hook_action_rank(&HookAction::Suspend),
            "undeclared import must be contained, got {action:?}"
        );
    }

    #[test]
    fn static_context_is_one_observation_not_per_operation_evidence() {
        let adapter = adapter_with_metadata(&[
            ("guardplane.enable_instruction_hooks", "true"),
            ("capability_witness.trust_level", "suspicious"),
            ("capability_witness.confidence_millionths", "150000"),
        ]);
        let ctx = test_hook_context(1);
        adapter.pre_property_access(&ctx, &ObjectId(1), &"value".to_string());
        let after_first = adapter
            .summary()
            .last_log_likelihood_ratio_millionths
            .expect("first decision recorded");
        for step in 2..=100 {
            adapter.pre_property_access(
                &test_hook_context(step),
                &ObjectId(1),
                &"value".to_string(),
            );
        }
        assert_eq!(
            adapter.summary().last_log_likelihood_ratio_millionths,
            Some(after_first),
            "ordinary reads after the first must not re-count the static context"
        );
    }

    #[test]
    fn missing_witness_confidence_is_not_zero_confidence() {
        let undeclared =
            context_with_metadata(&[("capability_witness.required_capabilities", "fs_read")]);
        assert!(!undeclared.witness_confidence_declared);
        let declared_zero = context_with_metadata(&[
            ("capability_witness.required_capabilities", "fs_read"),
            ("capability_witness.confidence_millionths", "0"),
        ]);
        assert!(declared_zero.witness_confidence_declared);
        // Malformed confidence fails closed as a declared zero, not absent.
        let malformed = context_with_metadata(&[
            ("capability_witness.required_capabilities", "fs_read"),
            ("capability_witness.confidence_millionths", "not-a-number"),
        ]);
        assert!(malformed.witness_confidence_declared);
        assert_eq!(malformed.witness_confidence_millionths, 0);

        let evidence_for = |context: GuardplaneExtensionContext| {
            context_evidence(&context, SecurityEpoch::from_raw(1))
        };
        let undeclared_evidence = evidence_for(undeclared);
        let declared_zero_evidence = evidence_for(declared_zero);
        assert!(
            undeclared_evidence.timing_anomaly_millionths
                < declared_zero_evidence.timing_anomaly_millionths,
            "only a declared low confidence may add confidence penalty"
        );
    }

    #[test]
    fn low_witness_confidence_earns_no_credit_and_no_extra_penalty() {
        for confidence in ["0", "300000", "600000"] {
            let adapter = adapter_with_metadata(&[
                ("capability_witness.trust_level", "provisional"),
                ("capability_witness.required_capabilities", "fs_read"),
                ("capability_witness.confidence_millionths", confidence),
            ]);
            assert_eq!(
                context_trust_penalty_millionths(&adapter.context),
                GuardplaneTrustLevel::Provisional.risk_penalty_millionths(),
                "confidence {confidence} must not raise the trust penalty"
            );
        }
        let confident = adapter_with_metadata(&[
            ("capability_witness.trust_level", "provisional"),
            ("capability_witness.required_capabilities", "fs_read"),
            ("capability_witness.confidence_millionths", "700000"),
        ]);
        assert!(
            context_trust_penalty_millionths(&confident.context)
                < GuardplaneTrustLevel::Provisional.risk_penalty_millionths()
        );
    }

    #[test]
    fn callee_names_match_exactly_not_by_substring() {
        let suspicion = |name: &str| {
            GuardplaneOperation::Call {
                callee_name: Some(name.to_string()),
                arg_count: 0,
            }
            .suspicion_millionths()
        };
        for benign in ["retrieval", "evaluateRow", "medieval", "constructorName"] {
            assert!(
                suspicion(benign) < SUSPICIOUS_OPERATION_FLOOR_MILLIONTHS,
                "{benign} is an ordinary function name"
            );
        }
        for dangerous in ["eval", "Function", "globalThis.eval", "AsyncFunction"] {
            assert!(
                suspicion(dangerous) >= SUSPICIOUS_OPERATION_FLOOR_MILLIONTHS,
                "{dangerous} must stay security-relevant"
            );
        }
    }

    #[test]
    fn dynamic_code_generation_is_contained_even_after_ordinary_work() {
        for name in ["Function", "eval"] {
            let adapter = agent_sandbox_adapter();
            for step in 1..=50 {
                ordinary_round(&adapter, step);
            }
            let action = adapter.pre_call(
                &test_hook_context(51),
                &named_call(name),
                &[Value::str("return this".to_string())],
            );
            assert!(
                hook_action_rank(&action) >= hook_action_rank(&HookAction::Suspend),
                "{name} code generation after ordinary work must be contained, got {action:?}"
            );
        }
    }

    #[test]
    fn prototype_pollution_access_is_contained_even_after_ordinary_work() {
        let adapter = agent_sandbox_adapter();
        for step in 1..=50 {
            ordinary_round(&adapter, step);
        }
        let action = adapter.pre_property_access(
            &test_hook_context(51),
            &ObjectId(9),
            &"__proto__".to_string(),
        );
        assert!(
            hook_action_rank(&action) >= hook_action_rank(&HookAction::Suspend),
            "__proto__ access must be contained, got {action:?}"
        );
    }

    #[test]
    fn repeated_suspicious_operations_still_raise_the_burst_rate() {
        let operation = GuardplaneOperation::Import {
            specifier: "node:child_process".to_string(),
        };
        assert!(operation.rate_millionths(5) > operation.rate_millionths(1));
        // An ordinary operation (suspicious index 0) never carries a burst.
        let ordinary = GuardplaneOperation::Allocation {
            kind: AllocKind::Object,
            size_hint: 1,
        };
        assert_eq!(ordinary.rate_millionths(0), ordinary.rate_millionths(1));
    }
}
