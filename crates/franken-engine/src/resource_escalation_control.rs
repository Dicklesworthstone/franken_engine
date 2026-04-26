#![forbid(unsafe_code)]

//! Resource Budget Escalation Control - unified API for throttle->sandbox->suspend->terminate
//!
//! Bead: bd-g61cl
//!
//! Provides a first-class deterministic API for resource exhaustion escalation
//! that drives the full sequence: throttle → sandbox → suspend → terminate
//! for one extension/workload and emits replay-stable artifacts/logs.
//!
//! This unifies the existing module capabilities:
//! - `queueing_admission_control`: throttle (queue/shed receipts)
//! - `resource_certificate_governance`: sandbox (over-budget governance receipts)
//! - `runtime_decision_theory`: suspend (suspend_adaptive on budget exhaust)
//! - NEW: terminate (deterministic termination with audit trail)
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for determinism.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::queueing_admission_control::AdmissionDecision;
use crate::resource_certificate_governance::{GovernanceVerdict, ResourceDimension};
use crate::runtime_decision_theory::{DecisionContext, LaneAction};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

pub const ESCALATION_SCHEMA_VERSION: &str = "franken-engine.resource-escalation-control.v1";
pub const ESCALATION_BEAD_ID: &str = "bd-g61cl";
const ESCALATION_STEP_INTERVAL_NS: u64 = 150_000_000;

/// Fixed-point millionths unit.
#[allow(dead_code)]
const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Escalation action
// ---------------------------------------------------------------------------

/// Resource escalation action in the throttle -> sandbox -> suspend -> terminate sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationAction {
    /// Throttle: queue/shed admission control.
    Throttle {
        /// Admission decision.
        decision: AdmissionDecision,
        /// Source rationale.
        rationale: String,
    },
    /// Sandbox: resource governance isolation.
    Sandbox {
        /// Governance verdict.
        verdict: GovernanceVerdict,
        /// Source rationale.
        rationale: String,
    },
    /// Suspend: adaptive execution suspension.
    Suspend {
        /// Lane action taken.
        action: LaneAction,
        /// Source rationale.
        rationale: String,
    },
    /// Terminate: final enforcement step.
    Terminate {
        /// Termination reason.
        reason: TerminationReason,
        /// Final resource measurements.
        final_measurements: BTreeMap<ResourceDimension, u64>,
        /// Source rationale.
        rationale: String,
    },
}

impl fmt::Display for EscalationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Throttle { .. } => write!(f, "throttle"),
            Self::Sandbox { .. } => write!(f, "sandbox"),
            Self::Suspend { .. } => write!(f, "suspend"),
            Self::Terminate { .. } => write!(f, "terminate"),
        }
    }
}

// ---------------------------------------------------------------------------
// Termination reason
// ---------------------------------------------------------------------------

/// Why a workload was terminated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    /// Persistent resource exhaustion despite escalation.
    PersistentExhaustion {
        /// Resource dimension that triggered termination.
        dimension: ResourceDimension,
        /// Utilization at termination (millionths).
        utilization_millionths: u64,
        /// Number of escalation attempts.
        escalation_attempts: u64,
    },
    /// Repeated governance violations.
    RepeatedViolations {
        /// Number of violations.
        violation_count: u64,
        /// Time span of violations in nanoseconds.
        violation_span_ns: u64,
    },
    /// Extension became unresponsive.
    Unresponsive {
        /// Timeout duration in nanoseconds.
        timeout_ns: u64,
    },
}

impl fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PersistentExhaustion { dimension, .. } => {
                write!(f, "persistent_exhaustion({})", dimension)
            }
            Self::RepeatedViolations {
                violation_count, ..
            } => {
                write!(f, "repeated_violations(count={})", violation_count)
            }
            Self::Unresponsive { timeout_ns } => {
                write!(f, "unresponsive(timeout_ns={})", timeout_ns)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Escalation event
// ---------------------------------------------------------------------------

/// Single event in the escalation sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationEvent {
    /// Timestamp in nanoseconds since epoch.
    pub timestamp_ns: u64,
    /// Escalation action taken.
    pub action: EscalationAction,
    /// Source module that generated this action.
    pub source_module: String,
    /// Additional context basis for the action.
    pub basis: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Escalation log
// ---------------------------------------------------------------------------

/// Complete escalation log for a workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationLog {
    /// Workload identifier.
    pub workload_id: String,
    /// Bounded resource dimensions.
    pub bounded_budget_dimensions: Vec<ResourceDimension>,
    /// Expected escalation sequence.
    pub expected_sequence: Vec<String>,
    /// Actual escalation events.
    pub events: Vec<EscalationEvent>,
    /// Content hash for replay stability.
    pub content_hash: ContentHash,
}

impl EscalationLog {
    /// Create a new escalation log.
    pub fn new(workload_id: String, bounded_budget_dimensions: Vec<ResourceDimension>) -> Self {
        let expected_sequence = vec![
            "throttle".to_string(),
            "sandbox".to_string(),
            "suspend".to_string(),
            "terminate".to_string(),
        ];

        let events = vec![];
        let content_hash = Self::compute_content_hash(
            &workload_id,
            &bounded_budget_dimensions,
            &expected_sequence,
            &events,
        );

        Self {
            workload_id,
            bounded_budget_dimensions,
            expected_sequence,
            events,
            content_hash,
        }
    }

    /// Add an escalation event.
    pub fn add_event(&mut self, event: EscalationEvent) {
        self.events.push(event);
        self.content_hash = Self::compute_content_hash(
            &self.workload_id,
            &self.bounded_budget_dimensions,
            &self.expected_sequence,
            &self.events,
        );
    }

    /// Check if the escalation sequence is complete.
    pub fn is_complete(&self) -> bool {
        if self.events.len() != self.expected_sequence.len() {
            return false;
        }

        let actual_sequence: Vec<String> =
            self.events.iter().map(|e| e.action.to_string()).collect();

        actual_sequence == self.expected_sequence
    }

    /// Verify the log has monotonic timestamps.
    pub fn has_monotonic_timestamps(&self) -> bool {
        self.events
            .windows(2)
            .all(|pair| pair[0].timestamp_ns <= pair[1].timestamp_ns)
    }

    /// Compute content hash for replay stability.
    ///
    /// Hashes every field that participates in the log's identity:
    /// `workload_id`, `bounded_budget_dimensions`, `expected_sequence`, and
    /// every event's full action + basis payload. Omitting any of these would
    /// let two logs with materially different contract surfaces collide on
    /// the same `content_hash`, defeating the replay-stability guarantee.
    /// Length-prefixed encoding prevents canonicalization ambiguity (e.g.
    /// concatenating two short strings vs. one long string).
    fn compute_content_hash(
        workload_id: &str,
        bounded_budget_dimensions: &[ResourceDimension],
        expected_sequence: &[String],
        events: &[EscalationEvent],
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update((workload_id.len() as u64).to_le_bytes());
        hasher.update(workload_id.as_bytes());

        let bounded_dim_bytes = serde_json::to_vec(bounded_budget_dimensions)
            .expect("ResourceDimension list should always serialize");
        hasher.update((bounded_dim_bytes.len() as u64).to_le_bytes());
        hasher.update(&bounded_dim_bytes);

        let expected_seq_bytes = serde_json::to_vec(expected_sequence)
            .expect("expected_sequence should always serialize");
        hasher.update((expected_seq_bytes.len() as u64).to_le_bytes());
        hasher.update(&expected_seq_bytes);

        hasher.update((events.len() as u64).to_le_bytes());
        for event in events {
            hasher.update(event.timestamp_ns.to_le_bytes());

            // Include full action payload, not just the variant name
            let action_json = serde_json::to_string(&event.action)
                .expect("EscalationAction should always serialize");
            hasher.update((action_json.len() as u64).to_le_bytes());
            hasher.update(action_json.as_bytes());

            hasher.update((event.source_module.len() as u64).to_le_bytes());
            hasher.update(event.source_module.as_bytes());

            // Include basis JSON for complete event context
            let basis_json = serde_json::to_string(&event.basis)
                .expect("serde_json::Value should always serialize");
            hasher.update((basis_json.len() as u64).to_le_bytes());
            hasher.update(basis_json.as_bytes());
        }

        let hash_bytes = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes);
        ContentHash::from_bytes(hash_array)
    }
}

/// Build a template `final_measurements` map keyed by the workload's
/// declared bounded dimensions. Each dimension is mapped to a representative
/// over-budget value chosen from a fixed table; unknown dimensions get a
/// nominal sentinel of 1. When `bounded` is empty, returns a single-entry
/// map keyed by `fallback` so audit consumers always observe a non-empty
/// final state.
fn template_final_measurements(
    bounded: &[ResourceDimension],
    fallback: ResourceDimension,
) -> BTreeMap<ResourceDimension, u64> {
    let mut measurements = BTreeMap::new();
    if bounded.is_empty() {
        measurements.insert(fallback, representative_overbudget(fallback));
        return measurements;
    }
    for dim in bounded {
        measurements.insert(*dim, representative_overbudget(*dim));
    }
    measurements
}

/// Representative over-budget value per dimension for the scripted template.
const fn representative_overbudget(dim: ResourceDimension) -> u64 {
    match dim {
        ResourceDimension::CpuTime => 125_000,
        ResourceDimension::WallTime => 125_000,
        ResourceDimension::HeapMemory => 80_000_000,
        ResourceDimension::StackDepth => 4_096,
        ResourceDimension::AllocationCount => 100_000,
        ResourceDimension::IoOperations => 10_000,
        ResourceDimension::NetworkBandwidth => 1_000_000_000,
        ResourceDimension::FileDescriptors => 1_024,
        ResourceDimension::GcPause => 100_000_000,
        ResourceDimension::InstructionCount => 1_000_000_000,
    }
}

// ---------------------------------------------------------------------------
// Resource escalation controller
// ---------------------------------------------------------------------------

/// Main controller for resource budget escalation.
#[derive(Debug, Clone)]
pub struct ResourceEscalationController {
    /// Security epoch.
    #[allow(dead_code)]
    epoch: SecurityEpoch,
    /// Decision context for runtime decisions.
    #[allow(dead_code)]
    decision_context: DecisionContext,
}

/// Error returned when constructing a [`ResourceEscalationController`] with
/// an `epoch` that does not match the policy bundle carried by the supplied
/// [`DecisionContext`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationEpochMismatch {
    /// Epoch supplied to the constructor.
    pub controller_epoch: SecurityEpoch,
    /// Epoch carried by the decision context's policy bundle.
    pub decision_context_epoch: SecurityEpoch,
}

impl fmt::Display for EscalationEpochMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "resource escalation controller epoch mismatch: controller_epoch={} decision_context_epoch={}",
            self.controller_epoch.as_u64(),
            self.decision_context_epoch.as_u64()
        )
    }
}

impl std::error::Error for EscalationEpochMismatch {}

impl ResourceEscalationController {
    /// Create a new escalation controller, validating that the controller's
    /// epoch matches the decision context's policy bundle epoch.
    ///
    /// Fails closed on mismatch: artifacts emitted by an escalation controller
    /// claim the controller's epoch in their `basis`, so a mismatch with the
    /// underlying decision context would produce evidence that misattributes
    /// which policy snapshot drove the escalation.
    pub fn try_new(
        epoch: SecurityEpoch,
        decision_context: DecisionContext,
    ) -> Result<Self, EscalationEpochMismatch> {
        let bundle_epoch = decision_context.policy_bundle().epoch;
        if bundle_epoch != epoch {
            return Err(EscalationEpochMismatch {
                controller_epoch: epoch,
                decision_context_epoch: bundle_epoch,
            });
        }
        Ok(Self {
            epoch,
            decision_context,
        })
    }

    /// Create a new escalation controller. Panics on epoch mismatch — see
    /// [`Self::try_new`] for the fallible variant.
    pub fn new(epoch: SecurityEpoch, decision_context: DecisionContext) -> Self {
        Self::try_new(epoch, decision_context)
            .expect("ResourceEscalationController epoch must match decision context epoch")
    }

    /// Emit a deterministic full-chain escalation template for a workload.
    ///
    /// This is a *scripted* throttle → sandbox → suspend → terminate sequence
    /// suitable for replay-stability tests, demos, and downstream artifact
    /// validation. It does NOT consume live admission, governance, or
    /// runtime-decision state — for production escalation flows driven by
    /// real subsystem signals, use the per-step `record_throttle`,
    /// `record_sandbox`, `record_suspend`, and `record_terminate` methods
    /// to assemble an `EscalationLog` from observed events.
    ///
    /// The emitted template:
    /// - Threads `self.epoch` into every event's `basis.policy_epoch` so
    ///   replay artifacts attribute the correct policy snapshot.
    /// - Picks the first entry of `bounded_dimensions` as the dimension
    ///   reported by `TerminationReason::PersistentExhaustion`, falling
    ///   back to `CpuTime` only when the caller declared no bounds. This
    ///   prevents audit-trail divergence between a workload's declared
    ///   bounds and the dimension the log claims was exhausted.
    /// - Builds `final_measurements` keyed by `bounded_dimensions` (each
    ///   mapped to a representative over-budget value) instead of always
    ///   the historical `{CpuTime, HeapMemory}` pair.
    /// - Uses saturating timestamp arithmetic so callers near `u64::MAX`
    ///   still get monotonic replay artifacts instead of overflow.
    pub fn execute_escalation(
        &mut self,
        workload_id: String,
        bounded_dimensions: Vec<ResourceDimension>,
        current_timestamp_ns: u64,
    ) -> EscalationLog {
        let primary_dimension = bounded_dimensions
            .first()
            .copied()
            .unwrap_or(ResourceDimension::CpuTime);
        let final_measurements =
            template_final_measurements(&bounded_dimensions, primary_dimension);
        let policy_epoch = self.epoch.as_u64();
        let sandbox_timestamp = current_timestamp_ns.saturating_add(ESCALATION_STEP_INTERVAL_NS);
        let suspend_timestamp = sandbox_timestamp.saturating_add(ESCALATION_STEP_INTERVAL_NS);
        let terminate_timestamp = suspend_timestamp.saturating_add(ESCALATION_STEP_INTERVAL_NS);

        let mut log = EscalationLog::new(workload_id, bounded_dimensions);

        // Step 1: Throttle (simulated queue decision)
        let throttle_event = EscalationEvent {
            timestamp_ns: current_timestamp_ns,
            action: EscalationAction::Throttle {
                decision: AdmissionDecision::Queue {
                    estimated_wait_ns: 150_000_000,
                    position: 3,
                },
                rationale:
                    "Queueing under sustained overload is the deterministic throttle boundary."
                        .to_string(),
            },
            source_module: "queueing_admission_control".to_string(),
            basis: serde_json::json!({
                "stage": "module_load",
                "admission_decision": "queue",
                "queue_position": 3,
                "utilization_millionths": 880_000,
                "policy_epoch": policy_epoch
            }),
        };
        log.add_event(throttle_event);

        // Step 2: Sandbox (simulated governance violation)
        let sandbox_event = EscalationEvent {
            timestamp_ns: sandbox_timestamp,
            action: EscalationAction::Sandbox {
                verdict: GovernanceVerdict::MultipleViolations,
                rationale: "Resource-governance failure is the point where the runtime should isolate the extension instead of only slowing it.".to_string(),
            },
            source_module: "resource_certificate_governance".to_string(),
            basis: serde_json::json!({
                "governance_verdict": "multiple_violations",
                "certificates": [
                    {
                        "dimension": "cpu_time",
                        "certified_budget": 100_000,
                        "measured_usage": 112_000,
                        "utilisation_millionths": 1_120_000
                    },
                    {
                        "dimension": "heap_memory",
                        "certified_budget": 67_108_864,
                        "measured_usage": 75_497_472,
                        "utilisation_millionths": 1_125_000
                    }
                ],
                "policy_epoch": policy_epoch
            }),
        };
        log.add_event(sandbox_event);

        // Step 3: Suspend (use actual decision context)
        let suspend_event = EscalationEvent {
            timestamp_ns: suspend_timestamp,
            action: EscalationAction::Suspend {
                action: LaneAction::SuspendAdaptive,
                rationale: "Budget exhaustion already has a direct deterministic suspend surface in DecisionContext.".to_string(),
            },
            source_module: "runtime_decision_theory".to_string(),
            basis: serde_json::json!({
                "lane_action": "suspend_adaptive",
                "demotion_reason": "budget_exhausted",
                "budget_remaining_millionths": 0,
                "policy_epoch": policy_epoch
            }),
        };
        log.add_event(suspend_event);

        // Step 4: Terminate — dimension and final_measurements derived from
        // the caller's declared bounded_dimensions instead of hardcoded
        // CpuTime/HeapMemory.
        let terminate_event = EscalationEvent {
            timestamp_ns: terminate_timestamp,
            action: EscalationAction::Terminate {
                reason: TerminationReason::PersistentExhaustion {
                    dimension: primary_dimension,
                    utilization_millionths: 1_250_000, // 125%
                    escalation_attempts: 3,
                },
                final_measurements,
                rationale: "Deterministic termination enforced after persistent resource exhaustion despite escalation attempts.".to_string(),
            },
            source_module: "resource_escalation_control".to_string(),
            basis: serde_json::json!({
                "termination_reason": "persistent_exhaustion",
                "escalation_sequence_completed": true,
                "final_resource_state": "over_budget",
                "primary_dimension": primary_dimension.to_string(),
                "policy_epoch": policy_epoch
            }),
        };
        log.add_event(terminate_event);

        log
    }

    /// Append a real throttle event to `log`. Use when escalation is being
    /// driven by an actual `queueing_admission_control` decision rather than
    /// by [`Self::execute_escalation`]'s scripted template.
    pub fn record_throttle(
        &self,
        log: &mut EscalationLog,
        timestamp_ns: u64,
        decision: AdmissionDecision,
        rationale: impl Into<String>,
    ) {
        log.add_event(EscalationEvent {
            timestamp_ns,
            action: EscalationAction::Throttle {
                decision,
                rationale: rationale.into(),
            },
            source_module: "queueing_admission_control".to_string(),
            basis: serde_json::json!({ "policy_epoch": self.epoch.as_u64() }),
        });
    }

    /// Append a real sandbox event to `log`.
    pub fn record_sandbox(
        &self,
        log: &mut EscalationLog,
        timestamp_ns: u64,
        verdict: GovernanceVerdict,
        rationale: impl Into<String>,
    ) {
        log.add_event(EscalationEvent {
            timestamp_ns,
            action: EscalationAction::Sandbox {
                verdict,
                rationale: rationale.into(),
            },
            source_module: "resource_certificate_governance".to_string(),
            basis: serde_json::json!({ "policy_epoch": self.epoch.as_u64() }),
        });
    }

    /// Append a real suspend event to `log`.
    pub fn record_suspend(
        &self,
        log: &mut EscalationLog,
        timestamp_ns: u64,
        action: LaneAction,
        rationale: impl Into<String>,
    ) {
        log.add_event(EscalationEvent {
            timestamp_ns,
            action: EscalationAction::Suspend {
                action,
                rationale: rationale.into(),
            },
            source_module: "runtime_decision_theory".to_string(),
            basis: serde_json::json!({ "policy_epoch": self.epoch.as_u64() }),
        });
    }

    /// Append a real terminate event to `log`. Supports early termination
    /// (sandbox- or suspend-resolved workloads that never need the full
    /// chain) and arbitrary `final_measurements` keyed by the dimensions
    /// the caller actually observed.
    pub fn record_terminate(
        &self,
        log: &mut EscalationLog,
        timestamp_ns: u64,
        reason: TerminationReason,
        final_measurements: BTreeMap<ResourceDimension, u64>,
        rationale: impl Into<String>,
    ) {
        log.add_event(EscalationEvent {
            timestamp_ns,
            action: EscalationAction::Terminate {
                reason,
                final_measurements,
                rationale: rationale.into(),
            },
            source_module: "resource_escalation_control".to_string(),
            basis: serde_json::json!({ "policy_epoch": self.epoch.as_u64() }),
        });
    }

    /// Terminate a workload immediately with given reason.
    pub fn terminate_workload(
        &self,
        workload_id: &str,
        reason: TerminationReason,
        timestamp_ns: u64,
    ) -> EscalationEvent {
        let final_measurements = BTreeMap::new(); // Empty for immediate termination

        EscalationEvent {
            timestamp_ns,
            action: EscalationAction::Terminate {
                reason,
                final_measurements,
                rationale: "Immediate termination requested.".to_string(),
            },
            source_module: "resource_escalation_control".to_string(),
            basis: serde_json::json!({
                "termination_type": "immediate",
                "workload_id": workload_id,
                "policy_epoch": self.epoch.as_u64()
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_decision_theory::DecisionContextConfig;

    #[test]
    fn test_escalation_log_creation() {
        let log = EscalationLog::new(
            "test-workload".to_string(),
            vec![ResourceDimension::CpuTime, ResourceDimension::HeapMemory],
        );

        assert_eq!(log.workload_id, "test-workload");
        assert_eq!(log.bounded_budget_dimensions.len(), 2);
        assert_eq!(log.expected_sequence.len(), 4);
        assert!(log.events.is_empty());
        assert!(!log.is_complete());
        assert!(log.has_monotonic_timestamps());
    }

    #[test]
    fn test_escalation_action_display() {
        let action = EscalationAction::Throttle {
            decision: AdmissionDecision::Queue {
                estimated_wait_ns: 1000,
                position: 1,
            },
            rationale: "Test".to_string(),
        };
        assert_eq!(action.to_string(), "throttle");

        let action = EscalationAction::Terminate {
            reason: TerminationReason::PersistentExhaustion {
                dimension: ResourceDimension::CpuTime,
                utilization_millionths: 1_200_000,
                escalation_attempts: 3,
            },
            final_measurements: BTreeMap::new(),
            rationale: "Test".to_string(),
        };
        assert_eq!(action.to_string(), "terminate");
    }

    #[test]
    fn test_escalation_controller_execution() {
        let epoch = SecurityEpoch::from_raw(1);
        let config = DecisionContextConfig::default();
        let decision_context = DecisionContext::new(config, epoch);
        let mut controller = ResourceEscalationController::new(epoch, decision_context);

        let log = controller.execute_escalation(
            "test-workload".to_string(),
            vec![ResourceDimension::CpuTime],
            1_000_000_000,
        );

        assert!(log.is_complete());
        assert!(log.has_monotonic_timestamps());
        assert_eq!(log.events.len(), 4);

        // Verify sequence
        assert!(matches!(
            log.events[0].action,
            EscalationAction::Throttle { .. }
        ));
        assert!(matches!(
            log.events[1].action,
            EscalationAction::Sandbox { .. }
        ));
        assert!(matches!(
            log.events[2].action,
            EscalationAction::Suspend { .. }
        ));
        assert!(matches!(
            log.events[3].action,
            EscalationAction::Terminate { .. }
        ));
    }

    #[test]
    fn test_termination_reason_display() {
        let reason = TerminationReason::PersistentExhaustion {
            dimension: ResourceDimension::CpuTime,
            utilization_millionths: 1_250_000,
            escalation_attempts: 3,
        };
        assert_eq!(reason.to_string(), "persistent_exhaustion(cpu_time)");

        let reason = TerminationReason::RepeatedViolations {
            violation_count: 5,
            violation_span_ns: 1_000_000_000,
        };
        assert_eq!(reason.to_string(), "repeated_violations(count=5)");
    }

    #[test]
    fn test_content_hash_stability() {
        let mut log1 = EscalationLog::new("test".to_string(), vec![]);
        let mut log2 = EscalationLog::new("test".to_string(), vec![]);

        let event = EscalationEvent {
            timestamp_ns: 1000,
            action: EscalationAction::Throttle {
                decision: AdmissionDecision::Queue {
                    estimated_wait_ns: 100,
                    position: 1,
                },
                rationale: "Test".to_string(),
            },
            source_module: "test_module".to_string(),
            basis: serde_json::json!({}),
        };

        log1.add_event(event.clone());
        log2.add_event(event);

        assert_eq!(log1.content_hash, log2.content_hash);
    }

    #[test]
    fn test_content_hash_distinguishes_different_payloads() {
        // Test that events with different payloads produce different content hashes
        let mut log1 = EscalationLog::new("test".to_string(), vec![]);
        let mut log2 = EscalationLog::new("test".to_string(), vec![]);
        let mut log3 = EscalationLog::new("test".to_string(), vec![]);

        let event1 = EscalationEvent {
            timestamp_ns: 1000,
            action: EscalationAction::Throttle {
                decision: AdmissionDecision::Queue {
                    estimated_wait_ns: 100,
                    position: 1,
                },
                rationale: "Test 1".to_string(),
            },
            source_module: "test_module".to_string(),
            basis: serde_json::json!({ "test": "value1" }),
        };

        let event2 = EscalationEvent {
            timestamp_ns: 1000, // Same timestamp
            action: EscalationAction::Throttle {
                decision: AdmissionDecision::Queue {
                    estimated_wait_ns: 200, // Different payload
                    position: 2,            // Different payload
                },
                rationale: "Test 2".to_string(), // Different rationale
            },
            source_module: "test_module".to_string(), // Same module
            basis: serde_json::json!({ "test": "value2" }), // Different basis
        };

        let event3 = EscalationEvent {
            timestamp_ns: 1000, // Same timestamp
            action: EscalationAction::Sandbox {
                verdict: GovernanceVerdict::Approved, // Different action variant
                rationale: "Test 3".to_string(),
            },
            source_module: "test_module".to_string(),
            basis: serde_json::json!({ "test": "value1" }), // Same basis as event1
        };

        log1.add_event(event1);
        log2.add_event(event2);
        log3.add_event(event3);

        // All three logs should have different content hashes despite similar timestamps/modules
        assert_ne!(
            log1.content_hash, log2.content_hash,
            "Events with different payloads should have different content hashes"
        );
        assert_ne!(
            log1.content_hash, log3.content_hash,
            "Events with different action variants should have different content hashes"
        );
        assert_ne!(
            log2.content_hash, log3.content_hash,
            "All events with different details should have unique content hashes"
        );
    }

    // bd-2kj2j: hash must cover bounded_budget_dimensions and the constructor
    // must validate epoch consistency.

    #[test]
    fn test_content_hash_distinguishes_bounded_dimensions() {
        let log_cpu = EscalationLog::new("wl".to_string(), vec![ResourceDimension::CpuTime]);
        let log_heap = EscalationLog::new("wl".to_string(), vec![ResourceDimension::HeapMemory]);
        let log_both = EscalationLog::new(
            "wl".to_string(),
            vec![ResourceDimension::CpuTime, ResourceDimension::HeapMemory],
        );

        assert_ne!(
            log_cpu.content_hash, log_heap.content_hash,
            "Different bounded dimensions must produce different content hashes"
        );
        assert_ne!(
            log_cpu.content_hash, log_both.content_hash,
            "Subset and superset bounded dimensions must produce different content hashes"
        );
        assert_ne!(log_heap.content_hash, log_both.content_hash);
    }

    #[test]
    fn test_content_hash_covers_expected_sequence() {
        // Build two logs with the same workload + dimensions but different
        // expected_sequence vectors. The constructor always emits the same
        // expected_sequence, so we mutate after construction.
        let dims = vec![ResourceDimension::CpuTime];
        let mut log_default = EscalationLog::new("wl".to_string(), dims.clone());
        let mut log_alt = EscalationLog::new("wl".to_string(), dims);
        log_alt.expected_sequence = vec!["throttle".to_string(), "terminate".to_string()];
        // Force re-hash via the public API (push then pop a sentinel event).
        let sentinel = EscalationEvent {
            timestamp_ns: 0,
            action: EscalationAction::Throttle {
                decision: AdmissionDecision::Queue {
                    estimated_wait_ns: 0,
                    position: 0,
                },
                rationale: String::new(),
            },
            source_module: "rehash".to_string(),
            basis: serde_json::Value::Null,
        };
        log_default.add_event(sentinel.clone());
        log_alt.add_event(sentinel);
        assert_ne!(
            log_default.content_hash, log_alt.content_hash,
            "Different expected_sequence must produce different content hashes"
        );
    }

    #[test]
    fn test_controller_try_new_rejects_epoch_mismatch() {
        let bundle_epoch = SecurityEpoch::from_raw(7);
        let controller_epoch = SecurityEpoch::from_raw(8);
        let config = DecisionContextConfig::default();
        let decision_context = DecisionContext::new(config, bundle_epoch);

        let err = ResourceEscalationController::try_new(controller_epoch, decision_context)
            .expect_err("mismatched epochs must fail closed");
        assert_eq!(err.controller_epoch, controller_epoch);
        assert_eq!(err.decision_context_epoch, bundle_epoch);
        assert!(err.to_string().contains("epoch mismatch"));
    }

    #[test]
    fn test_controller_try_new_accepts_matching_epoch() {
        let epoch = SecurityEpoch::from_raw(11);
        let config = DecisionContextConfig::default();
        let decision_context = DecisionContext::new(config, epoch);

        assert!(ResourceEscalationController::try_new(epoch, decision_context).is_ok());
    }

    #[test]
    #[should_panic(expected = "epoch must match decision context epoch")]
    fn test_controller_new_panics_on_epoch_mismatch() {
        let bundle_epoch = SecurityEpoch::from_raw(1);
        let controller_epoch = SecurityEpoch::from_raw(2);
        let config = DecisionContextConfig::default();
        let decision_context = DecisionContext::new(config, bundle_epoch);
        let _ = ResourceEscalationController::new(controller_epoch, decision_context);
    }

    // bd-3gc3v: execute_escalation must derive terminate.dimension and
    // final_measurements from bounded_dimensions, and must thread the
    // controller's epoch into every event's basis. Per-step record_*
    // methods support real (non-template) escalation flows including
    // early termination.

    fn fresh_controller(epoch_raw: u64) -> ResourceEscalationController {
        let epoch = SecurityEpoch::from_raw(epoch_raw);
        let config = DecisionContextConfig::default();
        let decision_context = DecisionContext::new(config, epoch);
        ResourceEscalationController::new(epoch, decision_context)
    }

    fn terminate_dimension(action: &EscalationAction) -> ResourceDimension {
        match action {
            EscalationAction::Terminate {
                reason: TerminationReason::PersistentExhaustion { dimension, .. },
                ..
            } => *dimension,
            other => panic!("expected PersistentExhaustion termination, got {other:?}"),
        }
    }

    fn terminate_measurements(action: &EscalationAction) -> &BTreeMap<ResourceDimension, u64> {
        match action {
            EscalationAction::Terminate {
                final_measurements, ..
            } => final_measurements,
            other => panic!("expected Terminate action, got {other:?}"),
        }
    }

    #[test]
    fn execute_escalation_derives_terminate_dimension_from_first_bounded() {
        let mut controller = fresh_controller(1);
        let log = controller.execute_escalation(
            "wl".to_string(),
            vec![ResourceDimension::AllocationCount],
            1_000,
        );
        let dim = terminate_dimension(&log.events[3].action);
        assert_eq!(
            dim,
            ResourceDimension::AllocationCount,
            "terminate.dimension must mirror the first bounded dimension"
        );
    }

    #[test]
    fn execute_escalation_keys_final_measurements_by_bounded_dimensions() {
        let mut controller = fresh_controller(1);
        let bounded = vec![
            ResourceDimension::IoOperations,
            ResourceDimension::FileDescriptors,
        ];
        let log = controller.execute_escalation("wl".to_string(), bounded.clone(), 0);
        let measurements = terminate_measurements(&log.events[3].action);
        assert_eq!(
            measurements.keys().copied().collect::<Vec<_>>(),
            bounded,
            "final_measurements keys must match bounded_dimensions exactly"
        );
        assert!(
            !measurements.contains_key(&ResourceDimension::CpuTime),
            "final_measurements must not silently include CpuTime when not bounded"
        );
        assert!(
            !measurements.contains_key(&ResourceDimension::HeapMemory),
            "final_measurements must not silently include HeapMemory when not bounded"
        );
    }

    #[test]
    fn execute_escalation_threads_policy_epoch_into_every_basis() {
        let mut controller = fresh_controller(42);
        let log =
            controller.execute_escalation("wl".to_string(), vec![ResourceDimension::CpuTime], 0);
        assert_eq!(log.events.len(), 4);
        for (idx, event) in log.events.iter().enumerate() {
            let policy_epoch = event
                .basis
                .get("policy_epoch")
                .unwrap_or_else(|| panic!("event {idx} basis missing policy_epoch"));
            assert_eq!(
                policy_epoch.as_u64(),
                Some(42),
                "event {idx} basis must carry the controller's epoch"
            );
        }
    }

    #[test]
    fn execute_escalation_falls_back_to_cpu_time_when_no_bounds_declared() {
        let mut controller = fresh_controller(1);
        let log = controller.execute_escalation("wl".to_string(), vec![], 0);
        assert_eq!(
            terminate_dimension(&log.events[3].action),
            ResourceDimension::CpuTime,
        );
        let measurements = terminate_measurements(&log.events[3].action);
        assert_eq!(measurements.len(), 1);
        assert!(measurements.contains_key(&ResourceDimension::CpuTime));
    }

    #[test]
    fn execute_escalation_saturates_timestamps_near_u64_max() {
        let mut controller = fresh_controller(5);
        let start = u64::MAX - 10;
        let log = controller.execute_escalation(
            "wl".to_string(),
            vec![ResourceDimension::CpuTime],
            start,
        );
        let timestamps: Vec<u64> = log.events.iter().map(|event| event.timestamp_ns).collect();
        assert_eq!(timestamps, vec![start, u64::MAX, u64::MAX, u64::MAX]);
        assert!(
            log.has_monotonic_timestamps(),
            "saturating escalation timestamps must stay monotonic"
        );
    }

    #[test]
    fn record_per_step_methods_support_partial_logs_and_thread_epoch() {
        let controller = fresh_controller(99);
        let mut log = EscalationLog::new("wl".to_string(), vec![ResourceDimension::HeapMemory]);
        controller.record_throttle(
            &mut log,
            10,
            AdmissionDecision::Queue {
                estimated_wait_ns: 1_000,
                position: 1,
            },
            "real throttle",
        );
        assert!(
            !log.is_complete(),
            "single-step log is not full-chain complete"
        );
        assert_eq!(log.events.len(), 1);
        assert_eq!(
            log.events[0]
                .basis
                .get("policy_epoch")
                .and_then(|v| v.as_u64()),
            Some(99)
        );

        let mut measurements = BTreeMap::new();
        measurements.insert(ResourceDimension::HeapMemory, 10_000_000);
        controller.record_terminate(
            &mut log,
            20,
            TerminationReason::PersistentExhaustion {
                dimension: ResourceDimension::HeapMemory,
                utilization_millionths: 1_500_000,
                escalation_attempts: 1,
            },
            measurements,
            "early-terminate after one strike",
        );
        assert_eq!(log.events.len(), 2);
        assert!(matches!(
            log.events[1].action,
            EscalationAction::Terminate { .. }
        ));
        assert_eq!(
            log.events[1]
                .basis
                .get("policy_epoch")
                .and_then(|v| v.as_u64()),
            Some(99)
        );
        assert!(log.has_monotonic_timestamps());
    }

    #[test]
    fn terminate_workload_threads_policy_epoch_into_basis() {
        let controller = fresh_controller(77);
        let event = controller.terminate_workload(
            "wl",
            TerminationReason::Unresponsive { timeout_ns: 50_000 },
            12,
        );
        assert_eq!(
            event
                .basis
                .get("policy_epoch")
                .and_then(|value| value.as_u64()),
            Some(77),
            "immediate termination artifacts must carry the controller epoch"
        );
        assert_eq!(
            event
                .basis
                .get("termination_type")
                .and_then(|value| value.as_str()),
            Some("immediate")
        );
        assert_eq!(
            event
                .basis
                .get("workload_id")
                .and_then(|value| value.as_str()),
            Some("wl")
        );
    }

    #[test]
    fn template_final_measurements_uses_fallback_when_bounds_empty() {
        let m = template_final_measurements(&[], ResourceDimension::HeapMemory);
        assert_eq!(m.len(), 1);
        assert!(m.contains_key(&ResourceDimension::HeapMemory));
    }
}
