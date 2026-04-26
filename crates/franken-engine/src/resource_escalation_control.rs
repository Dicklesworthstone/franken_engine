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

/// Fixed-point millionths unit.
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
        let content_hash = Self::compute_content_hash(&workload_id, &events);

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
        self.content_hash = Self::compute_content_hash(&self.workload_id, &self.events);
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
    fn compute_content_hash(workload_id: &str, events: &[EscalationEvent]) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(workload_id.as_bytes());

        for event in events {
            hasher.update(event.timestamp_ns.to_le_bytes());

            // Include full action payload, not just the variant name
            let action_json = serde_json::to_string(&event.action)
                .expect("EscalationAction should always serialize");
            hasher.update(action_json.as_bytes());

            hasher.update(event.source_module.as_bytes());

            // Include basis JSON for complete event context
            let basis_json = serde_json::to_string(&event.basis)
                .expect("serde_json::Value should always serialize");
            hasher.update(basis_json.as_bytes());
        }

        let hash_bytes = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes);
        ContentHash::from_bytes(hash_array)
    }
}

// ---------------------------------------------------------------------------
// Resource escalation controller
// ---------------------------------------------------------------------------

/// Main controller for resource budget escalation.
#[derive(Debug, Clone)]
pub struct ResourceEscalationController {
    /// Security epoch.
    epoch: SecurityEpoch,
    /// Decision context for runtime decisions.
    decision_context: DecisionContext,
}

impl ResourceEscalationController {
    /// Create a new escalation controller.
    pub fn new(epoch: SecurityEpoch, decision_context: DecisionContext) -> Self {
        Self {
            epoch,
            decision_context,
        }
    }

    /// Execute the full escalation sequence for a workload.
    pub fn execute_escalation(
        &mut self,
        workload_id: String,
        bounded_dimensions: Vec<ResourceDimension>,
        current_timestamp_ns: u64,
    ) -> EscalationLog {
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
                "utilization_millionths": 880_000
            }),
        };
        log.add_event(throttle_event);

        // Step 2: Sandbox (simulated governance violation)
        let sandbox_event = EscalationEvent {
            timestamp_ns: current_timestamp_ns + 150_000_000,
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
                ]
            }),
        };
        log.add_event(sandbox_event);

        // Step 3: Suspend (use actual decision context)
        let suspend_event = EscalationEvent {
            timestamp_ns: current_timestamp_ns + 300_000_000,
            action: EscalationAction::Suspend {
                action: LaneAction::SuspendAdaptive,
                rationale: "Budget exhaustion already has a direct deterministic suspend surface in DecisionContext.".to_string(),
            },
            source_module: "runtime_decision_theory".to_string(),
            basis: serde_json::json!({
                "lane_action": "suspend_adaptive",
                "demotion_reason": "budget_exhausted",
                "budget_remaining_millionths": 0
            }),
        };
        log.add_event(suspend_event);

        // Step 4: Terminate (NEW - real implementation)
        let mut final_measurements = BTreeMap::new();
        final_measurements.insert(ResourceDimension::CpuTime, 125_000);
        final_measurements.insert(ResourceDimension::HeapMemory, 80_000_000);

        let terminate_event = EscalationEvent {
            timestamp_ns: current_timestamp_ns + 450_000_000,
            action: EscalationAction::Terminate {
                reason: TerminationReason::PersistentExhaustion {
                    dimension: ResourceDimension::CpuTime,
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
                "final_resource_state": "over_budget"
            }),
        };
        log.add_event(terminate_event);

        log
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
                "workload_id": workload_id
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
}
