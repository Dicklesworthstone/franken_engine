//! Policy-as-Data Security and Adversarial Resilience Validation.
//!
//! Hardens governance through:
//! - policy-as-data artifact signing and verification,
//! - sandbox restrictions for policy/controller execution,
//! - adversarial workload suite to validate containment and fallback behavior,
//! - failure-mode playbooks with deterministic escalation.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic cross-platform computation.
//!
//! Plan reference: FRX-08.3 (Policy-as-Data Security).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Schema version for policy-as-data security artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.policy-as-data-security.v1";

// ---------------------------------------------------------------------------
// PolicyDataKind — classification of policy artifacts
// ---------------------------------------------------------------------------

/// Kind of policy-as-data artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDataKind {
    /// Lane routing policy (which lane under which conditions).
    LaneRouting,
    /// Security policy (capability grants, revocations).
    SecurityPolicy,
    /// Containment policy (sandbox restrictions, quarantine rules).
    ContainmentPolicy,
    /// Governance policy (epoch transitions, approval workflows).
    GovernancePolicy,
    /// Fallback policy (safe-mode triggers, demotion rules).
    FallbackPolicy,
    /// Optimization policy (specialization gating, proof requirements).
    OptimizationPolicy,
}

impl fmt::Display for PolicyDataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LaneRouting => f.write_str("lane_routing"),
            Self::SecurityPolicy => f.write_str("security_policy"),
            Self::ContainmentPolicy => f.write_str("containment_policy"),
            Self::GovernancePolicy => f.write_str("governance_policy"),
            Self::FallbackPolicy => f.write_str("fallback_policy"),
            Self::OptimizationPolicy => f.write_str("optimization_policy"),
        }
    }
}

// ---------------------------------------------------------------------------
// SignedPolicyArtifact — a signed, content-addressed policy bundle
// ---------------------------------------------------------------------------

/// A signed policy artifact with integrity guarantees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicyArtifact {
    /// Content-addressed artifact identifier.
    pub artifact_id: String,
    /// Policy kind.
    pub kind: PolicyDataKind,
    /// Human-readable policy name.
    pub policy_name: String,
    /// Version counter (monotonically increasing).
    pub version: u64,
    /// Security epoch this policy is valid for.
    pub epoch: SecurityEpoch,
    /// Content hash of the policy definition (SHA-256 hex prefix).
    pub definition_hash: String,
    /// Serialized policy body (canonical JSON bytes).
    pub policy_bytes: Vec<u8>,
    /// Signer identity (verification key hex).
    pub signer_id: String,
    /// Signature over the canonical preimage (hex).
    pub signature_hex: String,
    /// Tags for classification.
    pub tags: BTreeSet<String>,
    /// Timestamp of signing (nanoseconds since epoch).
    pub signed_at_ns: u64,
}

impl SignedPolicyArtifact {
    /// Compute the canonical preimage bytes for signing.
    pub fn preimage_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(SCHEMA_VERSION.as_bytes());
        buf.extend_from_slice(self.kind.to_string().as_bytes());
        buf.extend_from_slice(self.policy_name.as_bytes());
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(self.definition_hash.as_bytes());
        buf.extend_from_slice(&self.policy_bytes);
        buf
    }

    /// Verify that the definition hash matches the policy bytes.
    pub fn verify_definition_hash(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.policy_bytes);
        let computed = hex::encode(&hasher.finalize()[..16]);
        computed == self.definition_hash
    }

    /// Compute a content-addressed artifact ID.
    pub fn compute_artifact_id(
        kind: &PolicyDataKind,
        name: &str,
        version: u64,
        epoch: &SecurityEpoch,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(kind.to_string().as_bytes());
        hasher.update(name.as_bytes());
        hasher.update(version.to_le_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        format!("pol-{}", hex::encode(&hasher.finalize()[..12]))
    }
}

// ---------------------------------------------------------------------------
// PolicyVerificationResult — outcome of signature verification
// ---------------------------------------------------------------------------

/// Result of verifying a signed policy artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyVerificationResult {
    /// Artifact ID that was verified.
    pub artifact_id: String,
    /// Whether the definition hash matches policy bytes.
    pub definition_hash_valid: bool,
    /// Whether the signature is valid.
    pub signature_valid: bool,
    /// Whether the epoch is current.
    pub epoch_current: bool,
    /// Overall verification status.
    pub all_valid: bool,
    /// Detail message if verification failed.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// SandboxRestriction — constraints on policy execution
// ---------------------------------------------------------------------------

/// Sandbox restrictions for policy/controller execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRestriction {
    /// Restriction identifier.
    pub restriction_id: String,
    /// Human-readable description.
    pub description: String,
    /// Allowed capability names (empty = deny all).
    pub allowed_capabilities: BTreeSet<String>,
    /// Whether network access is permitted.
    pub allow_network: bool,
    /// Whether filesystem write is permitted.
    pub allow_fs_write: bool,
    /// Maximum memory in bytes (0 = unlimited).
    pub max_memory_bytes: u64,
    /// Maximum execution time in nanoseconds (0 = unlimited).
    pub max_execution_ns: u64,
    /// Whether process spawning is permitted.
    pub allow_process_spawn: bool,
}

impl SandboxRestriction {
    /// Create a maximally-restrictive sandbox (deny all).
    pub fn deny_all(restriction_id: String) -> Self {
        Self {
            restriction_id,
            description: "Deny all capabilities".to_string(),
            allowed_capabilities: BTreeSet::new(),
            allow_network: false,
            allow_fs_write: false,
            max_memory_bytes: 64 * 1024 * 1024, // 64 MB
            max_execution_ns: 5_000_000_000,    // 5 seconds
            allow_process_spawn: false,
        }
    }

    /// Check if a capability is allowed.
    pub fn is_allowed(&self, capability: &str) -> bool {
        self.allowed_capabilities.contains(capability)
    }

    /// Check if any resource limit would be exceeded.
    pub fn would_exceed_memory(&self, requested_bytes: u64) -> bool {
        self.max_memory_bytes > 0 && requested_bytes > self.max_memory_bytes
    }

    /// Check if execution time would be exceeded.
    pub fn would_exceed_time(&self, elapsed_ns: u64) -> bool {
        self.max_execution_ns > 0 && elapsed_ns > self.max_execution_ns
    }
}

// ---------------------------------------------------------------------------
// PolicySandboxProfile — named sandbox configuration
// ---------------------------------------------------------------------------

/// Named sandbox profile for different policy execution contexts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySandboxProfile {
    /// Profile name.
    pub name: String,
    /// Policy kinds this profile applies to.
    pub applicable_kinds: BTreeSet<PolicyDataKind>,
    /// Base restriction.
    pub restriction: SandboxRestriction,
    /// Whether this profile is the default.
    pub is_default: bool,
}

/// Generate canonical sandbox profiles.
pub fn canonical_sandbox_profiles() -> Vec<PolicySandboxProfile> {
    vec![
        PolicySandboxProfile {
            name: "security_policy".to_string(),
            applicable_kinds: BTreeSet::from([PolicyDataKind::SecurityPolicy]),
            restriction: SandboxRestriction::deny_all("sandbox-security".to_string()),
            is_default: false,
        },
        PolicySandboxProfile {
            name: "governance_policy".to_string(),
            applicable_kinds: BTreeSet::from([PolicyDataKind::GovernancePolicy]),
            restriction: SandboxRestriction {
                restriction_id: "sandbox-governance".to_string(),
                description: "Governance policies: read-only, no network".to_string(),
                allowed_capabilities: BTreeSet::from(["read_evidence".to_string()]),
                allow_network: false,
                allow_fs_write: false,
                max_memory_bytes: 128 * 1024 * 1024,
                max_execution_ns: 10_000_000_000,
                allow_process_spawn: false,
            },
            is_default: false,
        },
        PolicySandboxProfile {
            name: "default".to_string(),
            applicable_kinds: BTreeSet::from([
                PolicyDataKind::LaneRouting,
                PolicyDataKind::ContainmentPolicy,
                PolicyDataKind::FallbackPolicy,
                PolicyDataKind::OptimizationPolicy,
            ]),
            restriction: SandboxRestriction {
                restriction_id: "sandbox-default".to_string(),
                description: "Default: no network, no fs write, 64MB".to_string(),
                allowed_capabilities: BTreeSet::new(),
                allow_network: false,
                allow_fs_write: false,
                max_memory_bytes: 64 * 1024 * 1024,
                max_execution_ns: 5_000_000_000,
                allow_process_spawn: false,
            },
            is_default: true,
        },
    ]
}

// ---------------------------------------------------------------------------
// AdversarialScenario — test scenario for resilience validation
// ---------------------------------------------------------------------------

/// Classification of adversarial scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioCategory {
    /// Policy tampering: modify policy bytes after signing.
    PolicyTampering,
    /// Replay attack: reuse a valid policy from a prior epoch.
    ReplayAttack,
    /// Privilege escalation: attempt to gain capabilities beyond grant.
    PrivilegeEscalation,
    /// Resource exhaustion: overwhelm sandbox limits.
    ResourceExhaustion,
    /// Containment escape: break out of sandbox restrictions.
    ContainmentEscape,
    /// Fallback suppression: prevent safe-mode activation.
    FallbackSuppression,
}

impl fmt::Display for ScenarioCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyTampering => f.write_str("policy_tampering"),
            Self::ReplayAttack => f.write_str("replay_attack"),
            Self::PrivilegeEscalation => f.write_str("privilege_escalation"),
            Self::ResourceExhaustion => f.write_str("resource_exhaustion"),
            Self::ContainmentEscape => f.write_str("containment_escape"),
            Self::FallbackSuppression => f.write_str("fallback_suppression"),
        }
    }
}

/// Expected outcome of an adversarial scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    /// The attack should be blocked/denied.
    Blocked,
    /// The attack should trigger safe-mode fallback.
    FallbackTriggered,
    /// The attack should trigger containment/quarantine.
    Contained,
    /// The attack should be detected and logged.
    DetectedOnly,
}

impl fmt::Display for ExpectedOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked => f.write_str("blocked"),
            Self::FallbackTriggered => f.write_str("fallback_triggered"),
            Self::Contained => f.write_str("contained"),
            Self::DetectedOnly => f.write_str("detected_only"),
        }
    }
}

/// A single adversarial test scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversarialScenario {
    /// Scenario identifier.
    pub scenario_id: String,
    /// Human-readable name.
    pub name: String,
    /// Scenario category.
    pub category: ScenarioCategory,
    /// Expected outcome.
    pub expected_outcome: ExpectedOutcome,
    /// Description of the attack.
    pub description: String,
    /// Severity (0 = informational, MILLION = critical).
    pub severity_millionths: i64,
    /// Policy kinds targeted by this scenario.
    pub target_kinds: BTreeSet<PolicyDataKind>,
}

/// Result of executing an adversarial scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Scenario identifier.
    pub scenario_id: String,
    /// Actual outcome.
    pub actual_outcome: ExpectedOutcome,
    /// Whether expected == actual.
    pub passed: bool,
    /// Execution detail.
    pub detail: String,
    /// Evidence hash for audit trail.
    pub evidence_hash: String,
}

// ---------------------------------------------------------------------------
// AdversarialSuite — collection of scenarios
// ---------------------------------------------------------------------------

/// Suite of adversarial scenarios for resilience validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversarialSuite {
    /// Suite name.
    pub suite_name: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Scenarios in the suite.
    pub scenarios: Vec<AdversarialScenario>,
    /// Results (populated after execution).
    pub results: Vec<ScenarioResult>,
}

impl AdversarialSuite {
    /// Create a new empty suite.
    pub fn new(suite_name: String, epoch: SecurityEpoch) -> Self {
        Self {
            suite_name,
            epoch,
            scenarios: Vec::new(),
            results: Vec::new(),
        }
    }

    /// Add a scenario.
    pub fn add_scenario(&mut self, scenario: AdversarialScenario) {
        self.scenarios.push(scenario);
    }

    /// Record a result.
    pub fn record_result(&mut self, result: ScenarioResult) {
        self.results.push(result);
    }

    /// Number of scenarios.
    pub fn scenario_count(&self) -> usize {
        self.scenarios.len()
    }

    /// Number of passing results.
    pub fn pass_count(&self) -> usize {
        self.results.iter().filter(|r| r.passed).count()
    }

    /// Number of failing results.
    pub fn fail_count(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }

    /// Whether all recorded results pass.
    pub fn all_pass(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.passed)
    }

    /// Per-category pass rate (millionths).
    pub fn pass_rate_by_category(&self) -> BTreeMap<String, i64> {
        let mut totals: BTreeMap<String, (i64, i64)> = BTreeMap::new();

        // Build scenario-id → category mapping.
        let category_map: BTreeMap<&str, ScenarioCategory> = self
            .scenarios
            .iter()
            .map(|s| (s.scenario_id.as_str(), s.category))
            .collect();

        for r in &self.results {
            if let Some(cat) = category_map.get(r.scenario_id.as_str()) {
                let key = cat.to_string();
                let entry = totals.entry(key).or_insert((0, 0));
                entry.0 += 1;
                if r.passed {
                    entry.1 += 1;
                }
            }
        }

        totals
            .into_iter()
            .map(|(k, (total, passed))| {
                let rate = if total > 0 {
                    passed * MILLION / total
                } else {
                    0
                };
                (k, rate)
            })
            .collect()
    }
}

/// Generate canonical adversarial scenarios covering all categories.
pub fn canonical_adversarial_scenarios() -> Vec<AdversarialScenario> {
    vec![
        AdversarialScenario {
            scenario_id: "adv-001".to_string(),
            name: "Policy byte tampering after signing".to_string(),
            category: ScenarioCategory::PolicyTampering,
            expected_outcome: ExpectedOutcome::Blocked,
            description: "Modify policy_bytes after signing; verification must fail".to_string(),
            severity_millionths: MILLION,
            target_kinds: BTreeSet::from([PolicyDataKind::SecurityPolicy]),
        },
        AdversarialScenario {
            scenario_id: "adv-002".to_string(),
            name: "Replay stale epoch policy".to_string(),
            category: ScenarioCategory::ReplayAttack,
            expected_outcome: ExpectedOutcome::Blocked,
            description: "Submit a validly-signed policy from epoch N-1 in epoch N".to_string(),
            severity_millionths: 800_000,
            target_kinds: BTreeSet::from([PolicyDataKind::GovernancePolicy]),
        },
        AdversarialScenario {
            scenario_id: "adv-003".to_string(),
            name: "Capability escalation via policy injection".to_string(),
            category: ScenarioCategory::PrivilegeEscalation,
            expected_outcome: ExpectedOutcome::Contained,
            description: "Attempt to grant capabilities beyond allowed set".to_string(),
            severity_millionths: MILLION,
            target_kinds: BTreeSet::from([PolicyDataKind::SecurityPolicy]),
        },
        AdversarialScenario {
            scenario_id: "adv-004".to_string(),
            name: "Memory exhaustion in policy evaluation".to_string(),
            category: ScenarioCategory::ResourceExhaustion,
            expected_outcome: ExpectedOutcome::Contained,
            description: "Submit policy requiring >max_memory_bytes to evaluate".to_string(),
            severity_millionths: 600_000,
            target_kinds: BTreeSet::from([PolicyDataKind::OptimizationPolicy]),
        },
        AdversarialScenario {
            scenario_id: "adv-005".to_string(),
            name: "Sandbox escape via process spawning".to_string(),
            category: ScenarioCategory::ContainmentEscape,
            expected_outcome: ExpectedOutcome::Blocked,
            description: "Attempt process_spawn from within deny-all sandbox".to_string(),
            severity_millionths: MILLION,
            target_kinds: BTreeSet::from([PolicyDataKind::ContainmentPolicy]),
        },
        AdversarialScenario {
            scenario_id: "adv-006".to_string(),
            name: "Suppress safe-mode trigger via evidence flooding".to_string(),
            category: ScenarioCategory::FallbackSuppression,
            expected_outcome: ExpectedOutcome::FallbackTriggered,
            description: "Flood evidence channel to delay safe-mode activation".to_string(),
            severity_millionths: 700_000,
            target_kinds: BTreeSet::from([PolicyDataKind::FallbackPolicy]),
        },
    ]
}

// ---------------------------------------------------------------------------
// FailurePlaybook — deterministic escalation plan
// ---------------------------------------------------------------------------

/// Escalation level in a failure playbook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationLevel {
    /// Informational only — log and continue.
    Observe,
    /// Warning — log and emit alert.
    Alert,
    /// Mitigate — activate sandbox/containment.
    Mitigate,
    /// Escalate — trigger safe-mode fallback.
    Escalate,
    /// Emergency — full suspension and quarantine.
    Emergency,
}

impl fmt::Display for EscalationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observe => f.write_str("observe"),
            Self::Alert => f.write_str("alert"),
            Self::Mitigate => f.write_str("mitigate"),
            Self::Escalate => f.write_str("escalate"),
            Self::Emergency => f.write_str("emergency"),
        }
    }
}

/// A step in a failure-mode playbook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaybookStep {
    /// Step number (1-indexed).
    pub step: u32,
    /// Escalation level.
    pub level: EscalationLevel,
    /// Action to take at this step.
    pub action: String,
    /// Condition that triggers escalation to next step.
    pub escalation_condition: String,
    /// Maximum time at this level before escalating (nanoseconds, 0 = no limit).
    pub max_duration_ns: u64,
}

/// A failure-mode playbook defining deterministic escalation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailurePlaybook {
    /// Playbook identifier.
    pub playbook_id: String,
    /// Failure scenario this playbook addresses.
    pub scenario_category: ScenarioCategory,
    /// Ordered escalation steps.
    pub steps: Vec<PlaybookStep>,
    /// Whether the playbook allows de-escalation.
    pub allows_deescalation: bool,
    /// Content hash.
    pub content_hash: String,
}

impl FailurePlaybook {
    /// Build a playbook, computing the content hash.
    pub fn new(
        playbook_id: String,
        scenario_category: ScenarioCategory,
        steps: Vec<PlaybookStep>,
        allows_deescalation: bool,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(playbook_id.as_bytes());
        hasher.update(scenario_category.to_string().as_bytes());
        for step in &steps {
            hasher.update(step.step.to_le_bytes());
            hasher.update(step.level.to_string().as_bytes());
            hasher.update(step.action.as_bytes());
        }
        let content_hash = hex::encode(&hasher.finalize()[..16]);

        Self {
            playbook_id,
            scenario_category,
            steps,
            allows_deescalation,
            content_hash,
        }
    }

    /// Number of escalation steps.
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Maximum escalation level in this playbook.
    pub fn max_level(&self) -> Option<EscalationLevel> {
        self.steps.iter().map(|s| s.level).max()
    }
}

/// Generate canonical failure playbooks.
pub fn canonical_failure_playbooks() -> Vec<FailurePlaybook> {
    vec![
        FailurePlaybook::new(
            "pb-tampering".to_string(),
            ScenarioCategory::PolicyTampering,
            vec![
                PlaybookStep {
                    step: 1,
                    level: EscalationLevel::Alert,
                    action: "Log tampering detection and notify operator".to_string(),
                    escalation_condition: "Repeated tampering attempts (>3 in epoch)".to_string(),
                    max_duration_ns: 0,
                },
                PlaybookStep {
                    step: 2,
                    level: EscalationLevel::Mitigate,
                    action: "Quarantine affected policy artifact".to_string(),
                    escalation_condition: "Tampering from multiple sources".to_string(),
                    max_duration_ns: 60_000_000_000,
                },
                PlaybookStep {
                    step: 3,
                    level: EscalationLevel::Emergency,
                    action: "Suspend all policy loading and fall back to built-in defaults"
                        .to_string(),
                    escalation_condition: "N/A (terminal)".to_string(),
                    max_duration_ns: 0,
                },
            ],
            false,
        ),
        FailurePlaybook::new(
            "pb-exhaustion".to_string(),
            ScenarioCategory::ResourceExhaustion,
            vec![
                PlaybookStep {
                    step: 1,
                    level: EscalationLevel::Observe,
                    action: "Log resource usage spike".to_string(),
                    escalation_condition: "Memory usage exceeds 80% of sandbox limit".to_string(),
                    max_duration_ns: 5_000_000_000,
                },
                PlaybookStep {
                    step: 2,
                    level: EscalationLevel::Mitigate,
                    action: "Terminate policy evaluation and cache deny result".to_string(),
                    escalation_condition: "Timeout or OOM on policy evaluation".to_string(),
                    max_duration_ns: 10_000_000_000,
                },
                PlaybookStep {
                    step: 3,
                    level: EscalationLevel::Escalate,
                    action: "Activate safe-mode for affected policy domain".to_string(),
                    escalation_condition: "N/A (terminal)".to_string(),
                    max_duration_ns: 0,
                },
            ],
            true,
        ),
    ]
}

// ---------------------------------------------------------------------------
// SecurityReport — CI-readable aggregate report
// ---------------------------------------------------------------------------

/// CI-readable report of policy-as-data security validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityReport {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Total signed artifacts verified.
    pub artifacts_verified: usize,
    /// Artifacts with valid signatures.
    pub artifacts_valid: usize,
    /// Adversarial scenarios executed.
    pub scenarios_executed: usize,
    /// Adversarial scenarios passing.
    pub scenarios_passing: usize,
    /// Per-category pass rates (millionths).
    pub category_pass_rates: BTreeMap<String, i64>,
    /// Failure playbooks loaded.
    pub playbooks_loaded: usize,
    /// Sandbox profiles configured.
    pub sandbox_profiles: usize,
    /// Overall security posture (millionths, MILLION = fully hardened).
    pub security_posture_millionths: i64,
    /// Content hash for integrity.
    pub report_hash: String,
}

/// Generate a security report from suite results and verification outcomes.
pub fn generate_report(
    epoch: &SecurityEpoch,
    artifacts_verified: usize,
    artifacts_valid: usize,
    suite: &AdversarialSuite,
    playbook_count: usize,
    profile_count: usize,
) -> SecurityReport {
    let category_pass_rates = suite.pass_rate_by_category();
    let scenarios_executed = suite.results.len();
    let scenarios_passing = suite.pass_count();

    // Compute security posture as weighted average of:
    // - artifact verification rate (40%)
    // - adversarial pass rate (40%)
    // - playbook coverage (20%)
    let artifact_rate = if artifacts_verified > 0 {
        (artifacts_valid as i64 * MILLION) / artifacts_verified as i64
    } else {
        MILLION // No artifacts = no risk
    };

    let adversarial_rate = if scenarios_executed > 0 {
        (scenarios_passing as i64 * MILLION) / scenarios_executed as i64
    } else {
        0
    };

    let playbook_rate = if playbook_count > 0 {
        MILLION // Playbooks exist
    } else {
        0
    };

    let security_posture_millionths =
        (artifact_rate * 400_000 + adversarial_rate * 400_000 + playbook_rate * 200_000) / MILLION;

    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update((artifacts_verified as u64).to_le_bytes());
    hasher.update((scenarios_passing as u64).to_le_bytes());
    hasher.update(security_posture_millionths.to_le_bytes());
    let report_hash = hex::encode(&hasher.finalize()[..16]);

    SecurityReport {
        schema_version: SCHEMA_VERSION.to_string(),
        epoch: *epoch,
        artifacts_verified,
        artifacts_valid,
        scenarios_executed,
        scenarios_passing,
        category_pass_rates,
        playbooks_loaded: playbook_count,
        sandbox_profiles: profile_count,
        security_posture_millionths,
        report_hash,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(5)
    }

    fn test_policy_bytes() -> Vec<u8> {
        b"{\"rule\":\"deny_all\"}".to_vec()
    }

    fn test_definition_hash(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(&hasher.finalize()[..16])
    }

    fn test_signed_artifact() -> SignedPolicyArtifact {
        let bytes = test_policy_bytes();
        let def_hash = test_definition_hash(&bytes);
        let artifact_id = SignedPolicyArtifact::compute_artifact_id(
            &PolicyDataKind::SecurityPolicy,
            "test-policy",
            1,
            &test_epoch(),
        );
        SignedPolicyArtifact {
            artifact_id,
            kind: PolicyDataKind::SecurityPolicy,
            policy_name: "test-policy".to_string(),
            version: 1,
            epoch: test_epoch(),
            definition_hash: def_hash,
            policy_bytes: bytes,
            signer_id: "signer-001".to_string(),
            signature_hex: "deadbeef".to_string(),
            tags: BTreeSet::from(["security".to_string()]),
            signed_at_ns: 1_000_000_000,
        }
    }

    // -- PolicyDataKind tests --

    #[test]
    fn policy_kind_display_all_six() {
        let kinds = [
            PolicyDataKind::LaneRouting,
            PolicyDataKind::SecurityPolicy,
            PolicyDataKind::ContainmentPolicy,
            PolicyDataKind::GovernancePolicy,
            PolicyDataKind::FallbackPolicy,
            PolicyDataKind::OptimizationPolicy,
        ];
        let names: Vec<String> = kinds.iter().map(|k| k.to_string()).collect();
        assert_eq!(names.len(), 6);
        let unique: BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), 6);
    }

    #[test]
    fn policy_kind_serde_roundtrip() {
        for k in [
            PolicyDataKind::LaneRouting,
            PolicyDataKind::SecurityPolicy,
            PolicyDataKind::ContainmentPolicy,
            PolicyDataKind::GovernancePolicy,
            PolicyDataKind::FallbackPolicy,
            PolicyDataKind::OptimizationPolicy,
        ] {
            let json = serde_json::to_string(&k).expect("serde deserialization should succeed");
            let back: PolicyDataKind =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(k, back);
        }
    }

    // -- SignedPolicyArtifact tests --

    #[test]
    fn artifact_id_deterministic() {
        let id1 = SignedPolicyArtifact::compute_artifact_id(
            &PolicyDataKind::SecurityPolicy,
            "test",
            1,
            &test_epoch(),
        );
        let id2 = SignedPolicyArtifact::compute_artifact_id(
            &PolicyDataKind::SecurityPolicy,
            "test",
            1,
            &test_epoch(),
        );
        assert_eq!(id1, id2);
        assert!(id1.starts_with("pol-"));
    }

    #[test]
    fn artifact_id_differs_by_kind() {
        let id1 = SignedPolicyArtifact::compute_artifact_id(
            &PolicyDataKind::SecurityPolicy,
            "test",
            1,
            &test_epoch(),
        );
        let id2 = SignedPolicyArtifact::compute_artifact_id(
            &PolicyDataKind::FallbackPolicy,
            "test",
            1,
            &test_epoch(),
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn definition_hash_verification_passes() {
        let artifact = test_signed_artifact();
        assert!(artifact.verify_definition_hash());
    }

    #[test]
    fn definition_hash_verification_fails_on_tamper() {
        let mut artifact = test_signed_artifact();
        artifact.policy_bytes.push(0xFF);
        assert!(!artifact.verify_definition_hash());
    }

    #[test]
    fn preimage_bytes_deterministic() {
        let artifact = test_signed_artifact();
        assert_eq!(artifact.preimage_bytes(), artifact.preimage_bytes());
    }

    #[test]
    fn preimage_bytes_differ_on_version_change() {
        let a1 = test_signed_artifact();
        let mut a2 = test_signed_artifact();
        a2.version = 2;
        assert_ne!(a1.preimage_bytes(), a2.preimage_bytes());
    }

    #[test]
    fn signed_artifact_serde_roundtrip() {
        let artifact = test_signed_artifact();
        let json = serde_json::to_string(&artifact).expect("serde deserialization should succeed");
        let back: SignedPolicyArtifact =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(artifact, back);
    }

    // -- SandboxRestriction tests --

    #[test]
    fn deny_all_sandbox() {
        let sandbox = SandboxRestriction::deny_all("test".to_string());
        assert!(!sandbox.allow_network);
        assert!(!sandbox.allow_fs_write);
        assert!(!sandbox.allow_process_spawn);
        assert!(!sandbox.is_allowed("anything"));
    }

    #[test]
    fn sandbox_capability_check() {
        let mut sandbox = SandboxRestriction::deny_all("test".to_string());
        sandbox
            .allowed_capabilities
            .insert("read_evidence".to_string());
        assert!(sandbox.is_allowed("read_evidence"));
        assert!(!sandbox.is_allowed("write_policy"));
    }

    #[test]
    fn sandbox_memory_limit() {
        let sandbox = SandboxRestriction::deny_all("test".to_string());
        assert!(sandbox.would_exceed_memory(100 * 1024 * 1024));
        assert!(!sandbox.would_exceed_memory(32 * 1024 * 1024));
    }

    #[test]
    fn sandbox_time_limit() {
        let sandbox = SandboxRestriction::deny_all("test".to_string());
        assert!(sandbox.would_exceed_time(10_000_000_000));
        assert!(!sandbox.would_exceed_time(1_000_000_000));
    }

    #[test]
    fn sandbox_serde_roundtrip() {
        let sandbox = SandboxRestriction::deny_all("test".to_string());
        let json = serde_json::to_string(&sandbox).expect("serde deserialization should succeed");
        let back: SandboxRestriction =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(sandbox, back);
    }

    // -- PolicySandboxProfile tests --

    #[test]
    fn canonical_profiles_cover_all_kinds() {
        let profiles = canonical_sandbox_profiles();
        assert_eq!(profiles.len(), 3);

        let mut covered: BTreeSet<PolicyDataKind> = BTreeSet::new();
        for p in &profiles {
            covered.extend(&p.applicable_kinds);
        }
        assert_eq!(covered.len(), 6);
    }

    #[test]
    fn canonical_profiles_have_one_default() {
        let profiles = canonical_sandbox_profiles();
        let defaults: Vec<_> = profiles.iter().filter(|p| p.is_default).collect();
        assert_eq!(defaults.len(), 1);
    }

    // -- ScenarioCategory tests --

    #[test]
    fn scenario_category_display_all() {
        let cats = [
            ScenarioCategory::PolicyTampering,
            ScenarioCategory::ReplayAttack,
            ScenarioCategory::PrivilegeEscalation,
            ScenarioCategory::ResourceExhaustion,
            ScenarioCategory::ContainmentEscape,
            ScenarioCategory::FallbackSuppression,
        ];
        let names: Vec<String> = cats.iter().map(|c| c.to_string()).collect();
        let unique: BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), 6);
    }

    #[test]
    fn scenario_category_serde_roundtrip() {
        for c in [
            ScenarioCategory::PolicyTampering,
            ScenarioCategory::ReplayAttack,
            ScenarioCategory::PrivilegeEscalation,
            ScenarioCategory::ResourceExhaustion,
            ScenarioCategory::ContainmentEscape,
            ScenarioCategory::FallbackSuppression,
        ] {
            let json = serde_json::to_string(&c).expect("serde deserialization should succeed");
            let back: ScenarioCategory =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(c, back);
        }
    }

    // -- ExpectedOutcome tests --

    #[test]
    fn expected_outcome_serde_roundtrip() {
        for o in [
            ExpectedOutcome::Blocked,
            ExpectedOutcome::FallbackTriggered,
            ExpectedOutcome::Contained,
            ExpectedOutcome::DetectedOnly,
        ] {
            let json = serde_json::to_string(&o).expect("serde deserialization should succeed");
            let back: ExpectedOutcome =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(o, back);
        }
    }

    // -- AdversarialSuite tests --

    #[test]
    fn suite_empty() {
        let suite = AdversarialSuite::new("test".to_string(), test_epoch());
        assert_eq!(suite.scenario_count(), 0);
        assert_eq!(suite.pass_count(), 0);
        assert!(!suite.all_pass());
    }

    #[test]
    fn suite_all_pass() {
        let mut suite = AdversarialSuite::new("test".to_string(), test_epoch());
        suite.add_scenario(AdversarialScenario {
            scenario_id: "s-1".to_string(),
            name: "test".to_string(),
            category: ScenarioCategory::PolicyTampering,
            expected_outcome: ExpectedOutcome::Blocked,
            description: "test".to_string(),
            severity_millionths: MILLION,
            target_kinds: BTreeSet::new(),
        });
        suite.record_result(ScenarioResult {
            scenario_id: "s-1".to_string(),
            actual_outcome: ExpectedOutcome::Blocked,
            passed: true,
            detail: "blocked as expected".to_string(),
            evidence_hash: "hash".to_string(),
        });

        assert!(suite.all_pass());
        assert_eq!(suite.pass_count(), 1);
        assert_eq!(suite.fail_count(), 0);
    }

    #[test]
    fn suite_with_failure() {
        let mut suite = AdversarialSuite::new("test".to_string(), test_epoch());
        suite.add_scenario(AdversarialScenario {
            scenario_id: "s-2".to_string(),
            name: "test".to_string(),
            category: ScenarioCategory::ContainmentEscape,
            expected_outcome: ExpectedOutcome::Blocked,
            description: "test".to_string(),
            severity_millionths: MILLION,
            target_kinds: BTreeSet::new(),
        });
        suite.record_result(ScenarioResult {
            scenario_id: "s-2".to_string(),
            actual_outcome: ExpectedOutcome::DetectedOnly,
            passed: false,
            detail: "escape was only detected, not blocked".to_string(),
            evidence_hash: "hash".to_string(),
        });

        assert!(!suite.all_pass());
        assert_eq!(suite.fail_count(), 1);
    }

    #[test]
    fn suite_pass_rate_by_category() {
        let mut suite = AdversarialSuite::new("test".to_string(), test_epoch());
        suite.add_scenario(AdversarialScenario {
            scenario_id: "s-a".to_string(),
            name: "a".to_string(),
            category: ScenarioCategory::PolicyTampering,
            expected_outcome: ExpectedOutcome::Blocked,
            description: "a".to_string(),
            severity_millionths: MILLION,
            target_kinds: BTreeSet::new(),
        });
        suite.add_scenario(AdversarialScenario {
            scenario_id: "s-b".to_string(),
            name: "b".to_string(),
            category: ScenarioCategory::PolicyTampering,
            expected_outcome: ExpectedOutcome::Blocked,
            description: "b".to_string(),
            severity_millionths: MILLION,
            target_kinds: BTreeSet::new(),
        });

        suite.record_result(ScenarioResult {
            scenario_id: "s-a".to_string(),
            actual_outcome: ExpectedOutcome::Blocked,
            passed: true,
            detail: "ok".to_string(),
            evidence_hash: "h".to_string(),
        });
        suite.record_result(ScenarioResult {
            scenario_id: "s-b".to_string(),
            actual_outcome: ExpectedOutcome::DetectedOnly,
            passed: false,
            detail: "fail".to_string(),
            evidence_hash: "h".to_string(),
        });

        let rates = suite.pass_rate_by_category();
        assert_eq!(rates.get("policy_tampering"), Some(&500_000));
    }

    #[test]
    fn suite_serde_roundtrip() {
        let suite = AdversarialSuite::new("test".to_string(), test_epoch());
        let json = serde_json::to_string(&suite).expect("serde deserialization should succeed");
        let back: AdversarialSuite =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(suite, back);
    }

    // -- Canonical scenarios tests --

    #[test]
    fn canonical_scenarios_cover_all_categories() {
        let scenarios = canonical_adversarial_scenarios();
        assert_eq!(scenarios.len(), 6);
        let cats: BTreeSet<_> = scenarios.iter().map(|s| s.category).collect();
        assert_eq!(cats.len(), 6);
    }

    #[test]
    fn canonical_scenarios_unique_ids() {
        let scenarios = canonical_adversarial_scenarios();
        let ids: BTreeSet<_> = scenarios.iter().map(|s| &s.scenario_id).collect();
        assert_eq!(ids.len(), scenarios.len());
    }

    // -- EscalationLevel tests --

    #[test]
    fn escalation_ordering() {
        assert!(EscalationLevel::Observe < EscalationLevel::Alert);
        assert!(EscalationLevel::Alert < EscalationLevel::Mitigate);
        assert!(EscalationLevel::Mitigate < EscalationLevel::Escalate);
        assert!(EscalationLevel::Escalate < EscalationLevel::Emergency);
    }

    #[test]
    fn escalation_serde_roundtrip() {
        for e in [
            EscalationLevel::Observe,
            EscalationLevel::Alert,
            EscalationLevel::Mitigate,
            EscalationLevel::Escalate,
            EscalationLevel::Emergency,
        ] {
            let json = serde_json::to_string(&e).expect("serde deserialization should succeed");
            let back: EscalationLevel =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(e, back);
        }
    }

    // -- FailurePlaybook tests --

    #[test]
    fn playbook_step_count() {
        let pb = FailurePlaybook::new(
            "test".to_string(),
            ScenarioCategory::PolicyTampering,
            vec![
                PlaybookStep {
                    step: 1,
                    level: EscalationLevel::Alert,
                    action: "alert".to_string(),
                    escalation_condition: "repeated".to_string(),
                    max_duration_ns: 0,
                },
                PlaybookStep {
                    step: 2,
                    level: EscalationLevel::Emergency,
                    action: "suspend".to_string(),
                    escalation_condition: "N/A".to_string(),
                    max_duration_ns: 0,
                },
            ],
            false,
        );
        assert_eq!(pb.step_count(), 2);
        assert_eq!(pb.max_level(), Some(EscalationLevel::Emergency));
    }

    #[test]
    fn playbook_hash_deterministic() {
        let steps = vec![PlaybookStep {
            step: 1,
            level: EscalationLevel::Alert,
            action: "alert".to_string(),
            escalation_condition: "cond".to_string(),
            max_duration_ns: 0,
        }];
        let p1 = FailurePlaybook::new(
            "pb-1".to_string(),
            ScenarioCategory::ReplayAttack,
            steps.clone(),
            false,
        );
        let p2 = FailurePlaybook::new(
            "pb-1".to_string(),
            ScenarioCategory::ReplayAttack,
            steps,
            false,
        );
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn playbook_serde_roundtrip() {
        let pb = FailurePlaybook::new(
            "test".to_string(),
            ScenarioCategory::ResourceExhaustion,
            vec![PlaybookStep {
                step: 1,
                level: EscalationLevel::Mitigate,
                action: "kill".to_string(),
                escalation_condition: "OOM".to_string(),
                max_duration_ns: 5_000_000_000,
            }],
            true,
        );
        let json = serde_json::to_string(&pb).expect("serde deserialization should succeed");
        let back: FailurePlaybook =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(pb, back);
    }

    // -- Canonical playbooks tests --

    #[test]
    fn canonical_playbooks_exist() {
        let playbooks = canonical_failure_playbooks();
        assert_eq!(playbooks.len(), 2);
    }

    #[test]
    fn canonical_playbooks_have_steps() {
        let playbooks = canonical_failure_playbooks();
        for pb in &playbooks {
            assert!(pb.step_count() > 0);
        }
    }

    // -- SecurityReport tests --

    #[test]
    fn report_full_security() {
        let mut suite = AdversarialSuite::new("test".to_string(), test_epoch());
        suite.add_scenario(AdversarialScenario {
            scenario_id: "s-1".to_string(),
            name: "test".to_string(),
            category: ScenarioCategory::PolicyTampering,
            expected_outcome: ExpectedOutcome::Blocked,
            description: "test".to_string(),
            severity_millionths: MILLION,
            target_kinds: BTreeSet::new(),
        });
        suite.record_result(ScenarioResult {
            scenario_id: "s-1".to_string(),
            actual_outcome: ExpectedOutcome::Blocked,
            passed: true,
            detail: "ok".to_string(),
            evidence_hash: "h".to_string(),
        });

        let report = generate_report(&test_epoch(), 5, 5, &suite, 2, 3);
        assert_eq!(report.artifacts_verified, 5);
        assert_eq!(report.artifacts_valid, 5);
        assert_eq!(report.scenarios_executed, 1);
        assert_eq!(report.scenarios_passing, 1);
        assert_eq!(report.playbooks_loaded, 2);
        assert_eq!(report.sandbox_profiles, 3);
        assert_eq!(report.security_posture_millionths, MILLION);
        assert!(!report.report_hash.is_empty());
    }

    #[test]
    fn report_partial_security() {
        let suite = AdversarialSuite::new("test".to_string(), test_epoch());
        let report = generate_report(&test_epoch(), 10, 8, &suite, 1, 2);
        // artifact rate: 800000, adversarial rate: 0 (no scenarios), playbook rate: 1M
        // posture: (800000*400000 + 0*400000 + 1000000*200000) / 1M = 520000
        assert_eq!(report.security_posture_millionths, 520_000);
    }

    #[test]
    fn report_hash_deterministic() {
        let suite = AdversarialSuite::new("test".to_string(), test_epoch());
        let r1 = generate_report(&test_epoch(), 1, 1, &suite, 1, 1);
        let r2 = generate_report(&test_epoch(), 1, 1, &suite, 1, 1);
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn report_serde_roundtrip() {
        let suite = AdversarialSuite::new("test".to_string(), test_epoch());
        let report = generate_report(&test_epoch(), 1, 1, &suite, 1, 1);
        let json = serde_json::to_string(&report).expect("serde deserialization should succeed");
        let back: SecurityReport =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(report, back);
    }

    // -- PolicyVerificationResult tests --

    #[test]
    fn verification_result_serde_roundtrip() {
        let result = PolicyVerificationResult {
            artifact_id: "pol-1".to_string(),
            definition_hash_valid: true,
            signature_valid: true,
            epoch_current: true,
            all_valid: true,
            detail: "all checks pass".to_string(),
        };
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let back: PolicyVerificationResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, back);
    }

    // -- Enrichment: ordering, display, edge cases --

    #[test]
    fn policy_kind_ordering() {
        assert!(PolicyDataKind::LaneRouting < PolicyDataKind::SecurityPolicy);
        assert!(PolicyDataKind::SecurityPolicy < PolicyDataKind::ContainmentPolicy);
        assert!(PolicyDataKind::ContainmentPolicy < PolicyDataKind::GovernancePolicy);
        assert!(PolicyDataKind::GovernancePolicy < PolicyDataKind::FallbackPolicy);
        assert!(PolicyDataKind::FallbackPolicy < PolicyDataKind::OptimizationPolicy);
    }

    #[test]
    fn expected_outcome_display_all() {
        assert_eq!(ExpectedOutcome::Blocked.to_string(), "blocked");
        assert_eq!(
            ExpectedOutcome::FallbackTriggered.to_string(),
            "fallback_triggered"
        );
        assert_eq!(ExpectedOutcome::Contained.to_string(), "contained");
        assert_eq!(ExpectedOutcome::DetectedOnly.to_string(), "detected_only");
    }

    #[test]
    fn escalation_level_display_all() {
        assert_eq!(EscalationLevel::Observe.to_string(), "observe");
        assert_eq!(EscalationLevel::Alert.to_string(), "alert");
        assert_eq!(EscalationLevel::Mitigate.to_string(), "mitigate");
        assert_eq!(EscalationLevel::Escalate.to_string(), "escalate");
        assert_eq!(EscalationLevel::Emergency.to_string(), "emergency");
    }

    #[test]
    fn scenario_category_ordering() {
        assert!(ScenarioCategory::PolicyTampering < ScenarioCategory::ReplayAttack);
        assert!(ScenarioCategory::ReplayAttack < ScenarioCategory::PrivilegeEscalation);
        assert!(ScenarioCategory::PrivilegeEscalation < ScenarioCategory::ResourceExhaustion);
        assert!(ScenarioCategory::ResourceExhaustion < ScenarioCategory::ContainmentEscape);
        assert!(ScenarioCategory::ContainmentEscape < ScenarioCategory::FallbackSuppression);
    }

    #[test]
    fn artifact_id_differs_by_name() {
        let id1 = SignedPolicyArtifact::compute_artifact_id(
            &PolicyDataKind::SecurityPolicy,
            "policy-alpha",
            1,
            &test_epoch(),
        );
        let id2 = SignedPolicyArtifact::compute_artifact_id(
            &PolicyDataKind::SecurityPolicy,
            "policy-beta",
            1,
            &test_epoch(),
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn artifact_id_differs_by_epoch() {
        let id1 = SignedPolicyArtifact::compute_artifact_id(
            &PolicyDataKind::SecurityPolicy,
            "test",
            1,
            &SecurityEpoch::from_raw(5),
        );
        let id2 = SignedPolicyArtifact::compute_artifact_id(
            &PolicyDataKind::SecurityPolicy,
            "test",
            1,
            &SecurityEpoch::from_raw(6),
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn artifact_id_differs_by_version() {
        let id1 = SignedPolicyArtifact::compute_artifact_id(
            &PolicyDataKind::SecurityPolicy,
            "test",
            1,
            &test_epoch(),
        );
        let id2 = SignedPolicyArtifact::compute_artifact_id(
            &PolicyDataKind::SecurityPolicy,
            "test",
            2,
            &test_epoch(),
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn preimage_bytes_differ_by_name() {
        let a1 = test_signed_artifact();
        let mut a2 = test_signed_artifact();
        a2.policy_name = "other-policy".to_string();
        assert_ne!(a1.preimage_bytes(), a2.preimage_bytes());
    }

    #[test]
    fn preimage_bytes_differ_by_kind() {
        let a1 = test_signed_artifact();
        let mut a2 = test_signed_artifact();
        a2.kind = PolicyDataKind::FallbackPolicy;
        assert_ne!(a1.preimage_bytes(), a2.preimage_bytes());
    }

    #[test]
    fn preimage_bytes_differ_by_epoch() {
        let a1 = test_signed_artifact();
        let mut a2 = test_signed_artifact();
        a2.epoch = SecurityEpoch::from_raw(99);
        assert_ne!(a1.preimage_bytes(), a2.preimage_bytes());
    }

    #[test]
    fn sandbox_unlimited_memory_never_exceeds() {
        let sandbox = SandboxRestriction {
            restriction_id: "unlimited-mem".to_string(),
            description: "unlimited memory".to_string(),
            allowed_capabilities: BTreeSet::new(),
            allow_network: false,
            allow_fs_write: false,
            max_memory_bytes: 0,
            max_execution_ns: 5_000_000_000,
            allow_process_spawn: false,
        };
        assert!(!sandbox.would_exceed_memory(u64::MAX));
    }

    #[test]
    fn sandbox_unlimited_time_never_exceeds() {
        let sandbox = SandboxRestriction {
            restriction_id: "unlimited-time".to_string(),
            description: "unlimited time".to_string(),
            allowed_capabilities: BTreeSet::new(),
            allow_network: false,
            allow_fs_write: false,
            max_memory_bytes: 64 * 1024 * 1024,
            max_execution_ns: 0,
            allow_process_spawn: false,
        };
        assert!(!sandbox.would_exceed_time(u64::MAX));
    }

    #[test]
    fn canonical_security_profile_is_deny_all() {
        let profiles = canonical_sandbox_profiles();
        let security = profiles
            .iter()
            .find(|p| p.name == "security_policy")
            .expect("serde deserialization should succeed");
        assert!(security.restriction.allowed_capabilities.is_empty());
        assert!(!security.restriction.allow_network);
        assert!(!security.restriction.allow_fs_write);
        assert!(!security.restriction.allow_process_spawn);
    }

    #[test]
    fn canonical_governance_profile_allows_read_evidence() {
        let profiles = canonical_sandbox_profiles();
        let governance = profiles
            .iter()
            .find(|p| p.name == "governance_policy")
            .expect("serde deserialization should succeed");
        assert!(governance.restriction.is_allowed("read_evidence"));
        assert!(!governance.restriction.is_allowed("write_policy"));
    }

    #[test]
    fn suite_pass_rate_multiple_categories() {
        let mut suite = AdversarialSuite::new("multi".to_string(), test_epoch());
        suite.add_scenario(AdversarialScenario {
            scenario_id: "s-1".to_string(),
            name: "tamper".to_string(),
            category: ScenarioCategory::PolicyTampering,
            expected_outcome: ExpectedOutcome::Blocked,
            description: "test".to_string(),
            severity_millionths: MILLION,
            target_kinds: BTreeSet::new(),
        });
        suite.add_scenario(AdversarialScenario {
            scenario_id: "s-2".to_string(),
            name: "replay".to_string(),
            category: ScenarioCategory::ReplayAttack,
            expected_outcome: ExpectedOutcome::Blocked,
            description: "test".to_string(),
            severity_millionths: MILLION,
            target_kinds: BTreeSet::new(),
        });
        suite.record_result(ScenarioResult {
            scenario_id: "s-1".to_string(),
            actual_outcome: ExpectedOutcome::Blocked,
            passed: true,
            detail: "ok".to_string(),
            evidence_hash: "h1".to_string(),
        });
        suite.record_result(ScenarioResult {
            scenario_id: "s-2".to_string(),
            actual_outcome: ExpectedOutcome::Blocked,
            passed: true,
            detail: "ok".to_string(),
            evidence_hash: "h2".to_string(),
        });
        let rates = suite.pass_rate_by_category();
        assert_eq!(rates.len(), 2);
        assert_eq!(rates.get("policy_tampering"), Some(&MILLION));
        assert_eq!(rates.get("replay_attack"), Some(&MILLION));
    }

    #[test]
    fn suite_pass_rate_unknown_scenario_ignored() {
        let mut suite = AdversarialSuite::new("test".to_string(), test_epoch());
        suite.record_result(ScenarioResult {
            scenario_id: "nonexistent".to_string(),
            actual_outcome: ExpectedOutcome::Blocked,
            passed: true,
            detail: "ok".to_string(),
            evidence_hash: "h".to_string(),
        });
        let rates = suite.pass_rate_by_category();
        assert!(rates.is_empty());
    }

    #[test]
    fn playbook_max_level_empty_steps() {
        let pb = FailurePlaybook::new(
            "empty".to_string(),
            ScenarioCategory::PolicyTampering,
            vec![],
            false,
        );
        assert_eq!(pb.max_level(), None);
        assert_eq!(pb.step_count(), 0);
    }

    #[test]
    fn playbook_content_hash_differs_on_step_change() {
        let steps_a = vec![PlaybookStep {
            step: 1,
            level: EscalationLevel::Alert,
            action: "alert".to_string(),
            escalation_condition: "cond".to_string(),
            max_duration_ns: 0,
        }];
        let steps_b = vec![PlaybookStep {
            step: 1,
            level: EscalationLevel::Emergency,
            action: "suspend".to_string(),
            escalation_condition: "cond".to_string(),
            max_duration_ns: 0,
        }];
        let p1 = FailurePlaybook::new(
            "pb".to_string(),
            ScenarioCategory::PolicyTampering,
            steps_a,
            false,
        );
        let p2 = FailurePlaybook::new(
            "pb".to_string(),
            ScenarioCategory::PolicyTampering,
            steps_b,
            false,
        );
        assert_ne!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn canonical_playbooks_have_correct_categories() {
        let playbooks = canonical_failure_playbooks();
        let cats: BTreeSet<_> = playbooks.iter().map(|p| p.scenario_category).collect();
        assert!(cats.contains(&ScenarioCategory::PolicyTampering));
        assert!(cats.contains(&ScenarioCategory::ResourceExhaustion));
    }

    #[test]
    fn generate_report_zero_artifacts() {
        let suite = AdversarialSuite::new("test".to_string(), test_epoch());
        let report = generate_report(&test_epoch(), 0, 0, &suite, 2, 1);
        // artifact_rate = MILLION (no artifacts = no risk), adversarial = 0, playbook = MILLION
        // posture = (MILLION*400000 + 0*400000 + MILLION*200000) / MILLION = 600000
        assert_eq!(report.security_posture_millionths, 600_000);
    }

    #[test]
    fn generate_report_zero_playbooks() {
        let suite = AdversarialSuite::new("test".to_string(), test_epoch());
        let report = generate_report(&test_epoch(), 1, 1, &suite, 0, 1);
        // artifact_rate = MILLION, adversarial = 0, playbook_rate = 0
        // posture = (MILLION*400000 + 0*400000 + 0*200000) / MILLION = 400000
        assert_eq!(report.security_posture_millionths, 400_000);
    }

    #[test]
    fn report_hash_changes_on_input_change() {
        let suite = AdversarialSuite::new("test".to_string(), test_epoch());
        let r1 = generate_report(&test_epoch(), 10, 10, &suite, 1, 1);
        let r2 = generate_report(&test_epoch(), 10, 5, &suite, 1, 1);
        assert_ne!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn verification_result_all_valid_false() {
        let result = PolicyVerificationResult {
            artifact_id: "pol-tampered".to_string(),
            definition_hash_valid: false,
            signature_valid: true,
            epoch_current: true,
            all_valid: false,
            detail: "definition hash mismatch".to_string(),
        };
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let back: PolicyVerificationResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, back);
        assert!(!back.all_valid);
        assert!(!back.definition_hash_valid);
    }

    #[test]
    fn playbook_step_serde_roundtrip() {
        let step = PlaybookStep {
            step: 2,
            level: EscalationLevel::Mitigate,
            action: "quarantine artifact".to_string(),
            escalation_condition: "repeated from multiple sources".to_string(),
            max_duration_ns: 60_000_000_000,
        };
        let json = serde_json::to_string(&step).expect("serde deserialization should succeed");
        let back: PlaybookStep =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(step, back);
    }

    #[test]
    fn adversarial_scenario_serde_roundtrip() {
        let scenario = AdversarialScenario {
            scenario_id: "adv-test".to_string(),
            name: "Test scenario".to_string(),
            category: ScenarioCategory::ContainmentEscape,
            expected_outcome: ExpectedOutcome::Blocked,
            description: "escape attempt".to_string(),
            severity_millionths: 800_000,
            target_kinds: BTreeSet::from([PolicyDataKind::ContainmentPolicy]),
        };
        let json = serde_json::to_string(&scenario).expect("serde deserialization should succeed");
        let back: AdversarialScenario =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(scenario, back);
    }

    #[test]
    fn scenario_result_serde_roundtrip() {
        let result = ScenarioResult {
            scenario_id: "s-1".to_string(),
            actual_outcome: ExpectedOutcome::FallbackTriggered,
            passed: false,
            detail: "expected blocked, got fallback".to_string(),
            evidence_hash: "abc123".to_string(),
        };
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let back: ScenarioResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, back);
    }

    #[test]
    fn policy_sandbox_profile_serde_roundtrip() {
        let profile = PolicySandboxProfile {
            name: "test-profile".to_string(),
            applicable_kinds: BTreeSet::from([PolicyDataKind::LaneRouting]),
            restriction: SandboxRestriction::deny_all("sandbox-test".to_string()),
            is_default: false,
        };
        let json = serde_json::to_string(&profile).expect("serde deserialization should succeed");
        let back: PolicySandboxProfile =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(profile, back);
    }

    #[test]
    fn sandbox_memory_at_boundary() {
        let sandbox = SandboxRestriction::deny_all("test".to_string());
        let limit = sandbox.max_memory_bytes;
        assert!(!sandbox.would_exceed_memory(limit));
        assert!(sandbox.would_exceed_memory(limit + 1));
    }

    #[test]
    fn sandbox_time_at_boundary() {
        let sandbox = SandboxRestriction::deny_all("test".to_string());
        let limit = sandbox.max_execution_ns;
        assert!(!sandbox.would_exceed_time(limit));
        assert!(sandbox.would_exceed_time(limit + 1));
    }

    #[test]
    fn suite_all_pass_false_when_empty() {
        let suite = AdversarialSuite::new("empty".to_string(), test_epoch());
        assert!(!suite.all_pass());
    }

    #[test]
    fn canonical_scenarios_severity_range() {
        let scenarios = canonical_adversarial_scenarios();
        for s in &scenarios {
            assert!(
                s.severity_millionths > 0 && s.severity_millionths <= MILLION,
                "severity out of range for {}",
                s.scenario_id
            );
        }
    }

    #[test]
    fn canonical_scenarios_all_have_target_kinds() {
        let scenarios = canonical_adversarial_scenarios();
        for s in &scenarios {
            assert!(
                !s.target_kinds.is_empty(),
                "scenario {} has no target kinds",
                s.scenario_id
            );
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display uniqueness, serde, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn policy_data_kind_display_all_unique() {
        let kinds = [
            PolicyDataKind::LaneRouting,
            PolicyDataKind::SecurityPolicy,
            PolicyDataKind::ContainmentPolicy,
            PolicyDataKind::GovernancePolicy,
            PolicyDataKind::FallbackPolicy,
            PolicyDataKind::OptimizationPolicy,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for k in &kinds {
            seen.insert(format!("{k:?}"));
        }
        assert_eq!(
            seen.len(),
            6,
            "all 6 PolicyDataKind Debug strings must be unique"
        );
    }

    #[test]
    fn scenario_category_display_all_unique() {
        let cats = [
            ScenarioCategory::PolicyTampering,
            ScenarioCategory::ReplayAttack,
            ScenarioCategory::PrivilegeEscalation,
            ScenarioCategory::ResourceExhaustion,
            ScenarioCategory::ContainmentEscape,
            ScenarioCategory::FallbackSuppression,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for c in &cats {
            seen.insert(c.to_string());
        }
        assert_eq!(
            seen.len(),
            6,
            "all 6 ScenarioCategory Display strings must be unique"
        );
    }

    #[test]
    fn expected_outcome_display_all_unique() {
        let outcomes = [
            ExpectedOutcome::Blocked,
            ExpectedOutcome::FallbackTriggered,
            ExpectedOutcome::Contained,
            ExpectedOutcome::DetectedOnly,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for o in &outcomes {
            seen.insert(o.to_string());
        }
        assert_eq!(
            seen.len(),
            4,
            "all 4 ExpectedOutcome Display strings must be unique"
        );
    }

    #[test]
    fn escalation_level_display_all_unique() {
        let levels = [
            EscalationLevel::Observe,
            EscalationLevel::Alert,
            EscalationLevel::Mitigate,
            EscalationLevel::Escalate,
            EscalationLevel::Emergency,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for l in &levels {
            seen.insert(l.to_string());
        }
        assert_eq!(
            seen.len(),
            5,
            "all 5 EscalationLevel Display strings must be unique"
        );
    }

    #[test]
    fn signed_artifact_serde_roundtrip_full() {
        let artifact = test_signed_artifact();
        let json = serde_json::to_string(&artifact).expect("serde deserialization should succeed");
        let restored: SignedPolicyArtifact =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(artifact, restored);
    }

    #[test]
    fn sandbox_deny_all_has_no_capabilities() {
        let sandbox = SandboxRestriction::deny_all("test".to_string());
        assert!(sandbox.allowed_capabilities.is_empty());
        assert!(!sandbox.allow_network);
        assert!(!sandbox.allow_fs_write);
        assert!(!sandbox.allow_process_spawn);
    }

    #[test]
    fn sandbox_is_allowed_returns_false_for_absent_cap() {
        let sandbox = SandboxRestriction::deny_all("test".to_string());
        assert!(!sandbox.is_allowed("anything"));
    }

    #[test]
    fn canonical_sandbox_profiles_all_have_restrictions() {
        let profiles = canonical_sandbox_profiles();
        for p in &profiles {
            assert!(!p.restriction.restriction_id.is_empty());
            assert!(!p.restriction.description.is_empty());
        }
    }

    #[test]
    fn schema_version_constant_is_stable() {
        assert_eq!(SCHEMA_VERSION, "franken-engine.policy-as-data-security.v1");
    }
}
