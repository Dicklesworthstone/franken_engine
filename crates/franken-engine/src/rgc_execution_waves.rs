//! RGC execution-wave coordination protocol.
//!
//! This module defines a deterministic coordination contract for multi-agent
//! execution waves, including:
//! - wave mapping (parallel lanes + hard serial dependencies),
//! - file reservation and inbox polling requirements,
//! - anti-stall escalation thresholds,
//! - handoff package validation,
//! - a dry-run helper that emits structured coordination events.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION: &str =
    "franken-engine.rgc-execution-wave-protocol.v1";
pub const RGC_WAVE_HANDOFF_SCHEMA_VERSION: &str = "franken-engine.rgc-wave-handoff.v1";
pub const RGC_COORDINATION_EVENT_SCHEMA_VERSION: &str = "franken-engine.rgc-coordination.event.v1";
pub const RGC_COORDINATION_COMPONENT: &str = "rgc_execution_waves";

/// Deterministic execution waves used by the RGC program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExecutionWave {
    #[serde(rename = "wave_0")]
    Wave0,
    #[serde(rename = "wave_1")]
    Wave1,
    #[serde(rename = "wave_2")]
    Wave2,
    #[serde(rename = "wave_3")]
    Wave3,
}

impl ExecutionWave {
    pub const ALL: [Self; 4] = [Self::Wave0, Self::Wave1, Self::Wave2, Self::Wave3];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wave0 => "wave_0",
            Self::Wave1 => "wave_1",
            Self::Wave2 => "wave_2",
            Self::Wave3 => "wave_3",
        }
    }

    pub const fn order_index(self) -> usize {
        match self {
            Self::Wave0 => 0,
            Self::Wave1 => 1,
            Self::Wave2 => 2,
            Self::Wave3 => 3,
        }
    }
}

/// One wave's ownership and dependency boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WavePlanEntry {
    pub wave: ExecutionWave,
    pub parallel_bead_ids: Vec<String>,
    pub serial_bead_ids: Vec<String>,
    pub required_predecessor_waves: Vec<ExecutionWave>,
    pub entry_criteria: Vec<String>,
    pub exit_criteria: Vec<String>,
}

impl WavePlanEntry {
    fn all_bead_ids(&self) -> impl Iterator<Item = &String> {
        self.parallel_bead_ids
            .iter()
            .chain(self.serial_bead_ids.iter())
    }
}

/// File reservation policy for active wave execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileReservationProtocol {
    pub exclusive_required: bool,
    pub min_ttl_seconds: u64,
    pub renew_before_seconds: u64,
    pub max_paths_per_claim: u32,
}

/// Agent-mail polling and acknowledgement policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMailProtocol {
    pub poll_interval_seconds: u64,
    pub urgent_poll_interval_seconds: u64,
    pub ack_required_within_seconds: u64,
}

/// Escalation thresholds for anti-stall automation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiStallThresholds {
    pub warn_after_seconds: u64,
    pub escalate_after_seconds: u64,
    pub reassign_after_seconds: u64,
    pub split_after_seconds: u64,
}

/// Complete wave coordination protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWaveProtocol {
    pub schema_version: String,
    pub policy_id: String,
    pub wave_order: Vec<ExecutionWave>,
    pub waves: Vec<WavePlanEntry>,
    pub file_reservation: FileReservationProtocol,
    pub agent_mail: AgentMailProtocol,
    pub anti_stall: AntiStallThresholds,
}

/// Standard handoff package used to transition ownership across waves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveHandoffPackage {
    pub schema_version: String,
    pub wave: ExecutionWave,
    pub from_owner: String,
    pub to_owner: String,
    pub changed_beads: Vec<String>,
    pub artifact_links: Vec<String>,
    pub open_risks: Vec<String>,
    pub next_steps: Vec<String>,
}

/// Structured event for coordination logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

impl CoordinationEvent {
    fn pass(trace_id: &str, decision_id: &str, policy_id: &str, event: &str) -> Self {
        Self {
            schema_version: RGC_COORDINATION_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_string(),
            component: RGC_COORDINATION_COMPONENT.to_string(),
            event: event.to_string(),
            outcome: "pass".to_string(),
            error_code: None,
        }
    }
}

/// Anti-stall action selected for a given idle interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntiStallAction {
    Healthy,
    Warn,
    Escalate,
    Reassign,
    Split,
}

impl AntiStallAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warn => "warn",
            Self::Escalate => "escalate",
            Self::Reassign => "reassign",
            Self::Split => "split",
        }
    }
}

/// Result of a deterministic coordination dry run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationDryRunReport {
    pub action: AntiStallAction,
    pub events: Vec<CoordinationEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoordinationValidationError {
    InvalidSchemaVersion {
        field: String,
        expected: String,
        actual: String,
    },
    EmptyField {
        field: String,
    },
    DuplicateWaveEntry {
        wave: String,
    },
    MissingWaveEntry {
        wave: String,
    },
    DuplicateBeadOwnership {
        bead_id: String,
    },
    InvalidPredecessor {
        wave: String,
        predecessor: String,
    },
    InvalidThresholdOrder,
    InvalidMailPolicy,
    InvalidReservationPolicy,
    UnknownWaveForHandoff {
        wave: String,
    },
    MissingWaveEntryForHandoffSource {
        wave: String,
    },
    DuplicateHandoffFieldValue {
        field: String,
        value: String,
    },
    ChangedBeadOutsideSourceWave {
        bead_id: String,
        source_wave: String,
    },
    MissingRequiredArtifactLink {
        required_suffix: String,
    },
    MissingTargetWaveNextStep {
        wave: String,
    },
    HandoffOwnersMustDiffer,
}

impl std::fmt::Display for CoordinationValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSchemaVersion {
                field,
                expected,
                actual,
            } => write!(
                f,
                "invalid schema version for {} (expected {}, got {})",
                field, expected, actual
            ),
            Self::EmptyField { field } => write!(f, "empty required field: {field}"),
            Self::DuplicateWaveEntry { wave } => write!(f, "duplicate wave entry: {wave}"),
            Self::MissingWaveEntry { wave } => write!(f, "missing wave entry: {wave}"),
            Self::DuplicateBeadOwnership { bead_id } => {
                write!(f, "bead assigned to multiple waves: {bead_id}")
            }
            Self::InvalidPredecessor { wave, predecessor } => {
                write!(f, "invalid predecessor {predecessor} for {wave}")
            }
            Self::InvalidThresholdOrder => {
                write!(f, "anti-stall thresholds are not strictly ordered")
            }
            Self::InvalidMailPolicy => write!(f, "agent-mail policy violates cadence constraints"),
            Self::InvalidReservationPolicy => write!(f, "file reservation policy is invalid"),
            Self::UnknownWaveForHandoff { wave } => {
                write!(f, "handoff references unknown wave: {wave}")
            }
            Self::MissingWaveEntryForHandoffSource { wave } => {
                write!(f, "handoff source wave is missing from protocol: {wave}")
            }
            Self::DuplicateHandoffFieldValue { field, value } => {
                write!(
                    f,
                    "handoff field `{field}` contains duplicate value `{value}`"
                )
            }
            Self::ChangedBeadOutsideSourceWave {
                bead_id,
                source_wave,
            } => write!(
                f,
                "handoff changed bead `{bead_id}` is not owned by source wave `{source_wave}`"
            ),
            Self::MissingRequiredArtifactLink { required_suffix } => {
                write!(
                    f,
                    "handoff artifact_links missing required artifact suffix `{required_suffix}`"
                )
            }
            Self::MissingTargetWaveNextStep { wave } => {
                write!(
                    f,
                    "handoff next_steps missing explicit target-wave bead reference for {wave}"
                )
            }
            Self::HandoffOwnersMustDiffer => {
                write!(f, "handoff from_owner and to_owner must differ")
            }
        }
    }
}

impl std::error::Error for CoordinationValidationError {}

/// Default protocol for RGC multi-agent wave execution.
pub fn default_rgc_execution_wave_protocol() -> ExecutionWaveProtocol {
    ExecutionWaveProtocol {
        schema_version: RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION.to_string(),
        policy_id: "policy-rgc-execution-waves-v1".to_string(),
        wave_order: ExecutionWave::ALL.to_vec(),
        waves: vec![
            WavePlanEntry {
                wave: ExecutionWave::Wave0,
                parallel_bead_ids: vec![
                    "bd-1lsy.1.1".to_string(),
                    "bd-1lsy.1.4".to_string(),
                    "bd-1lsy.1.5".to_string(),
                ],
                serial_bead_ids: vec!["bd-1lsy.1.2".to_string(), "bd-1lsy.1.3".to_string()],
                required_predecessor_waves: Vec::new(),
                entry_criteria: vec![
                    "program charter is in_progress".to_string(),
                    "agent-mail identities are registered".to_string(),
                ],
                exit_criteria: vec![
                    "ownership handoff packet emitted".to_string(),
                    "wave summary includes blockers and replay commands".to_string(),
                ],
            },
            WavePlanEntry {
                wave: ExecutionWave::Wave1,
                parallel_bead_ids: vec![
                    "bd-1lsy.2.1".to_string(),
                    "bd-1lsy.3.1".to_string(),
                    "bd-1lsy.2.2".to_string(),
                ],
                serial_bead_ids: vec!["bd-1lsy.2.4".to_string()],
                required_predecessor_waves: vec![ExecutionWave::Wave0],
                entry_criteria: vec![
                    "wave_0 handoff packet accepted".to_string(),
                    "parser and ts-lane ownership boundaries acknowledged".to_string(),
                ],
                exit_criteria: vec![
                    "frontend parity evidence published".to_string(),
                    "unsupported syntax ledger updated".to_string(),
                ],
            },
            WavePlanEntry {
                wave: ExecutionWave::Wave2,
                parallel_bead_ids: vec![
                    "bd-1lsy.4.1".to_string(),
                    "bd-1lsy.5.1".to_string(),
                    "bd-1lsy.6.1".to_string(),
                ],
                serial_bead_ids: vec!["bd-1lsy.4.6".to_string()],
                required_predecessor_waves: vec![ExecutionWave::Wave1],
                entry_criteria: vec![
                    "wave_1 handoff packet accepted".to_string(),
                    "core runtime compatibility matrix is frozen for the wave".to_string(),
                ],
                exit_criteria: vec![
                    "runtime security and module evidence bundles published".to_string(),
                    "rollback drills are replayable".to_string(),
                ],
            },
            WavePlanEntry {
                wave: ExecutionWave::Wave3,
                parallel_bead_ids: vec![
                    "bd-1lsy.7.1".to_string(),
                    "bd-1lsy.8.1".to_string(),
                    "bd-1lsy.10.4".to_string(),
                ],
                serial_bead_ids: vec!["bd-1lsy.10.9".to_string()],
                required_predecessor_waves: vec![ExecutionWave::Wave2],
                entry_criteria: vec![
                    "wave_2 handoff packet accepted".to_string(),
                    "release-gate replay wrappers are green in report-only mode".to_string(),
                ],
                exit_criteria: vec![
                    "ga evidence package includes third-party replay commands".to_string(),
                    "remaining risks and follow-up beads are cataloged".to_string(),
                ],
            },
        ],
        file_reservation: FileReservationProtocol {
            exclusive_required: true,
            min_ttl_seconds: 3600,
            renew_before_seconds: 900,
            max_paths_per_claim: 12,
        },
        agent_mail: AgentMailProtocol {
            poll_interval_seconds: 120,
            urgent_poll_interval_seconds: 30,
            ack_required_within_seconds: 300,
        },
        anti_stall: AntiStallThresholds {
            warn_after_seconds: 900,
            escalate_after_seconds: 1800,
            reassign_after_seconds: 2700,
            split_after_seconds: 3600,
        },
    }
}

/// Default handoff package used by dry-run checks.
pub fn default_wave_handoff_package() -> WaveHandoffPackage {
    WaveHandoffPackage {
        schema_version: RGC_WAVE_HANDOFF_SCHEMA_VERSION.to_string(),
        wave: ExecutionWave::Wave1,
        from_owner: "Wave0Lead".to_string(),
        to_owner: "Wave1Lead".to_string(),
        changed_beads: vec!["bd-1lsy.1.4".to_string(), "bd-1lsy.1.5".to_string()],
        artifact_links: vec![
            "artifacts/rgc_execution_waves_coordination/20260228T000000Z/run_manifest.json"
                .to_string(),
            "artifacts/rgc_execution_waves_coordination/20260228T000000Z/events.jsonl".to_string(),
            "artifacts/rgc_execution_waves_coordination/20260228T000000Z/commands.txt".to_string(),
        ],
        open_risks: vec!["No active blockers at handoff time".to_string()],
        next_steps: vec![
            "Claim bd-1lsy.2.1 parser grammar lane".to_string(),
            "Claim bd-1lsy.3.1 deterministic TS ingestion lane".to_string(),
            "Reserve file scopes before edits".to_string(),
        ],
    }
}

/// Validate full wave execution protocol.
pub fn validate_execution_wave_protocol(
    protocol: &ExecutionWaveProtocol,
) -> Result<(), CoordinationValidationError> {
    if protocol.schema_version != RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION {
        return Err(CoordinationValidationError::InvalidSchemaVersion {
            field: "protocol.schema_version".to_string(),
            expected: RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION.to_string(),
            actual: protocol.schema_version.clone(),
        });
    }
    if protocol.policy_id.trim().is_empty() {
        return Err(CoordinationValidationError::EmptyField {
            field: "protocol.policy_id".to_string(),
        });
    }

    let mut seen_order = BTreeSet::new();
    for wave in &protocol.wave_order {
        if !seen_order.insert(*wave) {
            return Err(CoordinationValidationError::DuplicateWaveEntry {
                wave: wave.as_str().to_string(),
            });
        }
    }

    let mut seen_wave_entries = BTreeSet::new();
    let mut owned_beads = BTreeSet::new();
    for entry in &protocol.waves {
        if !seen_wave_entries.insert(entry.wave) {
            return Err(CoordinationValidationError::DuplicateWaveEntry {
                wave: entry.wave.as_str().to_string(),
            });
        }
        if entry.entry_criteria.is_empty() {
            return Err(CoordinationValidationError::EmptyField {
                field: format!("{}.entry_criteria", entry.wave.as_str()),
            });
        }
        if entry.exit_criteria.is_empty() {
            return Err(CoordinationValidationError::EmptyField {
                field: format!("{}.exit_criteria", entry.wave.as_str()),
            });
        }

        for predecessor in &entry.required_predecessor_waves {
            if predecessor.order_index() >= entry.wave.order_index() {
                return Err(CoordinationValidationError::InvalidPredecessor {
                    wave: entry.wave.as_str().to_string(),
                    predecessor: predecessor.as_str().to_string(),
                });
            }
        }

        for bead_id in entry.all_bead_ids() {
            if bead_id.trim().is_empty() {
                return Err(CoordinationValidationError::EmptyField {
                    field: format!("{}.bead_id", entry.wave.as_str()),
                });
            }
            if !owned_beads.insert(bead_id.clone()) {
                return Err(CoordinationValidationError::DuplicateBeadOwnership {
                    bead_id: bead_id.clone(),
                });
            }
        }
    }

    for wave in &protocol.wave_order {
        if !seen_wave_entries.contains(wave) {
            return Err(CoordinationValidationError::MissingWaveEntry {
                wave: wave.as_str().to_string(),
            });
        }
    }

    let thresholds = &protocol.anti_stall;
    if !(thresholds.warn_after_seconds < thresholds.escalate_after_seconds
        && thresholds.escalate_after_seconds < thresholds.reassign_after_seconds
        && thresholds.reassign_after_seconds < thresholds.split_after_seconds)
    {
        return Err(CoordinationValidationError::InvalidThresholdOrder);
    }

    let mail = &protocol.agent_mail;
    if !(mail.urgent_poll_interval_seconds > 0
        && mail.poll_interval_seconds > 0
        && mail.urgent_poll_interval_seconds <= mail.poll_interval_seconds
        && mail.ack_required_within_seconds >= mail.poll_interval_seconds)
    {
        return Err(CoordinationValidationError::InvalidMailPolicy);
    }

    let reservation = &protocol.file_reservation;
    if !(reservation.min_ttl_seconds >= 60
        && reservation.renew_before_seconds > 0
        && reservation.renew_before_seconds < reservation.min_ttl_seconds
        && reservation.max_paths_per_claim > 0)
    {
        return Err(CoordinationValidationError::InvalidReservationPolicy);
    }

    Ok(())
}

fn wave_entry(protocol: &ExecutionWaveProtocol, wave: ExecutionWave) -> Option<&WavePlanEntry> {
    protocol.waves.iter().find(|entry| entry.wave == wave)
}

fn previous_wave(target_wave: ExecutionWave) -> Option<ExecutionWave> {
    match target_wave {
        ExecutionWave::Wave0 => None,
        ExecutionWave::Wave1 => Some(ExecutionWave::Wave0),
        ExecutionWave::Wave2 => Some(ExecutionWave::Wave1),
        ExecutionWave::Wave3 => Some(ExecutionWave::Wave2),
    }
}

fn source_wave_for_handoff(target_wave: ExecutionWave) -> ExecutionWave {
    previous_wave(target_wave).unwrap_or(ExecutionWave::Wave0)
}

fn assert_unique_values(field: &str, values: &[String]) -> Result<(), CoordinationValidationError> {
    let mut seen = BTreeSet::<&str>::new();
    for value in values {
        if !seen.insert(value.as_str()) {
            return Err(CoordinationValidationError::DuplicateHandoffFieldValue {
                field: field.to_string(),
                value: value.clone(),
            });
        }
    }
    Ok(())
}

/// Validate one handoff package against a protocol.
pub fn validate_wave_handoff_package(
    protocol: &ExecutionWaveProtocol,
    package: &WaveHandoffPackage,
) -> Result<(), CoordinationValidationError> {
    if package.schema_version != RGC_WAVE_HANDOFF_SCHEMA_VERSION {
        return Err(CoordinationValidationError::InvalidSchemaVersion {
            field: "handoff.schema_version".to_string(),
            expected: RGC_WAVE_HANDOFF_SCHEMA_VERSION.to_string(),
            actual: package.schema_version.clone(),
        });
    }

    if package.from_owner.trim().is_empty() {
        return Err(CoordinationValidationError::EmptyField {
            field: "handoff.from_owner".to_string(),
        });
    }
    if package.to_owner.trim().is_empty() {
        return Err(CoordinationValidationError::EmptyField {
            field: "handoff.to_owner".to_string(),
        });
    }
    if package.from_owner.trim() == package.to_owner.trim() {
        return Err(CoordinationValidationError::HandoffOwnersMustDiffer);
    }
    if package.changed_beads.is_empty() {
        return Err(CoordinationValidationError::EmptyField {
            field: "handoff.changed_beads".to_string(),
        });
    }
    if package.artifact_links.is_empty() {
        return Err(CoordinationValidationError::EmptyField {
            field: "handoff.artifact_links".to_string(),
        });
    }
    if package.next_steps.is_empty() {
        return Err(CoordinationValidationError::EmptyField {
            field: "handoff.next_steps".to_string(),
        });
    }
    assert_unique_values("handoff.changed_beads", &package.changed_beads)?;
    assert_unique_values("handoff.artifact_links", &package.artifact_links)?;
    assert_unique_values("handoff.next_steps", &package.next_steps)?;

    let Some(target_wave_entry) = wave_entry(protocol, package.wave) else {
        return Err(CoordinationValidationError::UnknownWaveForHandoff {
            wave: package.wave.as_str().to_string(),
        });
    };

    let source_wave = source_wave_for_handoff(package.wave);
    let Some(source_wave_entry) = wave_entry(protocol, source_wave) else {
        return Err(
            CoordinationValidationError::MissingWaveEntryForHandoffSource {
                wave: source_wave.as_str().to_string(),
            },
        );
    };

    let source_wave_beads = source_wave_entry
        .all_bead_ids()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for changed_bead in &package.changed_beads {
        if !source_wave_beads.contains(changed_bead.as_str()) {
            return Err(CoordinationValidationError::ChangedBeadOutsideSourceWave {
                bead_id: changed_bead.clone(),
                source_wave: source_wave.as_str().to_string(),
            });
        }
    }

    for required_suffix in ["run_manifest.json", "events.jsonl", "commands.txt"] {
        if !package
            .artifact_links
            .iter()
            .any(|link| link.ends_with(required_suffix))
        {
            return Err(CoordinationValidationError::MissingRequiredArtifactLink {
                required_suffix: required_suffix.to_string(),
            });
        }
    }

    let target_wave_beads = target_wave_entry
        .all_bead_ids()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let has_target_wave_next_step = package.next_steps.iter().any(|next_step| {
        target_wave_beads
            .iter()
            .any(|target_bead| next_step.contains(target_bead))
    });
    if !has_target_wave_next_step {
        return Err(CoordinationValidationError::MissingTargetWaveNextStep {
            wave: package.wave.as_str().to_string(),
        });
    }

    Ok(())
}

/// Select anti-stall action for the current idle interval.
pub fn select_anti_stall_action(
    thresholds: &AntiStallThresholds,
    idle_seconds: u64,
) -> AntiStallAction {
    if idle_seconds >= thresholds.split_after_seconds {
        AntiStallAction::Split
    } else if idle_seconds >= thresholds.reassign_after_seconds {
        AntiStallAction::Reassign
    } else if idle_seconds >= thresholds.escalate_after_seconds {
        AntiStallAction::Escalate
    } else if idle_seconds >= thresholds.warn_after_seconds {
        AntiStallAction::Warn
    } else {
        AntiStallAction::Healthy
    }
}

/// Execute a deterministic dry run over protocol and handoff validation.
pub fn run_coordination_dry_run(
    protocol: &ExecutionWaveProtocol,
    package: &WaveHandoffPackage,
    idle_seconds: u64,
    trace_id: &str,
    decision_id: &str,
) -> Result<CoordinationDryRunReport, CoordinationValidationError> {
    validate_execution_wave_protocol(protocol)?;
    validate_wave_handoff_package(protocol, package)?;

    let action = select_anti_stall_action(&protocol.anti_stall, idle_seconds);
    let policy_id = protocol.policy_id.as_str();
    let events = vec![
        CoordinationEvent::pass(trace_id, decision_id, policy_id, "protocol_validated"),
        CoordinationEvent::pass(trace_id, decision_id, policy_id, "handoff_validated"),
        CoordinationEvent::pass(
            trace_id,
            decision_id,
            policy_id,
            &format!("anti_stall_{}", action.as_str()),
        ),
        CoordinationEvent::pass(trace_id, decision_id, policy_id, "dry_run_completed"),
    ];

    Ok(CoordinationDryRunReport { action, events })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_protocol_is_valid() {
        let protocol = default_rgc_execution_wave_protocol();
        validate_execution_wave_protocol(&protocol).expect("default protocol should validate");
    }

    #[test]
    fn duplicate_bead_ownership_is_rejected() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.waves[1]
            .parallel_bead_ids
            .push("bd-1lsy.1.4".to_string());

        let error =
            validate_execution_wave_protocol(&protocol).expect_err("must reject duplicate bead");
        assert!(matches!(
            error,
            CoordinationValidationError::DuplicateBeadOwnership { .. }
        ));
    }

    #[test]
    fn threshold_order_must_be_strict() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.anti_stall.reassign_after_seconds = protocol.anti_stall.escalate_after_seconds;

        let error =
            validate_execution_wave_protocol(&protocol).expect_err("must reject invalid ordering");
        assert!(matches!(
            error,
            CoordinationValidationError::InvalidThresholdOrder
        ));
    }

    #[test]
    fn anti_stall_action_boundaries_are_stable() {
        let thresholds = AntiStallThresholds {
            warn_after_seconds: 10,
            escalate_after_seconds: 20,
            reassign_after_seconds: 30,
            split_after_seconds: 40,
        };

        assert_eq!(
            select_anti_stall_action(&thresholds, 0),
            AntiStallAction::Healthy
        );
        assert_eq!(
            select_anti_stall_action(&thresholds, 10),
            AntiStallAction::Warn
        );
        assert_eq!(
            select_anti_stall_action(&thresholds, 20),
            AntiStallAction::Escalate
        );
        assert_eq!(
            select_anti_stall_action(&thresholds, 30),
            AntiStallAction::Reassign
        );
        assert_eq!(
            select_anti_stall_action(&thresholds, 40),
            AntiStallAction::Split
        );
    }

    #[test]
    fn handoff_requires_artifacts_and_next_steps() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.artifact_links.clear();

        let error = validate_wave_handoff_package(&protocol, &package)
            .expect_err("missing artifact links should fail");
        assert!(matches!(
            error,
            CoordinationValidationError::EmptyField { .. }
        ));

        package.artifact_links = vec![
            "a/run_manifest.json".to_string(),
            "a/events.jsonl".to_string(),
            "a/commands.txt".to_string(),
        ];
        package.next_steps.clear();
        let error = validate_wave_handoff_package(&protocol, &package)
            .expect_err("missing next steps should fail");
        assert!(matches!(
            error,
            CoordinationValidationError::EmptyField { .. }
        ));
    }

    #[test]
    fn handoff_requires_distinct_owners() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.to_owner = package.from_owner.clone();

        let error = validate_wave_handoff_package(&protocol, &package)
            .expect_err("handoff owners must differ");
        assert!(matches!(
            error,
            CoordinationValidationError::HandoffOwnersMustDiffer
        ));
    }

    #[test]
    fn handoff_rejects_duplicate_changed_beads() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.changed_beads.push("bd-1lsy.1.4".to_string());

        let error = validate_wave_handoff_package(&protocol, &package)
            .expect_err("duplicate changed_beads should fail");
        assert!(matches!(
            error,
            CoordinationValidationError::DuplicateHandoffFieldValue { .. }
        ));
    }

    #[test]
    fn handoff_requires_artifact_triad_suffixes() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.artifact_links = vec![
            "artifacts/run_manifest.json".to_string(),
            "artifacts/events.jsonl".to_string(),
            "artifacts/summary.md".to_string(),
        ];

        let error = validate_wave_handoff_package(&protocol, &package)
            .expect_err("artifact triad suffixes should be required");
        assert!(matches!(
            error,
            CoordinationValidationError::MissingRequiredArtifactLink { .. }
        ));
    }

    #[test]
    fn handoff_rejects_changed_bead_outside_source_wave() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.changed_beads = vec!["bd-1lsy.2.1".to_string()];

        let error = validate_wave_handoff_package(&protocol, &package)
            .expect_err("changed_beads must belong to source wave");
        assert!(matches!(
            error,
            CoordinationValidationError::ChangedBeadOutsideSourceWave { .. }
        ));
    }

    #[test]
    fn handoff_requires_target_wave_bead_reference_in_next_steps() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.next_steps = vec!["Review pending risks".to_string()];

        let error = validate_wave_handoff_package(&protocol, &package)
            .expect_err("next_steps must reference at least one target-wave bead");
        assert!(matches!(
            error,
            CoordinationValidationError::MissingTargetWaveNextStep { .. }
        ));
    }

    #[test]
    fn dry_run_emits_expected_events() {
        let protocol = default_rgc_execution_wave_protocol();
        let package = default_wave_handoff_package();

        let report = run_coordination_dry_run(
            &protocol,
            &package,
            2_100,
            "trace-rgc-test",
            "decision-rgc-test",
        )
        .expect("dry run should succeed");

        assert_eq!(report.action, AntiStallAction::Escalate);
        assert_eq!(report.events.len(), 4);
        assert_eq!(report.events[0].event, "protocol_validated");
        assert_eq!(report.events[1].event, "handoff_validated");
        assert_eq!(report.events[2].event, "anti_stall_escalate");
        assert_eq!(report.events[3].event, "dry_run_completed");

        for event in &report.events {
            assert_eq!(event.schema_version, RGC_COORDINATION_EVENT_SCHEMA_VERSION);
            assert_eq!(event.component, RGC_COORDINATION_COMPONENT);
            assert_eq!(event.trace_id, "trace-rgc-test");
            assert_eq!(event.decision_id, "decision-rgc-test");
            assert_eq!(event.outcome, "pass");
            assert_eq!(event.error_code, None);
        }
    }

    // ── ExecutionWave ──

    #[test]
    fn execution_wave_all_has_four_entries() {
        assert_eq!(ExecutionWave::ALL.len(), 4);
        assert_eq!(ExecutionWave::ALL[0], ExecutionWave::Wave0);
        assert_eq!(ExecutionWave::ALL[3], ExecutionWave::Wave3);
    }

    #[test]
    fn execution_wave_as_str_covers_all_variants() {
        assert_eq!(ExecutionWave::Wave0.as_str(), "wave_0");
        assert_eq!(ExecutionWave::Wave1.as_str(), "wave_1");
        assert_eq!(ExecutionWave::Wave2.as_str(), "wave_2");
        assert_eq!(ExecutionWave::Wave3.as_str(), "wave_3");
    }

    #[test]
    fn execution_wave_order_index_is_sequential() {
        assert_eq!(ExecutionWave::Wave0.order_index(), 0);
        assert_eq!(ExecutionWave::Wave1.order_index(), 1);
        assert_eq!(ExecutionWave::Wave2.order_index(), 2);
        assert_eq!(ExecutionWave::Wave3.order_index(), 3);
    }

    #[test]
    fn execution_wave_ordering_matches_index() {
        assert!(ExecutionWave::Wave0 < ExecutionWave::Wave1);
        assert!(ExecutionWave::Wave1 < ExecutionWave::Wave2);
        assert!(ExecutionWave::Wave2 < ExecutionWave::Wave3);
    }

    #[test]
    fn execution_wave_serde_roundtrip() {
        for wave in ExecutionWave::ALL {
            let json = serde_json::to_string(&wave).expect("serde deserialization should succeed");
            let back: ExecutionWave =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(wave, back);
        }
    }

    #[test]
    fn execution_wave_serde_tags_are_stable() {
        assert_eq!(
            serde_json::to_string(&ExecutionWave::Wave0)
                .expect("serde deserialization should succeed"),
            "\"wave_0\""
        );
        assert_eq!(
            serde_json::to_string(&ExecutionWave::Wave1)
                .expect("serde deserialization should succeed"),
            "\"wave_1\""
        );
        assert_eq!(
            serde_json::to_string(&ExecutionWave::Wave2)
                .expect("serde deserialization should succeed"),
            "\"wave_2\""
        );
        assert_eq!(
            serde_json::to_string(&ExecutionWave::Wave3)
                .expect("serde deserialization should succeed"),
            "\"wave_3\""
        );
    }

    // ── WavePlanEntry ──

    #[test]
    fn wave_plan_entry_all_bead_ids_combines_both_lists() {
        let entry = WavePlanEntry {
            wave: ExecutionWave::Wave0,
            parallel_bead_ids: vec!["a".to_string(), "b".to_string()],
            serial_bead_ids: vec!["c".to_string()],
            required_predecessor_waves: Vec::new(),
            entry_criteria: vec!["entry".to_string()],
            exit_criteria: vec!["exit".to_string()],
        };
        let all: Vec<_> = entry.all_bead_ids().cloned().collect();
        assert_eq!(all, vec!["a", "b", "c"]);
    }

    #[test]
    fn wave_plan_entry_serde_roundtrip() {
        let entry = WavePlanEntry {
            wave: ExecutionWave::Wave1,
            parallel_bead_ids: vec!["bd-1".to_string()],
            serial_bead_ids: vec!["bd-2".to_string()],
            required_predecessor_waves: vec![ExecutionWave::Wave0],
            entry_criteria: vec!["c1".to_string()],
            exit_criteria: vec!["c2".to_string()],
        };
        let json = serde_json::to_string(&entry).expect("serde deserialization should succeed");
        let back: WavePlanEntry =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(entry, back);
    }

    // ── FileReservationProtocol ──

    #[test]
    fn file_reservation_protocol_serde_roundtrip() {
        let proto = FileReservationProtocol {
            exclusive_required: true,
            min_ttl_seconds: 3600,
            renew_before_seconds: 900,
            max_paths_per_claim: 12,
        };
        let json = serde_json::to_string(&proto).expect("serde deserialization should succeed");
        let back: FileReservationProtocol =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(proto, back);
    }

    // ── AgentMailProtocol ──

    #[test]
    fn agent_mail_protocol_serde_roundtrip() {
        let proto = AgentMailProtocol {
            poll_interval_seconds: 120,
            urgent_poll_interval_seconds: 30,
            ack_required_within_seconds: 300,
        };
        let json = serde_json::to_string(&proto).expect("serde deserialization should succeed");
        let back: AgentMailProtocol =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(proto, back);
    }

    // ── AntiStallThresholds ──

    #[test]
    fn anti_stall_thresholds_serde_roundtrip() {
        let t = AntiStallThresholds {
            warn_after_seconds: 900,
            escalate_after_seconds: 1800,
            reassign_after_seconds: 2700,
            split_after_seconds: 3600,
        };
        let json = serde_json::to_string(&t).expect("serde deserialization should succeed");
        let back: AntiStallThresholds =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(t, back);
    }

    // ── AntiStallAction ──

    #[test]
    fn anti_stall_action_as_str_covers_all_variants() {
        assert_eq!(AntiStallAction::Healthy.as_str(), "healthy");
        assert_eq!(AntiStallAction::Warn.as_str(), "warn");
        assert_eq!(AntiStallAction::Escalate.as_str(), "escalate");
        assert_eq!(AntiStallAction::Reassign.as_str(), "reassign");
        assert_eq!(AntiStallAction::Split.as_str(), "split");
    }

    #[test]
    fn anti_stall_action_serde_roundtrip() {
        let actions = [
            AntiStallAction::Healthy,
            AntiStallAction::Warn,
            AntiStallAction::Escalate,
            AntiStallAction::Reassign,
            AntiStallAction::Split,
        ];
        for action in actions {
            let json =
                serde_json::to_string(&action).expect("serde deserialization should succeed");
            let back: AntiStallAction =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(action, back);
        }
    }

    // ── select_anti_stall_action: boundary testing ──

    #[test]
    fn anti_stall_action_one_below_warn_is_healthy() {
        let thresholds = AntiStallThresholds {
            warn_after_seconds: 10,
            escalate_after_seconds: 20,
            reassign_after_seconds: 30,
            split_after_seconds: 40,
        };
        assert_eq!(
            select_anti_stall_action(&thresholds, 9),
            AntiStallAction::Healthy
        );
    }

    #[test]
    fn anti_stall_action_above_split_is_still_split() {
        let thresholds = AntiStallThresholds {
            warn_after_seconds: 10,
            escalate_after_seconds: 20,
            reassign_after_seconds: 30,
            split_after_seconds: 40,
        };
        assert_eq!(
            select_anti_stall_action(&thresholds, 1000),
            AntiStallAction::Split
        );
    }

    #[test]
    fn anti_stall_action_between_warn_and_escalate() {
        let thresholds = AntiStallThresholds {
            warn_after_seconds: 10,
            escalate_after_seconds: 20,
            reassign_after_seconds: 30,
            split_after_seconds: 40,
        };
        assert_eq!(
            select_anti_stall_action(&thresholds, 15),
            AntiStallAction::Warn
        );
    }

    #[test]
    fn anti_stall_action_between_reassign_and_split() {
        let thresholds = AntiStallThresholds {
            warn_after_seconds: 10,
            escalate_after_seconds: 20,
            reassign_after_seconds: 30,
            split_after_seconds: 40,
        };
        assert_eq!(
            select_anti_stall_action(&thresholds, 35),
            AntiStallAction::Reassign
        );
    }

    // ── CoordinationEvent ──

    #[test]
    fn coordination_event_pass_factory_sets_outcome() {
        let event = CoordinationEvent::pass("t1", "d1", "p1", "test_event");
        assert_eq!(event.outcome, "pass");
        assert_eq!(event.error_code, None);
        assert_eq!(event.schema_version, RGC_COORDINATION_EVENT_SCHEMA_VERSION);
        assert_eq!(event.component, RGC_COORDINATION_COMPONENT);
    }

    #[test]
    fn coordination_event_serde_roundtrip() {
        let event = CoordinationEvent::pass("t", "d", "p", "e");
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let back: CoordinationEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, back);
    }

    // ── CoordinationDryRunReport ──

    #[test]
    fn dry_run_report_serde_roundtrip() {
        let report = CoordinationDryRunReport {
            action: AntiStallAction::Warn,
            events: vec![CoordinationEvent::pass("t", "d", "p", "test")],
        };
        let json = serde_json::to_string(&report).expect("serde deserialization should succeed");
        let back: CoordinationDryRunReport =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(report, back);
    }

    // ── CoordinationValidationError: Display ──

    #[test]
    fn validation_error_display_invalid_schema_version() {
        let err = CoordinationValidationError::InvalidSchemaVersion {
            field: "test".to_string(),
            expected: "v1".to_string(),
            actual: "v2".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("test"));
        assert!(msg.contains("v1"));
        assert!(msg.contains("v2"));
    }

    #[test]
    fn validation_error_display_empty_field() {
        let err = CoordinationValidationError::EmptyField {
            field: "policy_id".to_string(),
        };
        assert!(err.to_string().contains("policy_id"));
    }

    #[test]
    fn validation_error_display_duplicate_wave() {
        let err = CoordinationValidationError::DuplicateWaveEntry {
            wave: "wave_1".to_string(),
        };
        assert!(err.to_string().contains("wave_1"));
    }

    #[test]
    fn validation_error_display_missing_wave() {
        let err = CoordinationValidationError::MissingWaveEntry {
            wave: "wave_2".to_string(),
        };
        assert!(err.to_string().contains("wave_2"));
    }

    #[test]
    fn validation_error_display_duplicate_bead() {
        let err = CoordinationValidationError::DuplicateBeadOwnership {
            bead_id: "bd-test".to_string(),
        };
        assert!(err.to_string().contains("bd-test"));
    }

    #[test]
    fn validation_error_display_invalid_predecessor() {
        let err = CoordinationValidationError::InvalidPredecessor {
            wave: "wave_0".to_string(),
            predecessor: "wave_1".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("wave_0"));
        assert!(msg.contains("wave_1"));
    }

    #[test]
    fn validation_error_display_threshold_order() {
        let err = CoordinationValidationError::InvalidThresholdOrder;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn validation_error_display_mail_policy() {
        let err = CoordinationValidationError::InvalidMailPolicy;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn validation_error_display_reservation_policy() {
        let err = CoordinationValidationError::InvalidReservationPolicy;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn validation_error_display_unknown_wave_for_handoff() {
        let err = CoordinationValidationError::UnknownWaveForHandoff {
            wave: "wave_99".to_string(),
        };
        assert!(err.to_string().contains("wave_99"));
    }

    #[test]
    fn validation_error_display_missing_required_artifact_link() {
        let err = CoordinationValidationError::MissingRequiredArtifactLink {
            required_suffix: "commands.txt".to_string(),
        };
        assert!(err.to_string().contains("commands.txt"));
    }

    #[test]
    fn validation_error_display_changed_bead_outside_source_wave() {
        let err = CoordinationValidationError::ChangedBeadOutsideSourceWave {
            bead_id: "bd-x".to_string(),
            source_wave: "wave_0".to_string(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("bd-x"));
        assert!(rendered.contains("wave_0"));
    }

    #[test]
    fn validation_error_display_handoff_owners_must_differ() {
        let err = CoordinationValidationError::HandoffOwnersMustDiffer;
        assert!(err.to_string().contains("must differ"));
    }

    #[test]
    fn validation_error_is_error_trait() {
        let err = CoordinationValidationError::InvalidThresholdOrder;
        let _: &dyn std::error::Error = &err;
    }

    // ── validate_execution_wave_protocol: edge cases ──

    #[test]
    fn protocol_invalid_schema_version() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.schema_version = "wrong-version".to_string();
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::InvalidSchemaVersion { .. }
        ));
    }

    #[test]
    fn protocol_empty_policy_id() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.policy_id = "".to_string();
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::EmptyField { .. }
        ));
    }

    #[test]
    fn protocol_whitespace_only_policy_id() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.policy_id = "   ".to_string();
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::EmptyField { .. }
        ));
    }

    #[test]
    fn protocol_duplicate_wave_in_wave_order() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.wave_order.push(ExecutionWave::Wave0);
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::DuplicateWaveEntry { .. }
        ));
    }

    #[test]
    fn protocol_empty_entry_criteria() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.waves[0].entry_criteria.clear();
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::EmptyField { .. }
        ));
    }

    #[test]
    fn protocol_empty_exit_criteria() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.waves[0].exit_criteria.clear();
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::EmptyField { .. }
        ));
    }

    #[test]
    fn protocol_invalid_predecessor_same_wave() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.waves[1]
            .required_predecessor_waves
            .push(ExecutionWave::Wave1);
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::InvalidPredecessor { .. }
        ));
    }

    #[test]
    fn protocol_invalid_predecessor_later_wave() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.waves[0]
            .required_predecessor_waves
            .push(ExecutionWave::Wave2);
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::InvalidPredecessor { .. }
        ));
    }

    #[test]
    fn protocol_empty_bead_id() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.waves[0].parallel_bead_ids.push("".to_string());
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::EmptyField { .. }
        ));
    }

    #[test]
    fn protocol_missing_wave_entry_for_wave_in_order() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.waves.pop();
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::MissingWaveEntry { .. }
        ));
    }

    #[test]
    fn protocol_invalid_mail_policy_urgent_greater_than_normal() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.agent_mail.urgent_poll_interval_seconds = 200;
        protocol.agent_mail.poll_interval_seconds = 100;
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::InvalidMailPolicy
        ));
    }

    #[test]
    fn protocol_invalid_mail_policy_zero_urgent() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.agent_mail.urgent_poll_interval_seconds = 0;
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::InvalidMailPolicy
        ));
    }

    #[test]
    fn protocol_invalid_mail_policy_ack_below_poll() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.agent_mail.ack_required_within_seconds = 10;
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::InvalidMailPolicy
        ));
    }

    #[test]
    fn protocol_invalid_reservation_min_ttl_too_low() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.file_reservation.min_ttl_seconds = 30;
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::InvalidReservationPolicy
        ));
    }

    #[test]
    fn protocol_invalid_reservation_renew_before_zero() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.file_reservation.renew_before_seconds = 0;
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::InvalidReservationPolicy
        ));
    }

    #[test]
    fn protocol_invalid_reservation_renew_exceeds_ttl() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.file_reservation.renew_before_seconds =
            protocol.file_reservation.min_ttl_seconds + 1;
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::InvalidReservationPolicy
        ));
    }

    #[test]
    fn protocol_invalid_reservation_zero_max_paths() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.file_reservation.max_paths_per_claim = 0;
        let err = validate_execution_wave_protocol(&protocol).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::InvalidReservationPolicy
        ));
    }

    // ── validate_wave_handoff_package: edge cases ──

    #[test]
    fn handoff_invalid_schema_version() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.schema_version = "wrong".to_string();
        let err = validate_wave_handoff_package(&protocol, &package).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::InvalidSchemaVersion { .. }
        ));
    }

    #[test]
    fn handoff_empty_from_owner() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.from_owner = "".to_string();
        let err = validate_wave_handoff_package(&protocol, &package).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::EmptyField { .. }
        ));
    }

    #[test]
    fn handoff_whitespace_to_owner() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.to_owner = "   ".to_string();
        let err = validate_wave_handoff_package(&protocol, &package).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::EmptyField { .. }
        ));
    }

    #[test]
    fn handoff_empty_changed_beads() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.changed_beads.clear();
        let err = validate_wave_handoff_package(&protocol, &package).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::EmptyField { .. }
        ));
    }

    #[test]
    fn handoff_empty_artifact_links() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.artifact_links.clear();
        let err = validate_wave_handoff_package(&protocol, &package).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::EmptyField { .. }
        ));
    }

    #[test]
    fn handoff_empty_next_steps() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.next_steps.clear();
        let err = validate_wave_handoff_package(&protocol, &package).unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::EmptyField { .. }
        ));
    }

    // ── run_coordination_dry_run: variations ──

    #[test]
    fn dry_run_healthy_idle() {
        let protocol = default_rgc_execution_wave_protocol();
        let package = default_wave_handoff_package();
        let report = run_coordination_dry_run(&protocol, &package, 0, "t", "d")
            .expect("serde deserialization should succeed");
        assert_eq!(report.action, AntiStallAction::Healthy);
    }

    #[test]
    fn dry_run_split_idle() {
        let protocol = default_rgc_execution_wave_protocol();
        let package = default_wave_handoff_package();
        let report = run_coordination_dry_run(
            &protocol,
            &package,
            protocol.anti_stall.split_after_seconds + 100,
            "t",
            "d",
        )
        .expect("serde deserialization should succeed");
        assert_eq!(report.action, AntiStallAction::Split);
    }

    #[test]
    fn dry_run_propagates_protocol_validation_error() {
        let mut protocol = default_rgc_execution_wave_protocol();
        protocol.schema_version = "bad".to_string();
        let package = default_wave_handoff_package();
        let err = run_coordination_dry_run(&protocol, &package, 0, "t", "d").unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::InvalidSchemaVersion { .. }
        ));
    }

    #[test]
    fn dry_run_propagates_handoff_validation_error() {
        let protocol = default_rgc_execution_wave_protocol();
        let mut package = default_wave_handoff_package();
        package.from_owner = "".to_string();
        let err = run_coordination_dry_run(&protocol, &package, 0, "t", "d").unwrap_err();
        assert!(matches!(
            err,
            CoordinationValidationError::EmptyField { .. }
        ));
    }

    // ── WaveHandoffPackage ──

    #[test]
    fn default_handoff_package_serde_roundtrip() {
        let package = default_wave_handoff_package();
        let json = serde_json::to_string(&package).expect("serde deserialization should succeed");
        let back: WaveHandoffPackage =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(package, back);
    }

    #[test]
    fn default_handoff_package_is_valid() {
        let protocol = default_rgc_execution_wave_protocol();
        let package = default_wave_handoff_package();
        validate_wave_handoff_package(&protocol, &package)
            .expect("default handoff should be valid");
    }

    // ── ExecutionWaveProtocol ──

    #[test]
    fn default_protocol_serde_roundtrip() {
        let protocol = default_rgc_execution_wave_protocol();
        let json = serde_json::to_string(&protocol).expect("serde deserialization should succeed");
        let back: ExecutionWaveProtocol =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(protocol, back);
    }

    #[test]
    fn default_protocol_has_all_four_waves() {
        let protocol = default_rgc_execution_wave_protocol();
        assert_eq!(protocol.wave_order.len(), 4);
        assert_eq!(protocol.waves.len(), 4);
    }

    #[test]
    fn default_protocol_wave_order_matches_entries() {
        let protocol = default_rgc_execution_wave_protocol();
        for (i, wave) in protocol.wave_order.iter().enumerate() {
            assert_eq!(protocol.waves[i].wave, *wave);
        }
    }

    // ── Constants ──

    #[test]
    fn schema_constants_are_nonempty() {
        assert!(!RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION.is_empty());
        assert!(!RGC_WAVE_HANDOFF_SCHEMA_VERSION.is_empty());
        assert!(!RGC_COORDINATION_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!RGC_COORDINATION_COMPONENT.is_empty());
    }

    // ── CoordinationValidationError serde ──

    #[test]
    fn coordination_validation_error_serde_roundtrip_all_variants() {
        let variants = [
            CoordinationValidationError::InvalidSchemaVersion {
                field: "f".to_string(),
                expected: "e".to_string(),
                actual: "a".to_string(),
            },
            CoordinationValidationError::EmptyField {
                field: "f".to_string(),
            },
            CoordinationValidationError::DuplicateWaveEntry {
                wave: "w".to_string(),
            },
            CoordinationValidationError::MissingWaveEntry {
                wave: "w".to_string(),
            },
            CoordinationValidationError::DuplicateBeadOwnership {
                bead_id: "b".to_string(),
            },
            CoordinationValidationError::InvalidPredecessor {
                wave: "w".to_string(),
                predecessor: "p".to_string(),
            },
            CoordinationValidationError::InvalidThresholdOrder,
            CoordinationValidationError::InvalidMailPolicy,
            CoordinationValidationError::InvalidReservationPolicy,
            CoordinationValidationError::UnknownWaveForHandoff {
                wave: "w".to_string(),
            },
        ];
        for variant in variants {
            let json =
                serde_json::to_string(&variant).expect("serde deserialization should succeed");
            let back: CoordinationValidationError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(variant, back);
        }
    }
}
