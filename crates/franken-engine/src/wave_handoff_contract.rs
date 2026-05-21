//! RGC wave-level entry/exit and ownership handoff validation contract.
//!
//! This module is intentionally self-contained so integration tests can import
//! it without requiring top-level crate wiring while parallel edits are active.

use serde::{Deserialize, Serialize};

pub const WAVE_HANDOFF_CONTRACT_VERSION: &str = "franken-engine.rgc-wave-handoff.contract.v1";
pub const WAVE_HANDOFF_PACKET_SCHEMA_VERSION: &str = "frx.handoff.packet.v1";
pub const WAVE_HANDOFF_COMPONENT: &str = "rgc_wave_handoff_contract";
pub const WAVE_HANDOFF_FAILURE_CODE: &str = "FE-RGC-015-HANDOFF-0001";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaveId {
    Wave0,
    Wave1,
    Wave2,
    Wave3,
}

impl WaveId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wave0 => "wave_0",
            Self::Wave1 => "wave_1",
            Self::Wave2 => "wave_2",
            Self::Wave3 => "wave_3",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredBeadStatus {
    Open,
    InProgress,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveCriterion {
    pub criterion_id: String,
    pub bead_id: String,
    pub required_status: RequiredBeadStatus,
    pub required_artifact: String,
    pub mandatory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveTransitionContract {
    pub contract_version: String,
    pub packet_schema_version: String,
    pub wave_id: WaveId,
    pub minimum_handoff_score_milli: u16,
    pub entry_criteria: Vec<WaveCriterion>,
    pub exit_criteria: Vec<WaveCriterion>,
}

impl WaveTransitionContract {
    pub fn baseline(wave_id: WaveId) -> Self {
        Self {
            contract_version: WAVE_HANDOFF_CONTRACT_VERSION.to_string(),
            packet_schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
            wave_id,
            minimum_handoff_score_milli: 850,
            entry_criteria: vec![WaveCriterion {
                criterion_id: "entry-ready-deps".to_string(),
                bead_id: "bd-1lsy.1".to_string(),
                required_status: RequiredBeadStatus::InProgress,
                required_artifact: "artifacts/rgc/wave_entry_manifest.json".to_string(),
                mandatory: true,
            }],
            exit_criteria: vec![
                WaveCriterion {
                    criterion_id: "exit-handoff-doc".to_string(),
                    bead_id: "bd-1lsy.1.5".to_string(),
                    required_status: RequiredBeadStatus::InProgress,
                    required_artifact: "docs/FRX_CROSS_TRACK_HANDOFF_PROTOCOL_V1.md".to_string(),
                    mandatory: true,
                },
                WaveCriterion {
                    criterion_id: "exit-handoff-schema".to_string(),
                    bead_id: "bd-1lsy.1.5".to_string(),
                    required_status: RequiredBeadStatus::InProgress,
                    required_artifact: "docs/frx_handoff_packet_schema_v1.json".to_string(),
                    mandatory: true,
                },
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriterionAttestation {
    pub criterion_id: String,
    pub bead_id: String,
    pub bead_status: RequiredBeadStatus,
    pub artifact_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffPackage {
    pub packet_id: String,
    pub wave_id: WaveId,
    pub producer_owner: String,
    pub consumer_owner: String,
    pub changed_beads: Vec<String>,
    pub artifact_links: Vec<String>,
    pub open_risks: Vec<String>,
    pub next_step_recommendations: Vec<String>,
    pub criteria_attestations: Vec<CriterionAttestation>,
    pub completeness_score_milli: u16,
}

impl HandoffPackage {
    pub fn baseline() -> Self {
        Self {
            packet_id: "pkt-rgc-wave-1-demo".to_string(),
            wave_id: WaveId::Wave1,
            producer_owner: "agent_alpha".to_string(),
            consumer_owner: "agent_beta".to_string(),
            changed_beads: vec!["bd-1lsy.1".to_string(), "bd-1lsy.1.5".to_string()],
            artifact_links: vec![
                "docs/FRX_CROSS_TRACK_HANDOFF_PROTOCOL_V1.md".to_string(),
                "docs/frx_handoff_packet_schema_v1.json".to_string(),
                "artifacts/rgc/wave_entry_manifest.json".to_string(),
            ],
            open_risks: vec!["none".to_string()],
            next_step_recommendations: vec![
                "claim first unblocked child bead".to_string(),
                "reserve file paths before edits".to_string(),
            ],
            criteria_attestations: vec![
                CriterionAttestation {
                    criterion_id: "entry-ready-deps".to_string(),
                    bead_id: "bd-1lsy.1".to_string(),
                    bead_status: RequiredBeadStatus::InProgress,
                    artifact_ref: "artifacts/rgc/wave_entry_manifest.json".to_string(),
                },
                CriterionAttestation {
                    criterion_id: "exit-handoff-doc".to_string(),
                    bead_id: "bd-1lsy.1.5".to_string(),
                    bead_status: RequiredBeadStatus::InProgress,
                    artifact_ref: "docs/FRX_CROSS_TRACK_HANDOFF_PROTOCOL_V1.md".to_string(),
                },
                CriterionAttestation {
                    criterion_id: "exit-handoff-schema".to_string(),
                    bead_id: "bd-1lsy.1.5".to_string(),
                    bead_status: RequiredBeadStatus::InProgress,
                    artifact_ref: "docs/frx_handoff_packet_schema_v1.json".to_string(),
                },
            ],
            completeness_score_milli: 920,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffValidationErrorCode {
    MissingRequiredField,
    WeakHandoffPackage,
    MissingCriterionAttestation,
    CriterionStatusMismatch,
    CriterionArtifactMissing,
    CriterionBeadMissing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffValidationFailure {
    pub code: HandoffValidationErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffValidationReport {
    pub contract_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub valid: bool,
    pub failures: Vec<HandoffValidationFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub wave_id: String,
    pub packet_id: String,
}

pub fn validate_handoff(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    contract: &WaveTransitionContract,
    package: &HandoffPackage,
) -> HandoffValidationReport {
    let mut failures = Vec::new();

    if package.packet_id.trim().is_empty() {
        failures.push(HandoffValidationFailure {
            code: HandoffValidationErrorCode::MissingRequiredField,
            message: "packet_id must not be empty".to_string(),
        });
    }
    if package.producer_owner.trim().is_empty() {
        failures.push(HandoffValidationFailure {
            code: HandoffValidationErrorCode::MissingRequiredField,
            message: "producer_owner must not be empty".to_string(),
        });
    }
    if package.consumer_owner.trim().is_empty() {
        failures.push(HandoffValidationFailure {
            code: HandoffValidationErrorCode::MissingRequiredField,
            message: "consumer_owner must not be empty".to_string(),
        });
    }
    if package.changed_beads.is_empty() {
        failures.push(HandoffValidationFailure {
            code: HandoffValidationErrorCode::MissingRequiredField,
            message: "changed_beads must not be empty".to_string(),
        });
    }
    if package.artifact_links.is_empty() {
        failures.push(HandoffValidationFailure {
            code: HandoffValidationErrorCode::MissingRequiredField,
            message: "artifact_links must not be empty".to_string(),
        });
    }
    if package.next_step_recommendations.is_empty() {
        failures.push(HandoffValidationFailure {
            code: HandoffValidationErrorCode::MissingRequiredField,
            message: "next_step_recommendations must not be empty".to_string(),
        });
    }
    if package.completeness_score_milli < contract.minimum_handoff_score_milli {
        failures.push(HandoffValidationFailure {
            code: HandoffValidationErrorCode::WeakHandoffPackage,
            message: format!(
                "completeness_score_milli {} is below required threshold {}",
                package.completeness_score_milli, contract.minimum_handoff_score_milli
            ),
        });
    }

    validate_criteria(&contract.entry_criteria, package, &mut failures, "entry");
    validate_criteria(&contract.exit_criteria, package, &mut failures, "exit");

    let valid = failures.is_empty();
    HandoffValidationReport {
        contract_version: contract.contract_version.clone(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: WAVE_HANDOFF_COMPONENT.to_string(),
        event: "validate_handoff".to_string(),
        outcome: if valid {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if valid {
            "none".to_string()
        } else {
            WAVE_HANDOFF_FAILURE_CODE.to_string()
        },
        valid,
        failures,
    }
}

pub fn simulate_wave_transition(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    contract: &WaveTransitionContract,
    package: &HandoffPackage,
) -> (HandoffValidationReport, Vec<HandoffEvent>) {
    let validation = validate_handoff(trace_id, decision_id, policy_id, contract, package);
    let outcome = if validation.valid { "pass" } else { "fail" };
    let error_code = if validation.valid {
        None
    } else {
        Some(WAVE_HANDOFF_FAILURE_CODE.to_string())
    };
    let wave_id = package.wave_id.as_str().to_string();
    let packet_id = package.packet_id.clone();

    let mut events = vec![HandoffEvent {
        schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: WAVE_HANDOFF_COMPONENT.to_string(),
        event: "handoff_received".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        wave_id: wave_id.clone(),
        packet_id: packet_id.clone(),
    }];
    events.push(HandoffEvent {
        schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: WAVE_HANDOFF_COMPONENT.to_string(),
        event: "criteria_validated".to_string(),
        outcome: outcome.to_string(),
        error_code: error_code.clone(),
        wave_id: wave_id.clone(),
        packet_id: packet_id.clone(),
    });
    events.push(HandoffEvent {
        schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: WAVE_HANDOFF_COMPONENT.to_string(),
        event: if validation.valid {
            "ownership_transition_committed".to_string()
        } else {
            "ownership_transition_rejected".to_string()
        },
        outcome: outcome.to_string(),
        error_code,
        wave_id,
        packet_id,
    });

    (validation, events)
}

fn validate_criteria(
    criteria: &[WaveCriterion],
    package: &HandoffPackage,
    failures: &mut Vec<HandoffValidationFailure>,
    phase: &str,
) {
    for criterion in criteria.iter().filter(|criterion| criterion.mandatory) {
        let Some(attestation) = package
            .criteria_attestations
            .iter()
            .find(|attestation| attestation.criterion_id == criterion.criterion_id)
        else {
            failures.push(HandoffValidationFailure {
                code: HandoffValidationErrorCode::MissingCriterionAttestation,
                message: format!(
                    "{phase} criterion `{}` is missing attestation",
                    criterion.criterion_id
                ),
            });
            continue;
        };

        if attestation.bead_status != criterion.required_status {
            failures.push(HandoffValidationFailure {
                code: HandoffValidationErrorCode::CriterionStatusMismatch,
                message: format!(
                    "{phase} criterion `{}` requires status {:?}, found {:?}",
                    criterion.criterion_id, criterion.required_status, attestation.bead_status
                ),
            });
        }

        if attestation.bead_id != criterion.bead_id {
            failures.push(HandoffValidationFailure {
                code: HandoffValidationErrorCode::CriterionBeadMissing,
                message: format!(
                    "{phase} criterion `{}` expected bead `{}` but attested `{}`",
                    criterion.criterion_id, criterion.bead_id, attestation.bead_id
                ),
            });
        }

        if attestation.artifact_ref != criterion.required_artifact {
            failures.push(HandoffValidationFailure {
                code: HandoffValidationErrorCode::CriterionArtifactMissing,
                message: format!(
                    "{phase} criterion `{}` expected artifact `{}` but attested `{}`",
                    criterion.criterion_id, criterion.required_artifact, attestation.artifact_ref
                ),
            });
        }

        if !package
            .changed_beads
            .iter()
            .any(|bead| bead == &attestation.bead_id)
        {
            failures.push(HandoffValidationFailure {
                code: HandoffValidationErrorCode::CriterionBeadMissing,
                message: format!(
                    "{phase} criterion `{}` attests bead `{}` not present in changed_beads",
                    criterion.criterion_id, attestation.bead_id
                ),
            });
        }

        if !package
            .artifact_links
            .iter()
            .any(|artifact| artifact == &attestation.artifact_ref)
        {
            failures.push(HandoffValidationFailure {
                code: HandoffValidationErrorCode::CriterionArtifactMissing,
                message: format!(
                    "{phase} criterion `{}` artifact `{}` missing from artifact_links",
                    criterion.criterion_id, attestation.artifact_ref
                ),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── WaveId ──

    #[test]
    fn wave_id_as_str_covers_all_variants() {
        assert_eq!(WaveId::Wave0.as_str(), "wave_0");
        assert_eq!(WaveId::Wave1.as_str(), "wave_1");
        assert_eq!(WaveId::Wave2.as_str(), "wave_2");
        assert_eq!(WaveId::Wave3.as_str(), "wave_3");
    }

    #[test]
    fn wave_id_ordering_is_sequential() {
        assert!(WaveId::Wave0 < WaveId::Wave1);
        assert!(WaveId::Wave1 < WaveId::Wave2);
        assert!(WaveId::Wave2 < WaveId::Wave3);
    }

    #[test]
    fn wave_id_serde_roundtrip() {
        for wave in [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3] {
            // SAFETY: WaveId derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json = serde_json::to_string(&wave).expect("serialize derived Serialize");
            // SAFETY: JSON was just produced by to_string of a valid WaveId,
            // so from_str back to WaveId cannot fail (valid format + matching schema).
            let back: WaveId = serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(wave, back);
        }
    }

    #[test]
    fn wave_id_serde_uses_snake_case() {
        // SAFETY: WaveId derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&WaveId::Wave0).expect("serialize derived Serialize");
        assert_eq!(json, "\"wave0\"");
    }

    // ── RequiredBeadStatus ──

    #[test]
    fn required_bead_status_serde_roundtrip() {
        for status in [
            RequiredBeadStatus::Open,
            RequiredBeadStatus::InProgress,
            RequiredBeadStatus::Closed,
        ] {
            // SAFETY: RequiredBeadStatus derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json = serde_json::to_string(&status).expect("serialize derived Serialize");
            // SAFETY: JSON was just produced by to_string of a valid RequiredBeadStatus,
            // so from_str back to RequiredBeadStatus cannot fail (valid format + matching schema).
            let back: RequiredBeadStatus =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(status, back);
        }
    }

    #[test]
    fn required_bead_status_ordering() {
        assert!(RequiredBeadStatus::Open < RequiredBeadStatus::InProgress);
        assert!(RequiredBeadStatus::InProgress < RequiredBeadStatus::Closed);
    }

    // ── WaveCriterion ──

    #[test]
    fn wave_criterion_serde_roundtrip() {
        let c = WaveCriterion {
            criterion_id: "test-crit".to_string(),
            bead_id: "bd-test".to_string(),
            required_status: RequiredBeadStatus::Closed,
            required_artifact: "artifacts/test.json".to_string(),
            mandatory: true,
        };
        // SAFETY: WaveCriterion derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&c).expect("serialize derived Serialize");
        // SAFETY: JSON was just produced by to_string of a valid WaveCriterion,
        // so from_str back to WaveCriterion cannot fail (valid format + matching schema).
        let back: WaveCriterion =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(c, back);
    }

    #[test]
    fn wave_criterion_optional_not_mandatory() {
        let c = WaveCriterion {
            criterion_id: "opt-crit".to_string(),
            bead_id: "bd-opt".to_string(),
            required_status: RequiredBeadStatus::Open,
            required_artifact: "artifacts/opt.json".to_string(),
            mandatory: false,
        };
        assert!(!c.mandatory);
    }

    // ── WaveTransitionContract ──

    #[test]
    fn baseline_contract_has_expected_wave() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave2);
        assert_eq!(contract.wave_id, WaveId::Wave2);
        assert_eq!(contract.contract_version, WAVE_HANDOFF_CONTRACT_VERSION);
        assert_eq!(
            contract.packet_schema_version,
            WAVE_HANDOFF_PACKET_SCHEMA_VERSION
        );
    }

    #[test]
    fn baseline_contract_has_entry_and_exit_criteria() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        assert!(!contract.entry_criteria.is_empty());
        assert!(!contract.exit_criteria.is_empty());
    }

    #[test]
    fn baseline_contract_minimum_score_is_reasonable() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave0);
        assert!(contract.minimum_handoff_score_milli > 0);
        assert!(contract.minimum_handoff_score_milli <= 1000);
    }

    #[test]
    fn wave_transition_contract_serde_roundtrip() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave3);
        // SAFETY: WaveTransitionContract derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&contract).expect("serialize derived Serialize");
        // SAFETY: JSON was just produced by to_string of a valid WaveTransitionContract,
        // so from_str back to WaveTransitionContract cannot fail (valid format + matching schema).
        let back: WaveTransitionContract =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(contract, back);
    }

    // ── HandoffPackage ──

    #[test]
    fn baseline_handoff_package_is_well_formed() {
        let pkg = HandoffPackage::baseline();
        assert!(!pkg.packet_id.is_empty());
        assert!(!pkg.producer_owner.is_empty());
        assert!(!pkg.consumer_owner.is_empty());
        assert!(!pkg.changed_beads.is_empty());
        assert!(!pkg.artifact_links.is_empty());
        assert!(!pkg.next_step_recommendations.is_empty());
        assert!(!pkg.criteria_attestations.is_empty());
        assert!(pkg.completeness_score_milli > 0);
    }

    #[test]
    fn handoff_package_serde_roundtrip() {
        let pkg = HandoffPackage::baseline();
        let json = serde_json::to_string(&pkg).expect("serialize derived Serialize");
        let back: HandoffPackage =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(pkg, back);
    }

    // ── CriterionAttestation ──

    #[test]
    fn criterion_attestation_serde_roundtrip() {
        let att = CriterionAttestation {
            criterion_id: "c1".to_string(),
            bead_id: "bd-1".to_string(),
            bead_status: RequiredBeadStatus::InProgress,
            artifact_ref: "artifacts/a.json".to_string(),
        };
        let json = serde_json::to_string(&att).expect("serialize derived Serialize");
        let back: CriterionAttestation =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(att, back);
    }

    // ── HandoffValidationErrorCode ──

    #[test]
    fn validation_error_code_serde_roundtrip() {
        let codes = [
            HandoffValidationErrorCode::MissingRequiredField,
            HandoffValidationErrorCode::WeakHandoffPackage,
            HandoffValidationErrorCode::MissingCriterionAttestation,
            HandoffValidationErrorCode::CriterionStatusMismatch,
            HandoffValidationErrorCode::CriterionArtifactMissing,
            HandoffValidationErrorCode::CriterionBeadMissing,
        ];
        for code in codes {
            let json = serde_json::to_string(&code).expect("serialize derived Serialize");
            let back: HandoffValidationErrorCode =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(code, back);
        }
    }

    // ── HandoffValidationFailure ──

    #[test]
    fn validation_failure_serde_roundtrip() {
        let f = HandoffValidationFailure {
            code: HandoffValidationErrorCode::WeakHandoffPackage,
            message: "score too low".to_string(),
        };
        let json = serde_json::to_string(&f).expect("serialize derived Serialize");
        let back: HandoffValidationFailure =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(f, back);
    }

    // ── HandoffValidationReport ──

    #[test]
    fn validation_report_serde_roundtrip() {
        let report = HandoffValidationReport {
            contract_version: WAVE_HANDOFF_CONTRACT_VERSION.to_string(),
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: WAVE_HANDOFF_COMPONENT.to_string(),
            event: "validate_handoff".to_string(),
            outcome: "pass".to_string(),
            error_code: "none".to_string(),
            valid: true,
            failures: Vec::new(),
        };
        let json = serde_json::to_string(&report).expect("serialize derived Serialize");
        let back: HandoffValidationReport =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(report, back);
    }

    // ── HandoffEvent ──

    #[test]
    fn handoff_event_serde_roundtrip() {
        let event = HandoffEvent {
            schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: WAVE_HANDOFF_COMPONENT.to_string(),
            event: "handoff_received".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            wave_id: "wave_1".to_string(),
            packet_id: "pkt-1".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let back: HandoffEvent = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, back);
    }

    #[test]
    fn handoff_event_with_error_code_roundtrip() {
        let event = HandoffEvent {
            schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
            trace_id: "t2".to_string(),
            decision_id: "d2".to_string(),
            policy_id: "p2".to_string(),
            component: WAVE_HANDOFF_COMPONENT.to_string(),
            event: "criteria_validated".to_string(),
            outcome: "fail".to_string(),
            error_code: Some(WAVE_HANDOFF_FAILURE_CODE.to_string()),
            wave_id: "wave_0".to_string(),
            packet_id: "pkt-2".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let back: HandoffEvent = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, back);
    }

    // ── validate_handoff: happy path ──

    #[test]
    fn validate_handoff_baseline_passes() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let pkg = HandoffPackage::baseline();
        let report = validate_handoff("t1", "d1", "p1", &contract, &pkg);
        assert!(report.valid, "baseline should pass: {:?}", report.failures);
        assert!(report.failures.is_empty());
        assert_eq!(report.outcome, "pass");
        assert_eq!(report.error_code, "none");
        assert_eq!(report.component, WAVE_HANDOFF_COMPONENT);
    }

    // ── validate_handoff: empty field failures ──

    #[test]
    fn validate_handoff_empty_packet_id() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.packet_id = "".to_string();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::MissingRequiredField)
                && f.message.contains("packet_id")
        }));
    }

    #[test]
    fn validate_handoff_whitespace_only_packet_id() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.packet_id = "   ".to_string();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::MissingRequiredField)
                && f.message.contains("packet_id")
        }));
    }

    #[test]
    fn validate_handoff_empty_producer_owner() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.producer_owner = "".to_string();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::MissingRequiredField)
                && f.message.contains("producer_owner")
        }));
    }

    #[test]
    fn validate_handoff_empty_consumer_owner() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.consumer_owner = "".to_string();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::MissingRequiredField)
                && f.message.contains("consumer_owner")
        }));
    }

    #[test]
    fn validate_handoff_empty_changed_beads() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.changed_beads.clear();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::MissingRequiredField)
                && f.message.contains("changed_beads")
        }));
    }

    #[test]
    fn validate_handoff_empty_artifact_links() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.artifact_links.clear();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::MissingRequiredField)
                && f.message.contains("artifact_links")
        }));
    }

    #[test]
    fn validate_handoff_empty_next_step_recommendations() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.next_step_recommendations.clear();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::MissingRequiredField)
                && f.message.contains("next_step_recommendations")
        }));
    }

    // ── validate_handoff: weak score ──

    #[test]
    fn validate_handoff_weak_completeness_score() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.completeness_score_milli = 100;
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert!(
            report
                .failures
                .iter()
                .any(|f| { matches!(f.code, HandoffValidationErrorCode::WeakHandoffPackage) })
        );
    }

    #[test]
    fn validate_handoff_score_exactly_at_threshold_passes() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.completeness_score_milli = contract.minimum_handoff_score_milli;
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        let weak_failures: Vec<_> = report
            .failures
            .iter()
            .filter(|f| matches!(f.code, HandoffValidationErrorCode::WeakHandoffPackage))
            .collect();
        assert!(
            weak_failures.is_empty(),
            "score at threshold should not produce weak failure"
        );
    }

    #[test]
    fn validate_handoff_score_one_below_threshold_fails() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.completeness_score_milli = contract.minimum_handoff_score_milli - 1;
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(
            report
                .failures
                .iter()
                .any(|f| { matches!(f.code, HandoffValidationErrorCode::WeakHandoffPackage) })
        );
    }

    // ── validate_handoff: criterion attestation ──

    #[test]
    fn validate_handoff_missing_attestation_for_mandatory_criterion() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.criteria_attestations.clear();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert!(report.failures.iter().any(|f| {
            matches!(
                f.code,
                HandoffValidationErrorCode::MissingCriterionAttestation
            )
        }));
    }

    #[test]
    fn validate_handoff_criterion_status_mismatch() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        for att in &mut pkg.criteria_attestations {
            att.bead_status = RequiredBeadStatus::Open;
        }
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(
            report
                .failures
                .iter()
                .any(|f| { matches!(f.code, HandoffValidationErrorCode::CriterionStatusMismatch) })
        );
    }

    #[test]
    fn validate_handoff_criterion_bead_id_mismatch() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        for att in &mut pkg.criteria_attestations {
            att.bead_id = "bd-wrong".to_string();
        }
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(
            report
                .failures
                .iter()
                .any(|f| { matches!(f.code, HandoffValidationErrorCode::CriterionBeadMissing) })
        );
    }

    #[test]
    fn validate_handoff_criterion_artifact_mismatch() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        for att in &mut pkg.criteria_attestations {
            att.artifact_ref = "wrong/path.json".to_string();
        }
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(
            report.failures.iter().any(|f| {
                matches!(f.code, HandoffValidationErrorCode::CriterionArtifactMissing)
            })
        );
    }

    #[test]
    fn validate_handoff_bead_not_in_changed_beads() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.changed_beads = vec!["bd-unrelated".to_string()];
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::CriterionBeadMissing)
                && f.message.contains("changed_beads")
        }));
    }

    #[test]
    fn validate_handoff_artifact_not_in_artifact_links() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.artifact_links = vec!["unrelated/path.json".to_string()];
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::CriterionArtifactMissing)
                && f.message.contains("artifact_links")
        }));
    }

    #[test]
    fn validate_handoff_optional_criterion_is_ignored() {
        let mut contract = WaveTransitionContract::baseline(WaveId::Wave1);
        contract.entry_criteria.push(WaveCriterion {
            criterion_id: "optional-crit".to_string(),
            bead_id: "bd-opt".to_string(),
            required_status: RequiredBeadStatus::Closed,
            required_artifact: "none".to_string(),
            mandatory: false,
        });
        let pkg = HandoffPackage::baseline();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        let optional_failures: Vec<_> = report
            .failures
            .iter()
            .filter(|f| f.message.contains("optional-crit"))
            .collect();
        assert!(
            optional_failures.is_empty(),
            "optional criterion should not produce failures"
        );
    }

    // ── validate_handoff: multiple failures accumulate ──

    #[test]
    fn validate_handoff_accumulates_multiple_failures() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.packet_id = "".to_string();
        pkg.producer_owner = "".to_string();
        pkg.completeness_score_milli = 0;
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert!(
            report.failures.len() >= 3,
            "should have at least 3 failures, got {}",
            report.failures.len()
        );
    }

    // ── validate_handoff: report metadata ──

    #[test]
    fn validate_handoff_report_contains_trace_ids() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let pkg = HandoffPackage::baseline();
        let report = validate_handoff("trace-abc", "decision-def", "policy-ghi", &contract, &pkg);
        assert_eq!(report.trace_id, "trace-abc");
        assert_eq!(report.decision_id, "decision-def");
        assert_eq!(report.policy_id, "policy-ghi");
    }

    #[test]
    fn validate_handoff_failure_report_has_error_code() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.packet_id = "".to_string();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert_eq!(report.error_code, WAVE_HANDOFF_FAILURE_CODE);
        assert_eq!(report.outcome, "fail");
    }

    // ── simulate_wave_transition ──

    #[test]
    fn simulate_transition_valid_package_passes() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let pkg = HandoffPackage::baseline();
        let (report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
        assert!(report.valid);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event, "handoff_received");
        assert_eq!(events[0].outcome, "ok");
        assert_eq!(events[1].event, "criteria_validated");
        assert_eq!(events[1].outcome, "pass");
        assert_eq!(events[2].event, "ownership_transition_committed");
        assert_eq!(events[2].outcome, "pass");
    }

    #[test]
    fn simulate_transition_invalid_package_is_rejected() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.packet_id = "".to_string();
        let (report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].event, "criteria_validated");
        assert_eq!(events[1].outcome, "fail");
        assert_eq!(
            events[1].error_code,
            Some(WAVE_HANDOFF_FAILURE_CODE.to_string())
        );
        assert_eq!(events[2].event, "ownership_transition_rejected");
    }

    #[test]
    fn simulate_transition_events_share_trace_ids() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let pkg = HandoffPackage::baseline();
        let (_report, events) =
            simulate_wave_transition("trace-X", "dec-Y", "pol-Z", &contract, &pkg);
        for event in &events {
            assert_eq!(event.trace_id, "trace-X");
            assert_eq!(event.decision_id, "dec-Y");
            assert_eq!(event.policy_id, "pol-Z");
            assert_eq!(event.component, WAVE_HANDOFF_COMPONENT);
            assert_eq!(event.schema_version, WAVE_HANDOFF_PACKET_SCHEMA_VERSION);
        }
    }

    #[test]
    fn simulate_transition_events_contain_wave_and_packet_id() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let pkg = HandoffPackage::baseline();
        let (_report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
        for event in &events {
            assert_eq!(event.wave_id, pkg.wave_id.as_str());
            assert_eq!(event.packet_id, pkg.packet_id);
        }
    }

    // ── Constants ──

    #[test]
    fn contract_constants_are_nonempty() {
        assert!(!WAVE_HANDOFF_CONTRACT_VERSION.is_empty());
        assert!(!WAVE_HANDOFF_PACKET_SCHEMA_VERSION.is_empty());
        assert!(!WAVE_HANDOFF_COMPONENT.is_empty());
        assert!(!WAVE_HANDOFF_FAILURE_CODE.is_empty());
    }

    // ── Edge cases ──

    #[test]
    fn validate_handoff_with_no_criteria_passes_field_checks() {
        let mut contract = WaveTransitionContract::baseline(WaveId::Wave1);
        contract.entry_criteria.clear();
        contract.exit_criteria.clear();
        let pkg = HandoffPackage::baseline();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        let criterion_failures: Vec<_> = report
            .failures
            .iter()
            .filter(|f| {
                matches!(
                    f.code,
                    HandoffValidationErrorCode::MissingCriterionAttestation
                        | HandoffValidationErrorCode::CriterionStatusMismatch
                        | HandoffValidationErrorCode::CriterionArtifactMissing
                        | HandoffValidationErrorCode::CriterionBeadMissing
                )
            })
            .collect();
        assert!(
            criterion_failures.is_empty(),
            "no criteria means no criterion failures"
        );
    }

    #[test]
    fn validate_handoff_zero_score_threshold_always_passes_score_check() {
        let mut contract = WaveTransitionContract::baseline(WaveId::Wave1);
        contract.minimum_handoff_score_milli = 0;
        let mut pkg = HandoffPackage::baseline();
        pkg.completeness_score_milli = 0;
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        let weak_failures: Vec<_> = report
            .failures
            .iter()
            .filter(|f| matches!(f.code, HandoffValidationErrorCode::WeakHandoffPackage))
            .collect();
        assert!(
            weak_failures.is_empty(),
            "0 >= 0 should not produce weak failure"
        );
    }

    #[test]
    fn baseline_contract_all_wave_ids_produce_valid_contracts() {
        for wave in [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3] {
            let contract = WaveTransitionContract::baseline(wave);
            assert_eq!(contract.wave_id, wave);
            assert!(!contract.entry_criteria.is_empty());
            assert!(!contract.exit_criteria.is_empty());
        }
    }

    #[test]
    fn handoff_package_baseline_wave_matches_wave1() {
        let pkg = HandoffPackage::baseline();
        assert_eq!(pkg.wave_id, WaveId::Wave1);
    }

    // ══════════════════════════════════════════════════════════════════
    // Enrichment tests — Copy semantics
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn wave_id_copy_semantics() {
        let a = WaveId::Wave2;
        let b = a; // Copy
        let c = a; // still valid after copy
        assert_eq!(b, c);
        assert_eq!(a, WaveId::Wave2);
    }

    #[test]
    fn required_bead_status_copy_semantics() {
        let a = RequiredBeadStatus::Closed;
        let b = a;
        let c = a;
        assert_eq!(b, c);
        assert_eq!(a, RequiredBeadStatus::Closed);
    }

    #[test]
    fn handoff_validation_error_code_copy_semantics() {
        let a = HandoffValidationErrorCode::WeakHandoffPackage;
        let b = a;
        let c = a;
        assert_eq!(b, c);
        assert_eq!(a, HandoffValidationErrorCode::WeakHandoffPackage);
    }

    #[test]
    fn wave_id_copy_into_function() {
        fn consume(w: WaveId) -> &'static str {
            w.as_str()
        }
        let w = WaveId::Wave3;
        let s1 = consume(w);
        let s2 = consume(w); // still usable after consume
        assert_eq!(s1, s2);
    }

    #[test]
    fn required_bead_status_copy_in_vec() {
        let s = RequiredBeadStatus::InProgress;
        let v = [s, s, s]; // Copy into array multiple times
        assert_eq!(v.len(), 3);
        assert!(v.iter().all(|x| *x == RequiredBeadStatus::InProgress));
    }

    // ══════════════════════════════════════════════════════════════════
    // Debug distinctness
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn wave_id_debug_all_distinct() {
        let variants = [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            let dbg = format!("{:?}", v);
            assert!(seen.insert(dbg.clone()), "duplicate Debug for {:?}", v);
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn required_bead_status_debug_all_distinct() {
        let variants = [
            RequiredBeadStatus::Open,
            RequiredBeadStatus::InProgress,
            RequiredBeadStatus::Closed,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            let dbg = format!("{:?}", v);
            assert!(seen.insert(dbg.clone()), "duplicate Debug for {:?}", v);
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn handoff_validation_error_code_debug_all_distinct() {
        let variants = [
            HandoffValidationErrorCode::MissingRequiredField,
            HandoffValidationErrorCode::WeakHandoffPackage,
            HandoffValidationErrorCode::MissingCriterionAttestation,
            HandoffValidationErrorCode::CriterionStatusMismatch,
            HandoffValidationErrorCode::CriterionArtifactMissing,
            HandoffValidationErrorCode::CriterionBeadMissing,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            let dbg = format!("{:?}", v);
            assert!(seen.insert(dbg.clone()), "duplicate Debug for {:?}", v);
        }
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn wave_id_debug_contains_variant_name() {
        assert!(format!("{:?}", WaveId::Wave0).contains("Wave0"));
        assert!(format!("{:?}", WaveId::Wave3).contains("Wave3"));
    }

    #[test]
    fn required_bead_status_debug_contains_variant_name() {
        assert!(format!("{:?}", RequiredBeadStatus::Open).contains("Open"));
        assert!(format!("{:?}", RequiredBeadStatus::InProgress).contains("InProgress"));
        assert!(format!("{:?}", RequiredBeadStatus::Closed).contains("Closed"));
    }

    #[test]
    fn handoff_validation_error_code_debug_contains_variant_name() {
        assert!(
            format!("{:?}", HandoffValidationErrorCode::MissingRequiredField)
                .contains("MissingRequiredField")
        );
        assert!(
            format!("{:?}", HandoffValidationErrorCode::CriterionBeadMissing)
                .contains("CriterionBeadMissing")
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // Serde variant distinctness
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn wave_id_serde_all_variants_distinct_json() {
        let variants = [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            assert!(seen.insert(json.clone()), "duplicate JSON for {:?}", v);
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn required_bead_status_serde_all_variants_distinct_json() {
        let variants = [
            RequiredBeadStatus::Open,
            RequiredBeadStatus::InProgress,
            RequiredBeadStatus::Closed,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            assert!(seen.insert(json.clone()), "duplicate JSON for {:?}", v);
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn handoff_validation_error_code_serde_all_variants_distinct_json() {
        let variants = [
            HandoffValidationErrorCode::MissingRequiredField,
            HandoffValidationErrorCode::WeakHandoffPackage,
            HandoffValidationErrorCode::MissingCriterionAttestation,
            HandoffValidationErrorCode::CriterionStatusMismatch,
            HandoffValidationErrorCode::CriterionArtifactMissing,
            HandoffValidationErrorCode::CriterionBeadMissing,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            assert!(seen.insert(json.clone()), "duplicate JSON for {:?}", v);
        }
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn required_bead_status_serde_snake_case_values() {
        assert_eq!(
            serde_json::to_string(&RequiredBeadStatus::Open)
                .expect("serde deserialization should succeed"),
            "\"open\""
        );
        assert_eq!(
            serde_json::to_string(&RequiredBeadStatus::InProgress)
                .expect("serde deserialization should succeed"),
            "\"in_progress\""
        );
        assert_eq!(
            serde_json::to_string(&RequiredBeadStatus::Closed)
                .expect("serde deserialization should succeed"),
            "\"closed\""
        );
    }

    #[test]
    fn handoff_validation_error_code_serde_snake_case_values() {
        assert_eq!(
            serde_json::to_string(&HandoffValidationErrorCode::MissingRequiredField)
                .expect("serde deserialization should succeed"),
            "\"missing_required_field\""
        );
        assert_eq!(
            serde_json::to_string(&HandoffValidationErrorCode::WeakHandoffPackage)
                .expect("serde deserialization should succeed"),
            "\"weak_handoff_package\""
        );
        assert_eq!(
            serde_json::to_string(&HandoffValidationErrorCode::MissingCriterionAttestation)
                .expect("serde deserialization should succeed"),
            "\"missing_criterion_attestation\""
        );
        assert_eq!(
            serde_json::to_string(&HandoffValidationErrorCode::CriterionStatusMismatch)
                .expect("serde deserialization should succeed"),
            "\"criterion_status_mismatch\""
        );
        assert_eq!(
            serde_json::to_string(&HandoffValidationErrorCode::CriterionArtifactMissing)
                .expect("serde deserialization should succeed"),
            "\"criterion_artifact_missing\""
        );
        assert_eq!(
            serde_json::to_string(&HandoffValidationErrorCode::CriterionBeadMissing)
                .expect("serde deserialization should succeed"),
            "\"criterion_bead_missing\""
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // Clone independence
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn wave_criterion_clone_independence() {
        let original = WaveCriterion {
            criterion_id: "c1".to_string(),
            bead_id: "bd-1".to_string(),
            required_status: RequiredBeadStatus::Open,
            required_artifact: "art.json".to_string(),
            mandatory: true,
        };
        let mut cloned = original.clone();
        cloned.criterion_id = "c2".to_string();
        cloned.mandatory = false;
        assert_eq!(cloned.criterion_id, "c2");
        assert!(!cloned.mandatory);
        assert_eq!(original.criterion_id, "c1");
        assert!(original.mandatory);
    }

    #[test]
    fn wave_transition_contract_clone_independence() {
        let original = WaveTransitionContract::baseline(WaveId::Wave0);
        let mut cloned = original.clone();
        cloned.wave_id = WaveId::Wave3;
        cloned.minimum_handoff_score_milli = 999;
        cloned.entry_criteria.clear();
        assert_eq!(cloned.wave_id, WaveId::Wave3);
        assert_eq!(cloned.minimum_handoff_score_milli, 999);
        assert!(cloned.entry_criteria.is_empty());
        assert_eq!(original.wave_id, WaveId::Wave0);
        assert_eq!(original.minimum_handoff_score_milli, 850);
        assert!(!original.entry_criteria.is_empty());
    }

    #[test]
    fn handoff_package_clone_independence() {
        let original = HandoffPackage::baseline();
        let mut cloned = original.clone();
        cloned.packet_id = "pkt-modified".to_string();
        cloned.changed_beads.clear();
        cloned.completeness_score_milli = 0;
        assert_eq!(cloned.packet_id, "pkt-modified");
        assert!(cloned.changed_beads.is_empty());
        assert_eq!(cloned.completeness_score_milli, 0);
        assert_eq!(original.packet_id, "pkt-rgc-wave-1-demo");
        assert!(!original.changed_beads.is_empty());
        assert_eq!(original.completeness_score_milli, 920);
    }

    #[test]
    fn criterion_attestation_clone_independence() {
        let original = CriterionAttestation {
            criterion_id: "c1".to_string(),
            bead_id: "bd-1".to_string(),
            bead_status: RequiredBeadStatus::InProgress,
            artifact_ref: "art.json".to_string(),
        };
        let mut cloned = original.clone();
        cloned.bead_status = RequiredBeadStatus::Closed;
        cloned.artifact_ref = "other.json".to_string();
        assert_eq!(cloned.bead_status, RequiredBeadStatus::Closed);
        assert_eq!(cloned.artifact_ref, "other.json");
        assert_eq!(original.bead_status, RequiredBeadStatus::InProgress);
        assert_eq!(original.artifact_ref, "art.json");
    }

    #[test]
    fn handoff_validation_failure_clone_independence() {
        let original = HandoffValidationFailure {
            code: HandoffValidationErrorCode::MissingRequiredField,
            message: "original".to_string(),
        };
        let mut cloned = original.clone();
        cloned.code = HandoffValidationErrorCode::WeakHandoffPackage;
        cloned.message = "modified".to_string();
        assert_eq!(cloned.code, HandoffValidationErrorCode::WeakHandoffPackage);
        assert_eq!(cloned.message, "modified");
        assert_eq!(
            original.code,
            HandoffValidationErrorCode::MissingRequiredField
        );
        assert_eq!(original.message, "original");
    }

    #[test]
    fn handoff_validation_report_clone_independence() {
        let original = HandoffValidationReport {
            contract_version: "v1".to_string(),
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "comp".to_string(),
            event: "evt".to_string(),
            outcome: "pass".to_string(),
            error_code: "none".to_string(),
            valid: true,
            failures: Vec::new(),
        };
        let mut cloned = original.clone();
        cloned.valid = false;
        cloned.outcome = "fail".to_string();
        cloned.failures.push(HandoffValidationFailure {
            code: HandoffValidationErrorCode::WeakHandoffPackage,
            message: "weak".to_string(),
        });
        assert!(!cloned.valid);
        assert_eq!(cloned.outcome, "fail");
        assert_eq!(cloned.failures.len(), 1);
        assert!(original.valid);
        assert_eq!(original.outcome, "pass");
        assert!(original.failures.is_empty());
    }

    #[test]
    fn handoff_event_clone_independence() {
        let original = HandoffEvent {
            schema_version: "v1".to_string(),
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "comp".to_string(),
            event: "evt".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            wave_id: "wave_0".to_string(),
            packet_id: "pkt-1".to_string(),
        };
        let mut cloned = original.clone();
        cloned.event = "modified".to_string();
        cloned.error_code = Some("err".to_string());
        assert_eq!(cloned.event, "modified");
        assert_eq!(cloned.error_code.as_deref(), Some("err"));
        assert_eq!(original.event, "evt");
        assert_eq!(original.error_code, None);
    }

    // ══════════════════════════════════════════════════════════════════
    // JSON field-name stability
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn wave_criterion_json_field_names() {
        let c = WaveCriterion {
            criterion_id: "c".to_string(),
            bead_id: "b".to_string(),
            required_status: RequiredBeadStatus::Open,
            required_artifact: "a".to_string(),
            mandatory: false,
        };
        let json = serde_json::to_string(&c).expect("serialize derived Serialize");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        let obj = v.as_object().expect("serde deserialization should succeed");
        assert!(obj.contains_key("criterion_id"));
        assert!(obj.contains_key("bead_id"));
        assert!(obj.contains_key("required_status"));
        assert!(obj.contains_key("required_artifact"));
        assert!(obj.contains_key("mandatory"));
        assert_eq!(obj.len(), 5);
    }

    #[test]
    fn wave_transition_contract_json_field_names() {
        let c = WaveTransitionContract::baseline(WaveId::Wave0);
        let json = serde_json::to_string(&c).expect("serialize derived Serialize");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        let obj = v.as_object().expect("serde deserialization should succeed");
        assert!(obj.contains_key("contract_version"));
        assert!(obj.contains_key("packet_schema_version"));
        assert!(obj.contains_key("wave_id"));
        assert!(obj.contains_key("minimum_handoff_score_milli"));
        assert!(obj.contains_key("entry_criteria"));
        assert!(obj.contains_key("exit_criteria"));
        assert_eq!(obj.len(), 6);
    }

    #[test]
    fn criterion_attestation_json_field_names() {
        let a = CriterionAttestation {
            criterion_id: "c".to_string(),
            bead_id: "b".to_string(),
            bead_status: RequiredBeadStatus::Open,
            artifact_ref: "a".to_string(),
        };
        let json = serde_json::to_string(&a).expect("serialize derived Serialize");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        let obj = v.as_object().expect("serde deserialization should succeed");
        assert!(obj.contains_key("criterion_id"));
        assert!(obj.contains_key("bead_id"));
        assert!(obj.contains_key("bead_status"));
        assert!(obj.contains_key("artifact_ref"));
        assert_eq!(obj.len(), 4);
    }

    #[test]
    fn handoff_package_json_field_names() {
        let pkg = HandoffPackage::baseline();
        let json = serde_json::to_string(&pkg).expect("serialize derived Serialize");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        let obj = v.as_object().expect("serde deserialization should succeed");
        assert!(obj.contains_key("packet_id"));
        assert!(obj.contains_key("wave_id"));
        assert!(obj.contains_key("producer_owner"));
        assert!(obj.contains_key("consumer_owner"));
        assert!(obj.contains_key("changed_beads"));
        assert!(obj.contains_key("artifact_links"));
        assert!(obj.contains_key("open_risks"));
        assert!(obj.contains_key("next_step_recommendations"));
        assert!(obj.contains_key("criteria_attestations"));
        assert!(obj.contains_key("completeness_score_milli"));
        assert_eq!(obj.len(), 10);
    }

    #[test]
    fn handoff_validation_failure_json_field_names() {
        let f = HandoffValidationFailure {
            code: HandoffValidationErrorCode::MissingRequiredField,
            message: "msg".to_string(),
        };
        let json = serde_json::to_string(&f).expect("serialize derived Serialize");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        let obj = v.as_object().expect("serde deserialization should succeed");
        assert!(obj.contains_key("code"));
        assert!(obj.contains_key("message"));
        assert_eq!(obj.len(), 2);
    }

    #[test]
    fn handoff_validation_report_json_field_names() {
        let r = HandoffValidationReport {
            contract_version: "v".to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "o".to_string(),
            error_code: "ec".to_string(),
            valid: true,
            failures: Vec::new(),
        };
        let json = serde_json::to_string(&r).expect("serialize derived Serialize");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        let obj = v.as_object().expect("serde deserialization should succeed");
        assert!(obj.contains_key("contract_version"));
        assert!(obj.contains_key("trace_id"));
        assert!(obj.contains_key("decision_id"));
        assert!(obj.contains_key("policy_id"));
        assert!(obj.contains_key("component"));
        assert!(obj.contains_key("event"));
        assert!(obj.contains_key("outcome"));
        assert!(obj.contains_key("error_code"));
        assert!(obj.contains_key("valid"));
        assert!(obj.contains_key("failures"));
        assert_eq!(obj.len(), 10);
    }

    #[test]
    fn handoff_event_json_field_names() {
        let e = HandoffEvent {
            schema_version: "sv".to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "o".to_string(),
            error_code: None,
            wave_id: "w".to_string(),
            packet_id: "pk".to_string(),
        };
        let json = serde_json::to_string(&e).expect("serialize derived Serialize");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        let obj = v.as_object().expect("serde deserialization should succeed");
        assert!(obj.contains_key("schema_version"));
        assert!(obj.contains_key("trace_id"));
        assert!(obj.contains_key("decision_id"));
        assert!(obj.contains_key("policy_id"));
        assert!(obj.contains_key("component"));
        assert!(obj.contains_key("event"));
        assert!(obj.contains_key("outcome"));
        assert!(obj.contains_key("error_code"));
        assert!(obj.contains_key("wave_id"));
        assert!(obj.contains_key("packet_id"));
        assert_eq!(obj.len(), 10);
    }

    // ══════════════════════════════════════════════════════════════════
    // Hash consistency (via BTreeSet dedup as proxy)
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn wave_id_ord_consistency_across_calls() {
        let a = WaveId::Wave1;
        let b = WaveId::Wave1;
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
        assert_eq!(a, b);
    }

    #[test]
    fn wave_id_btreeset_dedup() {
        let mut set = std::collections::BTreeSet::new();
        set.insert(WaveId::Wave0);
        set.insert(WaveId::Wave0);
        set.insert(WaveId::Wave1);
        set.insert(WaveId::Wave1);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn required_bead_status_btreeset_dedup() {
        let mut set = std::collections::BTreeSet::new();
        set.insert(RequiredBeadStatus::Open);
        set.insert(RequiredBeadStatus::Open);
        set.insert(RequiredBeadStatus::Closed);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn handoff_validation_error_code_eq_reflexive() {
        let codes = [
            HandoffValidationErrorCode::MissingRequiredField,
            HandoffValidationErrorCode::WeakHandoffPackage,
            HandoffValidationErrorCode::MissingCriterionAttestation,
            HandoffValidationErrorCode::CriterionStatusMismatch,
            HandoffValidationErrorCode::CriterionArtifactMissing,
            HandoffValidationErrorCode::CriterionBeadMissing,
        ];
        for code in &codes {
            assert_eq!(code, code);
        }
    }

    #[test]
    fn wave_id_all_variants_in_btreeset() {
        let mut set = std::collections::BTreeSet::new();
        set.insert(WaveId::Wave0);
        set.insert(WaveId::Wave1);
        set.insert(WaveId::Wave2);
        set.insert(WaveId::Wave3);
        assert_eq!(set.len(), 4);
        // Verify ordering is correct
        let v: Vec<_> = set.into_iter().collect();
        assert_eq!(
            v,
            vec![WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3]
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // Boundary / edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn handoff_package_with_empty_open_risks() {
        let mut pkg = HandoffPackage::baseline();
        pkg.open_risks.clear();
        // open_risks is not checked by validate_handoff, so it should still pass
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(report.valid);
    }

    #[test]
    fn handoff_package_completeness_score_at_u16_max() {
        let mut pkg = HandoffPackage::baseline();
        pkg.completeness_score_milli = u16::MAX;
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        // u16::MAX well above 850 threshold, should pass score check
        let weak = report
            .failures
            .iter()
            .any(|f| matches!(f.code, HandoffValidationErrorCode::WeakHandoffPackage));
        assert!(!weak);
    }

    #[test]
    fn handoff_package_completeness_score_zero() {
        let mut pkg = HandoffPackage::baseline();
        pkg.completeness_score_milli = 0;
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(
            report
                .failures
                .iter()
                .any(|f| matches!(f.code, HandoffValidationErrorCode::WeakHandoffPackage))
        );
    }

    #[test]
    fn contract_minimum_score_at_u16_max() {
        let mut contract = WaveTransitionContract::baseline(WaveId::Wave1);
        contract.minimum_handoff_score_milli = u16::MAX;
        let mut pkg = HandoffPackage::baseline();
        pkg.completeness_score_milli = u16::MAX;
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        let weak = report
            .failures
            .iter()
            .any(|f| matches!(f.code, HandoffValidationErrorCode::WeakHandoffPackage));
        assert!(!weak, "u16::MAX >= u16::MAX should pass");
    }

    #[test]
    fn contract_minimum_score_at_u16_max_pkg_below() {
        let mut contract = WaveTransitionContract::baseline(WaveId::Wave1);
        contract.minimum_handoff_score_milli = u16::MAX;
        let mut pkg = HandoffPackage::baseline();
        pkg.completeness_score_milli = u16::MAX - 1;
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(
            report
                .failures
                .iter()
                .any(|f| matches!(f.code, HandoffValidationErrorCode::WeakHandoffPackage))
        );
    }

    #[test]
    fn validate_handoff_whitespace_only_producer_owner() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.producer_owner = " \t\n ".to_string();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::MissingRequiredField)
                && f.message.contains("producer_owner")
        }));
    }

    #[test]
    fn validate_handoff_whitespace_only_consumer_owner() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.consumer_owner = "\t".to_string();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::MissingRequiredField)
                && f.message.contains("consumer_owner")
        }));
    }

    #[test]
    fn validate_handoff_many_empty_fields_at_once() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.packet_id.clear();
        pkg.producer_owner.clear();
        pkg.consumer_owner.clear();
        pkg.changed_beads.clear();
        pkg.artifact_links.clear();
        pkg.next_step_recommendations.clear();
        pkg.completeness_score_milli = 0;
        pkg.criteria_attestations.clear();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        // At least 6 MissingRequiredField + 1 WeakHandoffPackage + criterion failures
        assert!(report.failures.len() >= 7);
    }

    #[test]
    fn handoff_package_very_long_strings() {
        let long_str = "x".repeat(10_000);
        let mut pkg = HandoffPackage::baseline();
        pkg.packet_id = long_str.clone();
        pkg.producer_owner = long_str.clone();
        pkg.consumer_owner = long_str;
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        // Long strings are valid — no MissingRequiredField for these fields
        let missing = report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::MissingRequiredField)
                && (f.message.contains("packet_id")
                    || f.message.contains("producer_owner")
                    || f.message.contains("consumer_owner"))
        });
        assert!(!missing);
    }

    #[test]
    fn handoff_package_empty_criteria_attestations_serde_roundtrip() {
        let mut pkg = HandoffPackage::baseline();
        pkg.criteria_attestations.clear();
        let json = serde_json::to_string(&pkg).expect("serialize derived Serialize");
        let back: HandoffPackage =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(pkg, back);
        assert!(back.criteria_attestations.is_empty());
    }

    #[test]
    fn wave_transition_contract_empty_criteria_serde_roundtrip() {
        let mut contract = WaveTransitionContract::baseline(WaveId::Wave2);
        contract.entry_criteria.clear();
        contract.exit_criteria.clear();
        let json = serde_json::to_string(&contract).expect("serialize derived Serialize");
        let back: WaveTransitionContract =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(contract, back);
    }

    #[test]
    fn handoff_package_many_changed_beads() {
        let mut pkg = HandoffPackage::baseline();
        for i in 0..100 {
            pkg.changed_beads.push(format!("bd-gen-{}", i));
        }
        let json = serde_json::to_string(&pkg).expect("serialize derived Serialize");
        let back: HandoffPackage =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(pkg, back);
    }

    #[test]
    fn handoff_package_many_artifact_links() {
        let mut pkg = HandoffPackage::baseline();
        for i in 0..100 {
            pkg.artifact_links.push(format!("artifacts/gen/{}.json", i));
        }
        let json = serde_json::to_string(&pkg).expect("serialize derived Serialize");
        let back: HandoffPackage =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(pkg, back);
    }

    // ══════════════════════════════════════════════════════════════════
    // Serde roundtrips (complex structs)
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn handoff_validation_report_with_failures_roundtrip() {
        let report = HandoffValidationReport {
            contract_version: WAVE_HANDOFF_CONTRACT_VERSION.to_string(),
            trace_id: "trace-complex".to_string(),
            decision_id: "decision-complex".to_string(),
            policy_id: "policy-complex".to_string(),
            component: WAVE_HANDOFF_COMPONENT.to_string(),
            event: "validate_handoff".to_string(),
            outcome: "fail".to_string(),
            error_code: WAVE_HANDOFF_FAILURE_CODE.to_string(),
            valid: false,
            failures: vec![
                HandoffValidationFailure {
                    code: HandoffValidationErrorCode::MissingRequiredField,
                    message: "packet_id must not be empty".to_string(),
                },
                HandoffValidationFailure {
                    code: HandoffValidationErrorCode::WeakHandoffPackage,
                    message: "score too low".to_string(),
                },
                HandoffValidationFailure {
                    code: HandoffValidationErrorCode::CriterionBeadMissing,
                    message: "bead missing".to_string(),
                },
            ],
        };
        let json =
            serde_json::to_string_pretty(&report).expect("serde deserialization should succeed");
        let back: HandoffValidationReport =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(report, back);
    }

    #[test]
    fn simulate_transition_report_and_events_roundtrip() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let pkg = HandoffPackage::baseline();
        let (report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
        let report_json = serde_json::to_string(&report).expect("serialize derived Serialize");
        let report_back: HandoffValidationReport =
            serde_json::from_str(&report_json).expect("deserialize known-valid JSON");
        assert_eq!(report, report_back);
        for event in &events {
            let ej = serde_json::to_string(event).expect("serialize derived Serialize");
            let eb: HandoffEvent = serde_json::from_str(&ej).expect("deserialize known-valid JSON");
            assert_eq!(*event, eb);
        }
    }

    #[test]
    fn full_contract_with_many_criteria_roundtrip() {
        let mut contract = WaveTransitionContract::baseline(WaveId::Wave3);
        for i in 0u64..10 {
            contract.entry_criteria.push(WaveCriterion {
                criterion_id: format!("entry-gen-{}", i),
                bead_id: format!("bd-entry-{}", i),
                required_status: RequiredBeadStatus::Closed,
                required_artifact: format!("artifacts/entry_{}.json", i),
                mandatory: i % 2 == 0,
            });
            contract.exit_criteria.push(WaveCriterion {
                criterion_id: format!("exit-gen-{}", i),
                bead_id: format!("bd-exit-{}", i),
                required_status: RequiredBeadStatus::InProgress,
                required_artifact: format!("artifacts/exit_{}.json", i),
                mandatory: true,
            });
        }
        let json = serde_json::to_string(&contract).expect("serialize derived Serialize");
        let back: WaveTransitionContract =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(contract, back);
    }

    #[test]
    fn handoff_event_none_error_code_serializes_as_null() {
        let event = HandoffEvent {
            schema_version: "v".to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "o".to_string(),
            error_code: None,
            wave_id: "w".to_string(),
            packet_id: "pk".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert!(v["error_code"].is_null());
    }

    #[test]
    fn handoff_event_some_error_code_serializes_as_string() {
        let event = HandoffEvent {
            schema_version: "v".to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "o".to_string(),
            error_code: Some("ERR-001".to_string()),
            wave_id: "w".to_string(),
            packet_id: "pk".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(
            v["error_code"]
                .as_str()
                .expect("serde deserialization should succeed"),
            "ERR-001"
        );
    }

    #[test]
    fn wave_criterion_with_unicode_strings_roundtrip() {
        let c = WaveCriterion {
            criterion_id: "\u{1f680}-crit".to_string(),
            bead_id: "bd-\u{00e9}".to_string(),
            required_status: RequiredBeadStatus::Open,
            required_artifact: "artifacts/\u{4e16}\u{754c}.json".to_string(),
            mandatory: true,
        };
        let json = serde_json::to_string(&c).expect("serialize derived Serialize");
        let back: WaveCriterion =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(c, back);
    }

    // ══════════════════════════════════════════════════════════════════
    // Validation logic — additional coverage
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn validate_handoff_report_event_is_validate_handoff() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let pkg = HandoffPackage::baseline();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert_eq!(report.event, "validate_handoff");
    }

    #[test]
    fn simulate_transition_first_event_is_handoff_received_with_ok() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.packet_id = "".to_string();
        let (_report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
        assert_eq!(events[0].event, "handoff_received");
        assert_eq!(events[0].outcome, "ok");
        assert_eq!(events[0].error_code, None);
    }

    #[test]
    fn simulate_transition_with_wave0() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave0);
        let mut pkg = HandoffPackage::baseline();
        pkg.wave_id = WaveId::Wave0;
        let (_report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
        for event in &events {
            assert_eq!(event.wave_id, "wave_0");
        }
    }

    #[test]
    fn simulate_transition_with_wave3() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave3);
        let mut pkg = HandoffPackage::baseline();
        pkg.wave_id = WaveId::Wave3;
        let (_report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
        for event in &events {
            assert_eq!(event.wave_id, "wave_3");
        }
    }

    #[test]
    fn validate_handoff_multiple_mandatory_criteria_all_checked() {
        let mut contract = WaveTransitionContract::baseline(WaveId::Wave1);
        contract.entry_criteria.push(WaveCriterion {
            criterion_id: "extra-entry".to_string(),
            bead_id: "bd-extra".to_string(),
            required_status: RequiredBeadStatus::Closed,
            required_artifact: "artifacts/extra.json".to_string(),
            mandatory: true,
        });
        let pkg = HandoffPackage::baseline();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        // Missing attestation for "extra-entry"
        assert!(!report.valid);
        assert!(report.failures.iter().any(|f| {
            matches!(
                f.code,
                HandoffValidationErrorCode::MissingCriterionAttestation
            ) && f.message.contains("extra-entry")
        }));
    }

    #[test]
    fn validate_handoff_non_mandatory_criterion_not_checked() {
        let mut contract = WaveTransitionContract::baseline(WaveId::Wave1);
        // Clear default criteria, add only non-mandatory ones
        contract.entry_criteria.clear();
        contract.exit_criteria.clear();
        contract.entry_criteria.push(WaveCriterion {
            criterion_id: "optional-only".to_string(),
            bead_id: "bd-opt".to_string(),
            required_status: RequiredBeadStatus::Closed,
            required_artifact: "missing.json".to_string(),
            mandatory: false,
        });
        let pkg = HandoffPackage::baseline();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        // No criterion failures expected
        let criterion_failures: Vec<_> = report
            .failures
            .iter()
            .filter(|f| {
                matches!(
                    f.code,
                    HandoffValidationErrorCode::MissingCriterionAttestation
                        | HandoffValidationErrorCode::CriterionStatusMismatch
                        | HandoffValidationErrorCode::CriterionArtifactMissing
                        | HandoffValidationErrorCode::CriterionBeadMissing
                )
            })
            .collect();
        assert!(criterion_failures.is_empty());
    }

    #[test]
    fn validate_handoff_attestation_bead_id_not_in_changed_beads_but_match_criterion() {
        let mut contract = WaveTransitionContract::baseline(WaveId::Wave1);
        contract.entry_criteria.clear();
        contract.exit_criteria.clear();
        contract.entry_criteria.push(WaveCriterion {
            criterion_id: "c-custom".to_string(),
            bead_id: "bd-custom".to_string(),
            required_status: RequiredBeadStatus::InProgress,
            required_artifact: "art.json".to_string(),
            mandatory: true,
        });
        let mut pkg = HandoffPackage::baseline();
        pkg.criteria_attestations = vec![CriterionAttestation {
            criterion_id: "c-custom".to_string(),
            bead_id: "bd-custom".to_string(),
            bead_status: RequiredBeadStatus::InProgress,
            artifact_ref: "art.json".to_string(),
        }];
        // bd-custom is NOT in changed_beads or artifact_links
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::CriterionBeadMissing)
                && f.message.contains("changed_beads")
        }));
    }

    #[test]
    fn validate_handoff_attestation_artifact_not_in_artifact_links_but_match_criterion() {
        let mut contract = WaveTransitionContract::baseline(WaveId::Wave1);
        contract.entry_criteria.clear();
        contract.exit_criteria.clear();
        contract.entry_criteria.push(WaveCriterion {
            criterion_id: "c-art".to_string(),
            bead_id: "bd-art".to_string(),
            required_status: RequiredBeadStatus::Open,
            required_artifact: "special/art.json".to_string(),
            mandatory: true,
        });
        let mut pkg = HandoffPackage::baseline();
        pkg.changed_beads.push("bd-art".to_string());
        pkg.criteria_attestations = vec![CriterionAttestation {
            criterion_id: "c-art".to_string(),
            bead_id: "bd-art".to_string(),
            bead_status: RequiredBeadStatus::Open,
            artifact_ref: "special/art.json".to_string(),
        }];
        // artifact not in artifact_links
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(report.failures.iter().any(|f| {
            matches!(f.code, HandoffValidationErrorCode::CriterionArtifactMissing)
                && f.message.contains("artifact_links")
        }));
    }

    // ══════════════════════════════════════════════════════════════════
    // Ordering / Eq / PartialOrd extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn wave_id_eq_same_variant() {
        assert_eq!(WaveId::Wave0, WaveId::Wave0);
        assert_eq!(WaveId::Wave1, WaveId::Wave1);
        assert_eq!(WaveId::Wave2, WaveId::Wave2);
        assert_eq!(WaveId::Wave3, WaveId::Wave3);
    }

    #[test]
    fn wave_id_ne_different_variant() {
        assert_ne!(WaveId::Wave0, WaveId::Wave1);
        assert_ne!(WaveId::Wave1, WaveId::Wave2);
        assert_ne!(WaveId::Wave2, WaveId::Wave3);
        assert_ne!(WaveId::Wave0, WaveId::Wave3);
    }

    #[test]
    fn required_bead_status_eq_same() {
        assert_eq!(RequiredBeadStatus::Open, RequiredBeadStatus::Open);
        assert_eq!(
            RequiredBeadStatus::InProgress,
            RequiredBeadStatus::InProgress
        );
        assert_eq!(RequiredBeadStatus::Closed, RequiredBeadStatus::Closed);
    }

    #[test]
    fn required_bead_status_ne_different() {
        assert_ne!(RequiredBeadStatus::Open, RequiredBeadStatus::InProgress);
        assert_ne!(RequiredBeadStatus::Open, RequiredBeadStatus::Closed);
        assert_ne!(RequiredBeadStatus::InProgress, RequiredBeadStatus::Closed);
    }

    #[test]
    fn required_bead_status_full_ordering() {
        let mut v = vec![
            RequiredBeadStatus::Closed,
            RequiredBeadStatus::Open,
            RequiredBeadStatus::InProgress,
        ];
        v.sort();
        assert_eq!(
            v,
            vec![
                RequiredBeadStatus::Open,
                RequiredBeadStatus::InProgress,
                RequiredBeadStatus::Closed,
            ]
        );
    }

    #[test]
    fn wave_id_full_sort_order() {
        let mut v = vec![WaveId::Wave3, WaveId::Wave0, WaveId::Wave2, WaveId::Wave1];
        v.sort();
        assert_eq!(
            v,
            vec![WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3]
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // Constants — specific values
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn contract_version_contains_expected_prefix() {
        assert!(WAVE_HANDOFF_CONTRACT_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn packet_schema_version_contains_expected_prefix() {
        assert!(WAVE_HANDOFF_PACKET_SCHEMA_VERSION.starts_with("frx."));
    }

    #[test]
    fn failure_code_contains_expected_prefix() {
        assert!(WAVE_HANDOFF_FAILURE_CODE.starts_with("FE-RGC-"));
    }

    #[test]
    fn component_name_is_exact() {
        assert_eq!(WAVE_HANDOFF_COMPONENT, "rgc_wave_handoff_contract");
    }

    // ══════════════════════════════════════════════════════════════════
    // simulate_wave_transition — additional coverage
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn simulate_transition_always_emits_exactly_3_events() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let pkg = HandoffPackage::baseline();
        let (_, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn simulate_transition_invalid_emits_exactly_3_events() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.packet_id.clear();
        pkg.changed_beads.clear();
        let (_, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn simulate_transition_valid_third_event_is_committed() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let pkg = HandoffPackage::baseline();
        let (report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
        assert!(report.valid);
        assert_eq!(events[2].event, "ownership_transition_committed");
        assert_eq!(events[2].error_code, None);
    }

    #[test]
    fn simulate_transition_invalid_third_event_is_rejected() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.packet_id.clear();
        let (report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
        assert!(!report.valid);
        assert_eq!(events[2].event, "ownership_transition_rejected");
        assert_eq!(
            events[2].error_code,
            Some(WAVE_HANDOFF_FAILURE_CODE.to_string())
        );
    }

    #[test]
    fn simulate_transition_packet_id_propagated_to_all_events() {
        let contract = WaveTransitionContract::baseline(WaveId::Wave1);
        let mut pkg = HandoffPackage::baseline();
        pkg.packet_id = "pkt-unique-42".to_string();
        let (_, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
        for event in &events {
            assert_eq!(event.packet_id, "pkt-unique-42");
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // Serde deserialization from raw JSON
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn wave_id_deserialize_from_raw_json_string() {
        let w: WaveId = serde_json::from_str("\"wave2\"").expect("deserialize known-valid JSON");
        assert_eq!(w, WaveId::Wave2);
    }

    #[test]
    fn required_bead_status_deserialize_from_raw_json_string() {
        let s: RequiredBeadStatus =
            serde_json::from_str("\"in_progress\"").expect("deserialize known-valid JSON");
        assert_eq!(s, RequiredBeadStatus::InProgress);
    }

    #[test]
    fn handoff_validation_error_code_deserialize_from_raw_json_string() {
        let c: HandoffValidationErrorCode = serde_json::from_str("\"weak_handoff_package\"")
            .expect("serde deserialization should succeed");
        assert_eq!(c, HandoffValidationErrorCode::WeakHandoffPackage);
    }

    #[test]
    fn wave_id_deserialize_invalid_variant_fails() {
        let result = serde_json::from_str::<WaveId>("\"wave_99\"");
        assert!(result.is_err());
    }

    #[test]
    fn required_bead_status_deserialize_invalid_variant_fails() {
        let result = serde_json::from_str::<RequiredBeadStatus>("\"deleted\"");
        assert!(result.is_err());
    }

    #[test]
    fn handoff_validation_error_code_deserialize_invalid_variant_fails() {
        let result = serde_json::from_str::<HandoffValidationErrorCode>("\"nonexistent_code\"");
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════════
    // WaveId as_str <-> serde consistency
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn wave_id_as_str_values_are_unique() {
        let strs: Vec<&str> = [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3]
            .iter()
            .map(|w| w.as_str())
            .collect();
        let mut set = std::collections::BTreeSet::new();
        for s in &strs {
            assert!(set.insert(*s), "duplicate as_str value: {}", s);
        }
    }

    #[test]
    fn wave_id_as_str_contains_numeric_suffix() {
        assert!(WaveId::Wave0.as_str().ends_with("0"));
        assert!(WaveId::Wave1.as_str().ends_with("1"));
        assert!(WaveId::Wave2.as_str().ends_with("2"));
        assert!(WaveId::Wave3.as_str().ends_with("3"));
    }

    // ══════════════════════════════════════════════════════════════════
    // Structural equality
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn wave_criterion_equality_depends_on_all_fields() {
        let base = WaveCriterion {
            criterion_id: "c1".to_string(),
            bead_id: "bd-1".to_string(),
            required_status: RequiredBeadStatus::Open,
            required_artifact: "art.json".to_string(),
            mandatory: true,
        };
        // Same should equal
        assert_eq!(base, base.clone());
        // Differ by criterion_id
        let mut diff = base.clone();
        diff.criterion_id = "c2".to_string();
        assert_ne!(base, diff);
        // Differ by mandatory
        let mut diff2 = base.clone();
        diff2.mandatory = false;
        assert_ne!(base, diff2);
        // Differ by required_status
        let mut diff3 = base.clone();
        diff3.required_status = RequiredBeadStatus::Closed;
        assert_ne!(base, diff3);
    }

    #[test]
    fn criterion_attestation_equality_depends_on_all_fields() {
        let base = CriterionAttestation {
            criterion_id: "c1".to_string(),
            bead_id: "bd-1".to_string(),
            bead_status: RequiredBeadStatus::InProgress,
            artifact_ref: "art.json".to_string(),
        };
        assert_eq!(base, base.clone());
        let mut diff = base.clone();
        diff.bead_status = RequiredBeadStatus::Closed;
        assert_ne!(base, diff);
    }

    #[test]
    fn handoff_package_equality_depends_on_score() {
        let mut a = HandoffPackage::baseline();
        let mut b = HandoffPackage::baseline();
        assert_eq!(a, b);
        a.completeness_score_milli = 100;
        b.completeness_score_milli = 200;
        assert_ne!(a, b);
    }

    #[test]
    fn handoff_validation_report_equality_depends_on_valid_flag() {
        let mut a = HandoffValidationReport {
            contract_version: "v".to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "pass".to_string(),
            error_code: "none".to_string(),
            valid: true,
            failures: Vec::new(),
        };
        let mut b = a.clone();
        assert_eq!(a, b);
        a.valid = false;
        b.valid = true;
        assert_ne!(a, b);
    }
}
