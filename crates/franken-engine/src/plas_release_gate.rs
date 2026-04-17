//! Deterministic release gate for PLAS cohort activation.
//!
//! Validates that prioritized extension cohorts run with PLAS active authority
//! control, signed capability witnesses, escrow-path replay evidence, and
//! revocation/traceability guarantees.
//!
//! Plan reference: Section 10.9 item 6 (`bd-2n3`) with implementation ownership
//! in Section 10.15.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability_witness::{
    CapabilityEscrowReceiptRecord, PublicationEntryKind, PublishedWitnessArtifact,
    WitnessPublicationPipeline,
};
use crate::engine_object_id::EngineObjectId;
use crate::hash_tiers::ContentHash;
use crate::policy_theorem_compiler::Capability;
use crate::signature_preimage::VerificationKey;

const PLAS_RELEASE_GATE_COMPONENT: &str = "plas_release_gate";

/// PLAS activation state for a prioritized cohort extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlasActivationMode {
    Active,
    Shadow,
    AuditOnly,
    Disabled,
}

impl PlasActivationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Shadow => "shadow",
            Self::AuditOnly => "audit_only",
            Self::Disabled => "disabled",
        }
    }
}

impl fmt::Display for PlasActivationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Escrow replay evidence for one grant decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasEscrowReplayEvidence {
    pub receipt_id: String,
    pub replay_decision_kind: String,
    pub replay_outcome: String,
    pub replay_policy_id: String,
    pub deterministic_replay: bool,
    pub replay_trace_id: String,
}

impl PlasEscrowReplayEvidence {
    fn normalize(&mut self) {
        self.receipt_id = self.receipt_id.trim().to_string();
        self.replay_decision_kind = self.replay_decision_kind.trim().to_string();
        self.replay_outcome = self.replay_outcome.trim().to_string();
        self.replay_policy_id = self.replay_policy_id.trim().to_string();
        self.replay_trace_id = self.replay_trace_id.trim().to_string();
    }
}

/// Grant record for release-gate validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasGrantCheckRecord {
    pub capability: Capability,
    pub receipt: CapabilityEscrowReceiptRecord,
    pub witness_artifact: PublishedWitnessArtifact,
    pub replay_evidence: Option<PlasEscrowReplayEvidence>,
}

impl PlasGrantCheckRecord {
    fn normalize(&mut self) {
        normalize_receipt(&mut self.receipt);
        if let Some(replay) = &mut self.replay_evidence {
            replay.normalize();
        }
    }

    fn sort_key(&self) -> (u64, String, String) {
        (
            self.receipt.timestamp_ns,
            self.receipt.receipt_id.clone(),
            self.capability.as_str().to_string(),
        )
    }
}

/// Revocation round-trip record for release-gate validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasRevocationCheckRecord {
    pub capability: Capability,
    pub receipt: CapabilityEscrowReceiptRecord,
    pub witness_artifact: PublishedWitnessArtifact,
}

impl PlasRevocationCheckRecord {
    fn normalize(&mut self) {
        normalize_receipt(&mut self.receipt);
    }

    fn sort_key(&self) -> (u64, String, String) {
        (
            self.receipt.timestamp_ns,
            self.receipt.receipt_id.clone(),
            self.capability.as_str().to_string(),
        )
    }
}

/// One prioritized extension entry in the PLAS release-gate cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasCohortExtension {
    pub extension_id: EngineObjectId,
    pub activation_mode: PlasActivationMode,
    #[serde(default)]
    pub manifest_capabilities: BTreeSet<Capability>,
    #[serde(default)]
    pub active_capabilities: BTreeSet<Capability>,
    #[serde(default)]
    pub grants: Vec<PlasGrantCheckRecord>,
    #[serde(default)]
    pub revocations: Vec<PlasRevocationCheckRecord>,
}

impl PlasCohortExtension {
    fn normalize(&mut self) {
        self.grants
            .iter_mut()
            .for_each(PlasGrantCheckRecord::normalize);
        self.revocations
            .iter_mut()
            .for_each(PlasRevocationCheckRecord::normalize);
        self.grants.sort_by_key(PlasGrantCheckRecord::sort_key);
        self.revocations
            .sort_by_key(PlasRevocationCheckRecord::sort_key);
    }
}

/// Gate input for PLAS release readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasReleaseGateInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub cohort_id: String,
    pub extensions: Vec<PlasCohortExtension>,
}

impl PlasReleaseGateInput {
    fn normalize(&mut self) {
        self.trace_id = self.trace_id.trim().to_string();
        self.decision_id = self.decision_id.trim().to_string();
        self.policy_id = self.policy_id.trim().to_string();
        self.cohort_id = self.cohort_id.trim().to_string();

        self.extensions
            .iter_mut()
            .for_each(PlasCohortExtension::normalize);
        self.extensions
            .sort_by_key(|entry| entry.extension_id.to_string());
    }

    fn validate(&self) -> Result<(), PlasReleaseGateError> {
        if self.trace_id.is_empty() {
            return Err(PlasReleaseGateError::InvalidInput {
                detail: "trace_id must not be empty".to_string(),
            });
        }
        if self.decision_id.is_empty() {
            return Err(PlasReleaseGateError::InvalidInput {
                detail: "decision_id must not be empty".to_string(),
            });
        }
        if self.policy_id.is_empty() {
            return Err(PlasReleaseGateError::InvalidInput {
                detail: "policy_id must not be empty".to_string(),
            });
        }
        if self.cohort_id.is_empty() {
            return Err(PlasReleaseGateError::InvalidInput {
                detail: "cohort_id must not be empty".to_string(),
            });
        }
        if self.extensions.is_empty() {
            return Err(PlasReleaseGateError::InvalidInput {
                detail: "at least one cohort extension is required".to_string(),
            });
        }

        let mut seen_extension_ids = BTreeSet::new();
        for extension in &self.extensions {
            let extension_key = extension.extension_id.to_string();
            if !seen_extension_ids.insert(extension_key.clone()) {
                return Err(PlasReleaseGateError::InvalidInput {
                    detail: format!("duplicate extension in cohort input: {extension_key}"),
                });
            }
        }
        Ok(())
    }
}

/// Trust-anchor material used for independent witness verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasReleaseGateTrustAnchors {
    pub witness_verification_key: VerificationKey,
    pub transparency_log_verification_key: VerificationKey,
}

/// Explicit failure taxonomy for PLAS release-gate checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlasReleaseGateFailureCode {
    CohortPlasNotActive,
    CohortCoverageMissingGrantExercise,
    MissingCapabilityWitness,
    WitnessSignatureVerificationFailed,
    EscrowReplayEvidenceMissing,
    EscrowReplayMismatch,
    RevocationWitnessMissing,
    RevocationEscrowEventMissing,
    AmbientAuthorityDetected,
}

impl PlasReleaseGateFailureCode {
    pub fn error_code(self) -> &'static str {
        match self {
            Self::CohortPlasNotActive => "cohort_plas_not_active",
            Self::CohortCoverageMissingGrantExercise => "cohort_coverage_missing_grant_exercise",
            Self::MissingCapabilityWitness => "missing_capability_witness",
            Self::WitnessSignatureVerificationFailed => "witness_signature_verification_failed",
            Self::EscrowReplayEvidenceMissing => "escrow_replay_evidence_missing",
            Self::EscrowReplayMismatch => "escrow_replay_mismatch",
            Self::RevocationWitnessMissing => "revocation_witness_missing",
            Self::RevocationEscrowEventMissing => "revocation_escrow_event_missing",
            Self::AmbientAuthorityDetected => "ambient_authority_detected",
        }
    }
}

impl fmt::Display for PlasReleaseGateFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.error_code())
    }
}

/// Structured finding for one gate failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasReleaseGateFinding {
    pub code: PlasReleaseGateFailureCode,
    pub extension_id: String,
    pub receipt_id: Option<String>,
    pub detail: String,
}

/// Structured gate log event with stable keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasReleaseGateLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub extension_id: Option<String>,
    pub receipt_id: Option<String>,
    pub capability: Option<String>,
}

/// Deterministic decision artifact for PLAS release-gate checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasReleaseGateDecisionArtifact {
    pub decision_id: String,
    pub cohort_id: String,
    pub pass: bool,
    pub checked_extensions: u64,
    pub checked_grants: u64,
    pub checked_revocations: u64,
    pub findings: Vec<PlasReleaseGateFinding>,
    pub logs: Vec<PlasReleaseGateLogEvent>,
    pub decision_hash: ContentHash,
}

/// Errors for invalid gate input or deterministic artifact serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlasReleaseGateError {
    InvalidInput { detail: String },
    Serialization { detail: String },
}

impl fmt::Display for PlasReleaseGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { detail } => write!(f, "invalid PLAS release gate input: {detail}"),
            Self::Serialization { detail } => write!(f, "serialization failure: {detail}"),
        }
    }
}

impl std::error::Error for PlasReleaseGateError {}

/// Evaluate PLAS release-gate readiness for a prioritized extension cohort.
pub fn evaluate_plas_release_gate(
    input: &PlasReleaseGateInput,
    trust_anchors: &PlasReleaseGateTrustAnchors,
) -> Result<PlasReleaseGateDecisionArtifact, PlasReleaseGateError> {
    let mut normalized = input.clone();
    normalized.normalize();
    normalized.validate()?;

    let mut findings = Vec::new();
    let mut logs = Vec::new();
    let mut checked_grants = 0u64;
    let mut checked_revocations = 0u64;

    for extension in &normalized.extensions {
        let extension_label = extension.extension_id.to_string();

        if extension.activation_mode != PlasActivationMode::Active {
            add_finding(
                &mut findings,
                PlasReleaseGateFailureCode::CohortPlasNotActive,
                &extension_label,
                None,
                format!(
                    "extension must run with PLAS active, got {}",
                    extension.activation_mode
                ),
            );
            push_log(
                &mut logs,
                &normalized,
                "cohort_activation",
                "fail",
                Some(PlasReleaseGateFailureCode::CohortPlasNotActive.error_code()),
                Some(&extension_label),
                None,
                None,
            );
        } else {
            push_log(
                &mut logs,
                &normalized,
                "cohort_activation",
                "pass",
                None,
                Some(&extension_label),
                None,
                None,
            );
        }

        if extension.grants.is_empty() {
            add_finding(
                &mut findings,
                PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise,
                &extension_label,
                None,
                "cohort extension has no exercised PLAS grant".to_string(),
            );
            push_log(
                &mut logs,
                &normalized,
                "cohort_grant_coverage",
                "fail",
                Some(PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise.error_code()),
                Some(&extension_label),
                None,
                None,
            );
        }

        let mut traced_capabilities = BTreeSet::new();
        let mut granted_capabilities = BTreeSet::new();
        let mut seen_grant_receipts = BTreeSet::new();

        for grant in &extension.grants {
            checked_grants = checked_grants.saturating_add(1);
            let capability_label = grant.capability.as_str().to_string();
            let receipt_id = grant.receipt.receipt_id.trim().to_string();

            if !seen_grant_receipts.insert(receipt_id.clone()) {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::MissingCapabilityWitness,
                    &extension_label,
                    Some(&receipt_id),
                    "duplicate grant receipt_id in cohort input".to_string(),
                );
            }

            let grant_receipt_valid = validate_grant_receipt(
                &grant.receipt,
                &extension.extension_id,
                &capability_label,
                &normalized.policy_id,
            );
            if let Err(detail) = grant_receipt_valid {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::MissingCapabilityWitness,
                    &extension_label,
                    Some(&receipt_id),
                    detail,
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "grant_witness_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::MissingCapabilityWitness.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            let witness = &grant.witness_artifact.witness;
            let witness_has_fields = witness.extension_id == extension.extension_id
                && witness.timestamp_ns > 0
                && !witness.required_capabilities.is_empty()
                && witness.required_capabilities.contains(&grant.capability)
                && !witness.synthesizer_signature.is_empty()
                && !grant.witness_artifact.signature_bundle.is_empty();
            if !witness_has_fields {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::MissingCapabilityWitness,
                    &extension_label,
                    Some(&receipt_id),
                    "signed capability witness is missing required grant fields".to_string(),
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "grant_witness_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::MissingCapabilityWitness.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            if let Err(err) = WitnessPublicationPipeline::verify_artifact(
                &grant.witness_artifact,
                &trust_anchors.witness_verification_key,
                &trust_anchors.transparency_log_verification_key,
            ) {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed,
                    &extension_label,
                    Some(&receipt_id),
                    format!("witness/trust-anchor verification failed: {err}"),
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "grant_witness_validation",
                    "fail",
                    Some(
                        PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed.error_code(),
                    ),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            traced_capabilities.extend(witness.required_capabilities.iter().cloned());
            granted_capabilities.insert(grant.capability.clone());

            push_log(
                &mut logs,
                &normalized,
                "grant_witness_validation",
                "pass",
                None,
                Some(&extension_label),
                Some(&receipt_id),
                Some(&capability_label),
            );

            let Some(replay) = &grant.replay_evidence else {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing,
                    &extension_label,
                    Some(&receipt_id),
                    "missing escrow replay evidence for grant".to_string(),
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "escrow_replay_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            };

            let replay_matches = replay.deterministic_replay
                && replay.receipt_id == grant.receipt.receipt_id
                && replay.replay_decision_kind == grant.receipt.decision_kind
                && replay.replay_outcome == grant.receipt.outcome
                && replay.replay_policy_id == grant.receipt.policy_id;
            if !replay_matches {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::EscrowReplayMismatch,
                    &extension_label,
                    Some(&receipt_id),
                    "escrow replay does not deterministically reproduce the original grant"
                        .to_string(),
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "escrow_replay_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::EscrowReplayMismatch.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            push_log(
                &mut logs,
                &normalized,
                "escrow_replay_validation",
                "pass",
                None,
                Some(&extension_label),
                Some(&receipt_id),
                Some(&capability_label),
            );
        }

        let mut seen_revocation_receipts = BTreeSet::new();
        for revocation in &extension.revocations {
            checked_revocations = checked_revocations.saturating_add(1);
            let capability_label = revocation.capability.as_str().to_string();
            let receipt_id = revocation.receipt.receipt_id.trim().to_string();

            if !seen_revocation_receipts.insert(receipt_id.clone()) {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
                    &extension_label,
                    Some(&receipt_id),
                    "duplicate revocation receipt_id in cohort input".to_string(),
                );
            }

            if !granted_capabilities.contains(&revocation.capability) {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
                    &extension_label,
                    Some(&receipt_id),
                    "revocation capability has no corresponding grant in cohort evidence"
                        .to_string(),
                );
            }

            if let Err(detail) = validate_revocation_receipt(
                &revocation.receipt,
                &extension.extension_id,
                &capability_label,
                &normalized.policy_id,
            ) {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
                    &extension_label,
                    Some(&receipt_id),
                    detail,
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "revocation_round_trip_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::RevocationEscrowEventMissing.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            if !revocation.witness_artifact.is_revoked() {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::RevocationWitnessMissing,
                    &extension_label,
                    Some(&receipt_id),
                    "revocation receipt missing signed revocation witness proof".to_string(),
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "revocation_round_trip_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::RevocationWitnessMissing.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            if let Some(bundle) = &revocation.witness_artifact.revocation_proof {
                let reason_is_empty = bundle
                    .log_entry
                    .revocation_reason
                    .as_ref()
                    .map(|reason| reason.trim().is_empty())
                    .unwrap_or(true);
                if bundle.log_entry.kind != PublicationEntryKind::Revoke || reason_is_empty {
                    add_finding(
                        &mut findings,
                        PlasReleaseGateFailureCode::RevocationWitnessMissing,
                        &extension_label,
                        Some(&receipt_id),
                        "revocation witness proof is malformed".to_string(),
                    );
                    push_log(
                        &mut logs,
                        &normalized,
                        "revocation_round_trip_validation",
                        "fail",
                        Some(PlasReleaseGateFailureCode::RevocationWitnessMissing.error_code()),
                        Some(&extension_label),
                        Some(&receipt_id),
                        Some(&capability_label),
                    );
                    continue;
                }
            }

            if let Err(err) = WitnessPublicationPipeline::verify_artifact(
                &revocation.witness_artifact,
                &trust_anchors.witness_verification_key,
                &trust_anchors.transparency_log_verification_key,
            ) {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::RevocationWitnessMissing,
                    &extension_label,
                    Some(&receipt_id),
                    format!("revocation witness verification failed: {err}"),
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "revocation_round_trip_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::RevocationWitnessMissing.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            push_log(
                &mut logs,
                &normalized,
                "revocation_round_trip_validation",
                "pass",
                None,
                Some(&extension_label),
                Some(&receipt_id),
                Some(&capability_label),
            );
        }

        for active_capability in &extension.active_capabilities {
            if traced_capabilities.contains(active_capability) {
                continue;
            }
            add_finding(
                &mut findings,
                PlasReleaseGateFailureCode::AmbientAuthorityDetected,
                &extension_label,
                None,
                format!(
                    "active capability `{}` is not traceable to any signed capability witness",
                    active_capability
                ),
            );
            push_log(
                &mut logs,
                &normalized,
                "ambient_authority_scan",
                "fail",
                Some(PlasReleaseGateFailureCode::AmbientAuthorityDetected.error_code()),
                Some(&extension_label),
                None,
                Some(active_capability.as_str()),
            );
        }

        if extension
            .active_capabilities
            .iter()
            .all(|capability| traced_capabilities.contains(capability))
        {
            push_log(
                &mut logs,
                &normalized,
                "ambient_authority_scan",
                "pass",
                None,
                Some(&extension_label),
                None,
                None,
            );
        }
    }

    findings.sort_by(|a, b| {
        a.code
            .cmp(&b.code)
            .then(a.extension_id.cmp(&b.extension_id))
            .then(a.receipt_id.cmp(&b.receipt_id))
            .then(a.detail.cmp(&b.detail))
    });

    let pass = findings.is_empty();
    push_log(
        &mut logs,
        &normalized,
        "release_gate_decision",
        if pass { "pass" } else { "fail" },
        if pass {
            None
        } else {
            Some("plas_release_gate_failed")
        },
        None,
        None,
        None,
    );

    let checked_extensions = normalized.extensions.len() as u64;
    let decision_hash = compute_decision_hash(
        &normalized,
        pass,
        checked_extensions,
        checked_grants,
        checked_revocations,
        &findings,
        &logs,
    )?;

    Ok(PlasReleaseGateDecisionArtifact {
        decision_id: normalized.decision_id,
        cohort_id: normalized.cohort_id,
        pass,
        checked_extensions,
        checked_grants,
        checked_revocations,
        findings,
        logs,
        decision_hash,
    })
}

fn normalize_receipt(receipt: &mut CapabilityEscrowReceiptRecord) {
    receipt.receipt_id = receipt.receipt_id.trim().to_string();
    receipt.decision_kind = receipt.decision_kind.trim().to_string();
    receipt.outcome = receipt.outcome.trim().to_string();
    receipt.trace_id = receipt.trace_id.trim().to_string();
    receipt.decision_id = receipt.decision_id.trim().to_string();
    receipt.policy_id = receipt.policy_id.trim().to_string();
    receipt.error_code = receipt
        .error_code
        .take()
        .map(|code| code.trim().to_string())
        .filter(|code| !code.is_empty());
}

fn validate_grant_receipt(
    receipt: &CapabilityEscrowReceiptRecord,
    extension_id: &EngineObjectId,
    capability_label: &str,
    expected_policy_id: &str,
) -> Result<(), String> {
    if receipt.receipt_id.is_empty() {
        return Err("grant receipt_id must not be empty".to_string());
    }
    if receipt.extension_id != *extension_id {
        return Err("grant receipt extension_id does not match cohort extension".to_string());
    }
    if receipt.timestamp_ns == 0 {
        return Err("grant receipt timestamp_ns must be > 0".to_string());
    }
    if receipt.decision_kind != "grant" {
        return Err("grant receipt decision_kind must be `grant`".to_string());
    }
    if receipt.outcome.is_empty() {
        return Err("grant receipt outcome must not be empty".to_string());
    }
    if receipt.policy_id != expected_policy_id {
        return Err("grant receipt policy_id does not match gate policy_id".to_string());
    }
    if receipt.capability.as_ref().map(Capability::as_str) != Some(capability_label) {
        return Err("grant receipt capability does not match grant capability".to_string());
    }
    Ok(())
}

fn validate_revocation_receipt(
    receipt: &CapabilityEscrowReceiptRecord,
    extension_id: &EngineObjectId,
    capability_label: &str,
    expected_policy_id: &str,
) -> Result<(), String> {
    if receipt.receipt_id.is_empty() {
        return Err("revocation receipt_id must not be empty".to_string());
    }
    if receipt.extension_id != *extension_id {
        return Err("revocation receipt extension_id does not match cohort extension".to_string());
    }
    if receipt.timestamp_ns == 0 {
        return Err("revocation receipt timestamp_ns must be > 0".to_string());
    }
    if receipt.decision_kind != "revoke" {
        return Err("revocation receipt decision_kind must be `revoke`".to_string());
    }
    if receipt.outcome.is_empty() {
        return Err("revocation receipt outcome must not be empty".to_string());
    }
    if receipt.policy_id != expected_policy_id {
        return Err("revocation receipt policy_id does not match gate policy_id".to_string());
    }
    if receipt.capability.as_ref().map(Capability::as_str) != Some(capability_label) {
        return Err("revocation receipt capability does not match revoked capability".to_string());
    }
    Ok(())
}

fn add_finding(
    findings: &mut Vec<PlasReleaseGateFinding>,
    code: PlasReleaseGateFailureCode,
    extension_id: &str,
    receipt_id: Option<&str>,
    detail: String,
) {
    findings.push(PlasReleaseGateFinding {
        code,
        extension_id: extension_id.to_string(),
        receipt_id: receipt_id.map(str::to_string),
        detail,
    });
}

#[allow(clippy::too_many_arguments)]
fn push_log(
    logs: &mut Vec<PlasReleaseGateLogEvent>,
    input: &PlasReleaseGateInput,
    event: &str,
    outcome: &str,
    error_code: Option<&str>,
    extension_id: Option<&str>,
    receipt_id: Option<&str>,
    capability: Option<&str>,
) {
    logs.push(PlasReleaseGateLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: PLAS_RELEASE_GATE_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code: error_code.map(str::to_string),
        extension_id: extension_id.map(str::to_string),
        receipt_id: receipt_id.map(str::to_string),
        capability: capability.map(str::to_string),
    });
}

fn compute_decision_hash(
    input: &PlasReleaseGateInput,
    pass: bool,
    checked_extensions: u64,
    checked_grants: u64,
    checked_revocations: u64,
    findings: &[PlasReleaseGateFinding],
    logs: &[PlasReleaseGateLogEvent],
) -> Result<ContentHash, PlasReleaseGateError> {
    let payload = serde_json::to_vec(&(
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
        &input.cohort_id,
        pass,
        checked_extensions,
        checked_grants,
        checked_revocations,
        findings,
        logs,
    ))
    .map_err(|err| PlasReleaseGateError::Serialization {
        detail: err.to_string(),
    })?;
    Ok(ContentHash::compute(&payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────

    fn ext_id(n: u8) -> EngineObjectId {
        EngineObjectId([n; 32])
    }

    fn trust_anchors() -> PlasReleaseGateTrustAnchors {
        PlasReleaseGateTrustAnchors {
            witness_verification_key: VerificationKey::from_bytes([1u8; 32]).unwrap(),
            transparency_log_verification_key: VerificationKey::from_bytes([2u8; 32]).unwrap(),
        }
    }

    fn minimal_extension(n: u8, mode: PlasActivationMode) -> PlasCohortExtension {
        PlasCohortExtension {
            extension_id: ext_id(n),
            activation_mode: mode,
            manifest_capabilities: BTreeSet::new(),
            active_capabilities: BTreeSet::new(),
            grants: Vec::new(),
            revocations: Vec::new(),
        }
    }

    fn make_input(extensions: Vec<PlasCohortExtension>) -> PlasReleaseGateInput {
        PlasReleaseGateInput {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            cohort_id: "c1".to_string(),
            extensions,
        }
    }

    // ── PlasActivationMode ──────────────────────────────────────────

    #[test]
    fn activation_mode_as_str() {
        assert_eq!(PlasActivationMode::Active.as_str(), "active");
        assert_eq!(PlasActivationMode::Shadow.as_str(), "shadow");
        assert_eq!(PlasActivationMode::AuditOnly.as_str(), "audit_only");
        assert_eq!(PlasActivationMode::Disabled.as_str(), "disabled");
    }

    #[test]
    fn activation_mode_display() {
        assert_eq!(format!("{}", PlasActivationMode::Active), "active");
        assert_eq!(format!("{}", PlasActivationMode::AuditOnly), "audit_only");
    }

    #[test]
    fn activation_mode_ordering() {
        assert!(PlasActivationMode::Active < PlasActivationMode::Shadow);
        assert!(PlasActivationMode::Shadow < PlasActivationMode::AuditOnly);
        assert!(PlasActivationMode::AuditOnly < PlasActivationMode::Disabled);
    }

    #[test]
    fn activation_mode_serde_roundtrip() {
        for variant in [
            PlasActivationMode::Active,
            PlasActivationMode::Shadow,
            PlasActivationMode::AuditOnly,
            PlasActivationMode::Disabled,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: PlasActivationMode = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // ── PlasReleaseGateFailureCode ──────────────────────────────────

    #[test]
    fn failure_code_error_code() {
        assert_eq!(
            PlasReleaseGateFailureCode::CohortPlasNotActive.error_code(),
            "cohort_plas_not_active"
        );
        assert_eq!(
            PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise.error_code(),
            "cohort_coverage_missing_grant_exercise"
        );
        assert_eq!(
            PlasReleaseGateFailureCode::MissingCapabilityWitness.error_code(),
            "missing_capability_witness"
        );
        assert_eq!(
            PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed.error_code(),
            "witness_signature_verification_failed"
        );
        assert_eq!(
            PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing.error_code(),
            "escrow_replay_evidence_missing"
        );
        assert_eq!(
            PlasReleaseGateFailureCode::EscrowReplayMismatch.error_code(),
            "escrow_replay_mismatch"
        );
        assert_eq!(
            PlasReleaseGateFailureCode::RevocationWitnessMissing.error_code(),
            "revocation_witness_missing"
        );
        assert_eq!(
            PlasReleaseGateFailureCode::RevocationEscrowEventMissing.error_code(),
            "revocation_escrow_event_missing"
        );
        assert_eq!(
            PlasReleaseGateFailureCode::AmbientAuthorityDetected.error_code(),
            "ambient_authority_detected"
        );
    }

    #[test]
    fn failure_code_display() {
        for variant in [
            PlasReleaseGateFailureCode::CohortPlasNotActive,
            PlasReleaseGateFailureCode::AmbientAuthorityDetected,
        ] {
            assert_eq!(format!("{variant}"), variant.error_code());
        }
    }

    #[test]
    fn failure_code_serde_roundtrip() {
        for variant in [
            PlasReleaseGateFailureCode::CohortPlasNotActive,
            PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise,
            PlasReleaseGateFailureCode::MissingCapabilityWitness,
            PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed,
            PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing,
            PlasReleaseGateFailureCode::EscrowReplayMismatch,
            PlasReleaseGateFailureCode::RevocationWitnessMissing,
            PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
            PlasReleaseGateFailureCode::AmbientAuthorityDetected,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: PlasReleaseGateFailureCode = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // ── PlasReleaseGateError ────────────────────────────────────────

    #[test]
    fn error_display_invalid_input() {
        let err = PlasReleaseGateError::InvalidInput {
            detail: "bad".to_string(),
        };
        assert_eq!(format!("{err}"), "invalid PLAS release gate input: bad");
    }

    #[test]
    fn error_display_serialization() {
        let err = PlasReleaseGateError::Serialization {
            detail: "oops".to_string(),
        };
        assert_eq!(format!("{err}"), "serialization failure: oops");
    }

    #[test]
    fn error_serde_roundtrip() {
        let err = PlasReleaseGateError::InvalidInput {
            detail: "test".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: PlasReleaseGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // ── PlasEscrowReplayEvidence ────────────────────────────────────

    #[test]
    fn replay_evidence_normalize_trims() {
        let mut e = PlasEscrowReplayEvidence {
            receipt_id: "  r1  ".to_string(),
            replay_decision_kind: "  grant  ".to_string(),
            replay_outcome: "  allow  ".to_string(),
            replay_policy_id: "  p1  ".to_string(),
            deterministic_replay: true,
            replay_trace_id: "  t1  ".to_string(),
        };
        e.normalize();
        assert_eq!(e.receipt_id, "r1");
        assert_eq!(e.replay_decision_kind, "grant");
        assert_eq!(e.replay_outcome, "allow");
        assert_eq!(e.replay_policy_id, "p1");
        assert_eq!(e.replay_trace_id, "t1");
    }

    #[test]
    fn replay_evidence_serde_roundtrip() {
        let e = PlasEscrowReplayEvidence {
            receipt_id: "r1".to_string(),
            replay_decision_kind: "grant".to_string(),
            replay_outcome: "allow".to_string(),
            replay_policy_id: "p1".to_string(),
            deterministic_replay: true,
            replay_trace_id: "t1".to_string(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: PlasEscrowReplayEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // ── PlasReleaseGateInput validation ─────────────────────────────

    #[test]
    fn input_validate_empty_trace_id() {
        let mut input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        input.trace_id = "".to_string();
        let err = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap_err();
        assert!(err.to_string().contains("trace_id"));
    }

    #[test]
    fn input_validate_empty_decision_id() {
        let mut input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        input.decision_id = "".to_string();
        let err = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap_err();
        assert!(err.to_string().contains("decision_id"));
    }

    #[test]
    fn input_validate_empty_policy_id() {
        let mut input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        input.policy_id = "".to_string();
        let err = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap_err();
        assert!(err.to_string().contains("policy_id"));
    }

    #[test]
    fn input_validate_empty_cohort_id() {
        let mut input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        input.cohort_id = "".to_string();
        let err = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap_err();
        assert!(err.to_string().contains("cohort_id"));
    }

    #[test]
    fn input_validate_no_extensions() {
        let input = make_input(vec![]);
        let err = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap_err();
        assert!(err.to_string().contains("at least one"));
    }

    #[test]
    fn input_validate_duplicate_extension() {
        let input = make_input(vec![
            minimal_extension(1, PlasActivationMode::Active),
            minimal_extension(1, PlasActivationMode::Active),
        ]);
        let err = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn input_normalize_trims_ids() {
        let mut input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        input.trace_id = "  t1  ".to_string();
        input.decision_id = "  d1  ".to_string();
        // This should not error — normalization trims before validation
        let result = evaluate_plas_release_gate(&input, &trust_anchors());
        assert!(result.is_ok());
    }

    // ── evaluate: CohortPlasNotActive ───────────────────────────────

    #[test]
    fn evaluate_not_active_shadow() {
        let input = make_input(vec![minimal_extension(1, PlasActivationMode::Shadow)]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        assert!(!result.pass);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PlasReleaseGateFailureCode::CohortPlasNotActive)
        );
    }

    #[test]
    fn evaluate_not_active_disabled() {
        let input = make_input(vec![minimal_extension(1, PlasActivationMode::Disabled)]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        assert!(!result.pass);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PlasReleaseGateFailureCode::CohortPlasNotActive)
        );
    }

    #[test]
    fn evaluate_not_active_audit_only() {
        let input = make_input(vec![minimal_extension(1, PlasActivationMode::AuditOnly)]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        assert!(!result.pass);
        let finding = result
            .findings
            .iter()
            .find(|f| f.code == PlasReleaseGateFailureCode::CohortPlasNotActive)
            .unwrap();
        assert!(finding.detail.contains("audit_only"));
    }

    // ── evaluate: CohortCoverageMissingGrantExercise ────────────────

    #[test]
    fn evaluate_empty_grants() {
        let input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        assert!(!result.pass);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise)
        );
    }

    // ── evaluate: AmbientAuthorityDetected ──────────────────────────

    #[test]
    fn evaluate_ambient_authority_no_grants() {
        let mut ext = minimal_extension(1, PlasActivationMode::Active);
        ext.active_capabilities
            .insert(Capability::new("net.connect"));
        let input = make_input(vec![ext]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        assert!(!result.pass);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PlasReleaseGateFailureCode::AmbientAuthorityDetected)
        );
    }

    // ── evaluate: decision artifact fields ──────────────────────────

    #[test]
    fn evaluate_decision_artifact_ids() {
        let input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        assert_eq!(result.decision_id, "d1");
        assert_eq!(result.cohort_id, "c1");
        assert_eq!(result.checked_extensions, 1);
        assert_eq!(result.checked_grants, 0);
        assert_eq!(result.checked_revocations, 0);
    }

    #[test]
    fn evaluate_decision_hash_deterministic() {
        let input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        let r1 = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        let r2 = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        assert_eq!(r1.decision_hash, r2.decision_hash);
    }

    #[test]
    fn evaluate_decision_hash_differs_on_different_input() {
        let input1 = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        let input2 = make_input(vec![minimal_extension(2, PlasActivationMode::Active)]);
        let r1 = evaluate_plas_release_gate(&input1, &trust_anchors()).unwrap();
        let r2 = evaluate_plas_release_gate(&input2, &trust_anchors()).unwrap();
        assert_ne!(r1.decision_hash, r2.decision_hash);
    }

    // ── evaluate: logs ──────────────────────────────────────────────

    #[test]
    fn evaluate_produces_logs() {
        let input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        assert!(!result.logs.is_empty());
        // Should have a release_gate_decision log
        assert!(
            result
                .logs
                .iter()
                .any(|l| l.event == "release_gate_decision")
        );
        // All logs should have component = plas_release_gate
        assert!(
            result
                .logs
                .iter()
                .all(|l| l.component == "plas_release_gate")
        );
    }

    #[test]
    fn evaluate_fail_log_has_error_code() {
        let input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        let decision_log = result
            .logs
            .iter()
            .find(|l| l.event == "release_gate_decision")
            .unwrap();
        assert_eq!(decision_log.outcome, "fail");
        assert_eq!(
            decision_log.error_code.as_deref(),
            Some("plas_release_gate_failed")
        );
    }

    // ── evaluate: multiple extensions ───────────────────────────────

    #[test]
    fn evaluate_multiple_extensions_all_checked() {
        let input = make_input(vec![
            minimal_extension(1, PlasActivationMode::Active),
            minimal_extension(2, PlasActivationMode::Shadow),
            minimal_extension(3, PlasActivationMode::Active),
        ]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        assert_eq!(result.checked_extensions, 3);
        assert!(!result.pass);
    }

    // ── PlasReleaseGateFinding serde ────────────────────────────────

    #[test]
    fn finding_serde_roundtrip() {
        let f = PlasReleaseGateFinding {
            code: PlasReleaseGateFailureCode::CohortPlasNotActive,
            extension_id: "ext-1".to_string(),
            receipt_id: Some("r-1".to_string()),
            detail: "not active".to_string(),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: PlasReleaseGateFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    // ── PlasReleaseGateLogEvent serde ───────────────────────────────

    #[test]
    fn log_event_serde_roundtrip() {
        let le = PlasReleaseGateLogEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            extension_id: Some("ext".to_string()),
            receipt_id: None,
            capability: Some("net.connect".to_string()),
        };
        let json = serde_json::to_string(&le).unwrap();
        let back: PlasReleaseGateLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(le, back);
    }

    // ── PlasReleaseGateDecisionArtifact serde ───────────────────────

    #[test]
    fn decision_artifact_serde_roundtrip() {
        let input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        let artifact = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        let json = serde_json::to_string(&artifact).unwrap();
        let back: PlasReleaseGateDecisionArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    // ── PlasReleaseGateInput serde ──────────────────────────────────

    #[test]
    fn input_serde_roundtrip() {
        let input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        let json = serde_json::to_string(&input).unwrap();
        let back: PlasReleaseGateInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    // ── PlasReleaseGateTrustAnchors serde ───────────────────────────

    #[test]
    fn trust_anchors_serde_roundtrip() {
        let ta = trust_anchors();
        let json = serde_json::to_string(&ta).unwrap();
        let back: PlasReleaseGateTrustAnchors = serde_json::from_str(&json).unwrap();
        assert_eq!(ta, back);
    }

    // ── PlasCohortExtension serde ───────────────────────────────────

    #[test]
    fn cohort_extension_serde_roundtrip() {
        let ext = minimal_extension(1, PlasActivationMode::Active);
        let json = serde_json::to_string(&ext).unwrap();
        let back: PlasCohortExtension = serde_json::from_str(&json).unwrap();
        assert_eq!(ext, back);
    }

    // ── findings sorted deterministically ───────────────────────────

    #[test]
    fn findings_sorted_by_code_then_extension() {
        let input = make_input(vec![
            minimal_extension(2, PlasActivationMode::Shadow),
            minimal_extension(1, PlasActivationMode::Disabled),
        ]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        let codes: Vec<_> = result.findings.iter().map(|f| f.code).collect();
        // All CohortPlasNotActive codes should be grouped (sorted)
        let mut sorted_codes = codes.clone();
        sorted_codes.sort();
        assert_eq!(codes, sorted_codes);
    }

    // -- Enrichment: error std::error trait --

    #[test]
    fn error_is_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(PlasReleaseGateError::InvalidInput {
                detail: "bad".to_string(),
            }),
            Box::new(PlasReleaseGateError::Serialization {
                detail: "json".to_string(),
            }),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: failure code ordering --

    #[test]
    fn failure_code_ordering() {
        assert!(
            PlasReleaseGateFailureCode::CohortPlasNotActive
                < PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise
        );
        assert!(
            PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise
                < PlasReleaseGateFailureCode::MissingCapabilityWitness
        );
        assert!(
            PlasReleaseGateFailureCode::MissingCapabilityWitness
                < PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed
        );
        assert!(
            PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed
                < PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing
        );
        assert!(
            PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing
                < PlasReleaseGateFailureCode::EscrowReplayMismatch
        );
        assert!(
            PlasReleaseGateFailureCode::EscrowReplayMismatch
                < PlasReleaseGateFailureCode::RevocationWitnessMissing
        );
        assert!(
            PlasReleaseGateFailureCode::RevocationWitnessMissing
                < PlasReleaseGateFailureCode::RevocationEscrowEventMissing
        );
        assert!(
            PlasReleaseGateFailureCode::RevocationEscrowEventMissing
                < PlasReleaseGateFailureCode::AmbientAuthorityDetected
        );
    }

    // -- Enrichment: failure code display all variants --

    #[test]
    fn failure_code_display_all_variants() {
        let codes = [
            PlasReleaseGateFailureCode::CohortPlasNotActive,
            PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise,
            PlasReleaseGateFailureCode::MissingCapabilityWitness,
            PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed,
            PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing,
            PlasReleaseGateFailureCode::EscrowReplayMismatch,
            PlasReleaseGateFailureCode::RevocationWitnessMissing,
            PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
            PlasReleaseGateFailureCode::AmbientAuthorityDetected,
        ];
        for code in &codes {
            assert!(!code.to_string().is_empty());
        }
    }

    // -- Enrichment: error serde all variants --

    #[test]
    fn error_serde_all_variants() {
        let errors = [
            PlasReleaseGateError::InvalidInput {
                detail: "bad input".to_string(),
            },
            PlasReleaseGateError::Serialization {
                detail: "json fail".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: PlasReleaseGateError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    // -- Enrichment: failure code error_code uniqueness --

    #[test]
    fn failure_code_error_codes_unique() {
        let codes = [
            PlasReleaseGateFailureCode::CohortPlasNotActive,
            PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise,
            PlasReleaseGateFailureCode::MissingCapabilityWitness,
            PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed,
            PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing,
            PlasReleaseGateFailureCode::EscrowReplayMismatch,
            PlasReleaseGateFailureCode::RevocationWitnessMissing,
            PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
            PlasReleaseGateFailureCode::AmbientAuthorityDetected,
        ];
        let error_codes: BTreeSet<&str> = codes.iter().map(|c| c.error_code()).collect();
        assert_eq!(error_codes.len(), codes.len());
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn escrow_replay_evidence_serde_false_deterministic() {
        let evidence = PlasEscrowReplayEvidence {
            receipt_id: "r1".into(),
            replay_decision_kind: "grant".into(),
            replay_outcome: "allow".into(),
            replay_policy_id: "p1".into(),
            deterministic_replay: false,
            replay_trace_id: "t1".into(),
        };
        let json = serde_json::to_string(&evidence).unwrap();
        let back: PlasEscrowReplayEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence, back);
        assert!(!back.deterministic_replay);
    }

    #[test]
    fn cohort_extension_empty_sets_serde() {
        let ext = PlasCohortExtension {
            extension_id: ext_id(5),
            activation_mode: PlasActivationMode::Active,
            manifest_capabilities: BTreeSet::new(),
            active_capabilities: BTreeSet::new(),
            grants: Vec::new(),
            revocations: Vec::new(),
        };
        let json = serde_json::to_string(&ext).unwrap();
        let back: PlasCohortExtension = serde_json::from_str(&json).unwrap();
        assert_eq!(ext, back);
        assert!(back.manifest_capabilities.is_empty());
        assert!(back.active_capabilities.is_empty());
    }

    #[test]
    fn finding_serde_no_receipt_id() {
        let finding = PlasReleaseGateFinding {
            code: PlasReleaseGateFailureCode::AmbientAuthorityDetected,
            extension_id: "ext-99".into(),
            receipt_id: None,
            detail: "ambient authority".into(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: PlasReleaseGateFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
        assert!(back.receipt_id.is_none());
    }

    #[test]
    fn log_event_all_none_optional_fields() {
        let le = PlasReleaseGateLogEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "pass".into(),
            error_code: None,
            extension_id: None,
            receipt_id: None,
            capability: None,
        };
        let json = serde_json::to_string(&le).unwrap();
        let back: PlasReleaseGateLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(le, back);
        assert!(back.error_code.is_none());
        assert!(back.extension_id.is_none());
        assert!(back.receipt_id.is_none());
        assert!(back.capability.is_none());
    }

    #[test]
    fn log_event_all_some_optional_fields() {
        let le = PlasReleaseGateLogEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "fail".into(),
            error_code: Some("err".into()),
            extension_id: Some("ext".into()),
            receipt_id: Some("rcpt".into()),
            capability: Some("cap".into()),
        };
        let json = serde_json::to_string(&le).unwrap();
        let back: PlasReleaseGateLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(le, back);
    }

    #[test]
    fn evaluate_extensions_sorted_deterministically() {
        let input1 = make_input(vec![
            minimal_extension(2, PlasActivationMode::Active),
            minimal_extension(1, PlasActivationMode::Active),
        ]);
        let input2 = make_input(vec![
            minimal_extension(1, PlasActivationMode::Active),
            minimal_extension(2, PlasActivationMode::Active),
        ]);
        let r1 = evaluate_plas_release_gate(&input1, &trust_anchors()).unwrap();
        let r2 = evaluate_plas_release_gate(&input2, &trust_anchors()).unwrap();
        assert_eq!(r1.decision_hash, r2.decision_hash);
    }

    #[test]
    fn activation_mode_serde_rename_snake_case() {
        let json = serde_json::to_string(&PlasActivationMode::AuditOnly).unwrap();
        assert_eq!(json, "\"audit_only\"");
        let back: PlasActivationMode = serde_json::from_str("\"audit_only\"").unwrap();
        assert_eq!(back, PlasActivationMode::AuditOnly);
    }

    #[test]
    fn error_display_all_unique() {
        let variants: Vec<PlasReleaseGateError> = vec![
            PlasReleaseGateError::InvalidInput { detail: "a".into() },
            PlasReleaseGateError::Serialization { detail: "b".into() },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(format!("{v}"));
        }
        assert_eq!(displays.len(), variants.len());
    }

    #[test]
    fn failure_code_serde_rename_snake_case() {
        let json = serde_json::to_string(&PlasReleaseGateFailureCode::CohortPlasNotActive).unwrap();
        assert_eq!(json, "\"cohort_plas_not_active\"");
        let back: PlasReleaseGateFailureCode =
            serde_json::from_str("\"cohort_plas_not_active\"").unwrap();
        assert_eq!(back, PlasReleaseGateFailureCode::CohortPlasNotActive);
    }

    // -- Enrichment: PearlTower 2026-02-27 --

    #[test]
    fn clone_equality_escrow_replay_evidence() {
        let a = PlasEscrowReplayEvidence {
            receipt_id: "r1".into(),
            replay_decision_kind: "grant".into(),
            replay_outcome: "allow".into(),
            replay_policy_id: "p1".into(),
            deterministic_replay: true,
            replay_trace_id: "t1".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_equality_finding() {
        let a = PlasReleaseGateFinding {
            code: PlasReleaseGateFailureCode::EscrowReplayMismatch,
            extension_id: "ext-42".into(),
            receipt_id: Some("r-42".into()),
            detail: "mismatch detail".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_equality_log_event() {
        let a = PlasReleaseGateLogEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "plas_release_gate".into(),
            event: "cohort_activation".into(),
            outcome: "pass".into(),
            error_code: None,
            extension_id: Some("ext".into()),
            receipt_id: None,
            capability: Some("net.connect".into()),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_equality_trust_anchors() {
        let a = trust_anchors();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_equality_cohort_extension() {
        let a = minimal_extension(7, PlasActivationMode::Shadow);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn json_field_presence_escrow_replay_evidence() {
        let e = PlasEscrowReplayEvidence {
            receipt_id: "r1".into(),
            replay_decision_kind: "grant".into(),
            replay_outcome: "allow".into(),
            replay_policy_id: "p1".into(),
            deterministic_replay: true,
            replay_trace_id: "t1".into(),
        };
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("\"receipt_id\""));
        assert!(j.contains("\"replay_decision_kind\""));
        assert!(j.contains("\"replay_outcome\""));
        assert!(j.contains("\"replay_policy_id\""));
        assert!(j.contains("\"deterministic_replay\""));
        assert!(j.contains("\"replay_trace_id\""));
    }

    #[test]
    fn json_field_presence_finding() {
        let f = PlasReleaseGateFinding {
            code: PlasReleaseGateFailureCode::AmbientAuthorityDetected,
            extension_id: "ext-1".into(),
            receipt_id: Some("r-1".into()),
            detail: "ambient".into(),
        };
        let j = serde_json::to_string(&f).unwrap();
        assert!(j.contains("\"code\""));
        assert!(j.contains("\"extension_id\""));
        assert!(j.contains("\"receipt_id\""));
        assert!(j.contains("\"detail\""));
    }

    #[test]
    fn json_field_presence_log_event() {
        let le = PlasReleaseGateLogEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "pass".into(),
            error_code: Some("err".into()),
            extension_id: Some("ext".into()),
            receipt_id: Some("rcpt".into()),
            capability: Some("cap".into()),
        };
        let j = serde_json::to_string(&le).unwrap();
        assert!(j.contains("\"trace_id\""));
        assert!(j.contains("\"decision_id\""));
        assert!(j.contains("\"policy_id\""));
        assert!(j.contains("\"component\""));
        assert!(j.contains("\"event\""));
        assert!(j.contains("\"outcome\""));
        assert!(j.contains("\"error_code\""));
    }

    #[test]
    fn display_uniqueness_activation_mode() {
        let variants = [
            PlasActivationMode::Active,
            PlasActivationMode::Shadow,
            PlasActivationMode::AuditOnly,
            PlasActivationMode::Disabled,
        ];
        let mut displays = BTreeSet::new();
        for v in &variants {
            assert!(
                displays.insert(v.to_string()),
                "duplicate display for {v:?}"
            );
        }
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn display_uniqueness_failure_code() {
        let codes = [
            PlasReleaseGateFailureCode::CohortPlasNotActive,
            PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise,
            PlasReleaseGateFailureCode::MissingCapabilityWitness,
            PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed,
            PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing,
            PlasReleaseGateFailureCode::EscrowReplayMismatch,
            PlasReleaseGateFailureCode::RevocationWitnessMissing,
            PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
            PlasReleaseGateFailureCode::AmbientAuthorityDetected,
        ];
        let mut displays = BTreeSet::new();
        for c in &codes {
            assert!(
                displays.insert(c.to_string()),
                "duplicate display for {c:?}"
            );
        }
        assert_eq!(displays.len(), 9);
    }

    #[test]
    fn error_source_is_none() {
        use std::error::Error;
        let err1 = PlasReleaseGateError::InvalidInput {
            detail: "test".into(),
        };
        let err2 = PlasReleaseGateError::Serialization {
            detail: "test".into(),
        };
        assert!(err1.source().is_none());
        assert!(err2.source().is_none());
    }

    #[test]
    fn whitespace_only_trace_id_rejected() {
        let mut input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        input.trace_id = "   ".to_string();
        let err = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap_err();
        assert!(err.to_string().contains("trace_id"));
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn enrichment_activation_mode_copy_semantics() {
        let a = PlasActivationMode::Shadow;
        let b = a; // Copy
        let c = a; // still usable after move — proves Copy
        assert_eq!(b, c);
        assert_eq!(a, PlasActivationMode::Shadow);
    }

    #[test]
    fn enrichment_activation_mode_in_btreeset() {
        let mut set = BTreeSet::new();
        set.insert(PlasActivationMode::Disabled);
        set.insert(PlasActivationMode::Active);
        set.insert(PlasActivationMode::Shadow);
        set.insert(PlasActivationMode::AuditOnly);
        set.insert(PlasActivationMode::Active); // duplicate
        assert_eq!(set.len(), 4);
        // Ord ordering: Active < Shadow < AuditOnly < Disabled
        let ordered: Vec<_> = set.into_iter().collect();
        assert_eq!(
            ordered,
            vec![
                PlasActivationMode::Active,
                PlasActivationMode::Shadow,
                PlasActivationMode::AuditOnly,
                PlasActivationMode::Disabled,
            ]
        );
    }

    #[test]
    fn enrichment_failure_code_copy_semantics() {
        let a = PlasReleaseGateFailureCode::EscrowReplayMismatch;
        let b = a;
        let c = a;
        assert_eq!(b, c);
        assert_eq!(a, PlasReleaseGateFailureCode::EscrowReplayMismatch);
    }

    #[test]
    fn enrichment_failure_code_in_btreeset() {
        let mut set = BTreeSet::new();
        set.insert(PlasReleaseGateFailureCode::AmbientAuthorityDetected);
        set.insert(PlasReleaseGateFailureCode::CohortPlasNotActive);
        set.insert(PlasReleaseGateFailureCode::MissingCapabilityWitness);
        set.insert(PlasReleaseGateFailureCode::CohortPlasNotActive); // dup
        assert_eq!(set.len(), 3);
        let first = *set.iter().next().unwrap();
        assert_eq!(first, PlasReleaseGateFailureCode::CohortPlasNotActive);
    }

    #[test]
    fn enrichment_activation_mode_debug_format() {
        let dbg = format!("{:?}", PlasActivationMode::AuditOnly);
        assert_eq!(dbg, "AuditOnly");
        let dbg2 = format!("{:?}", PlasActivationMode::Active);
        assert_eq!(dbg2, "Active");
    }

    #[test]
    fn enrichment_failure_code_debug_format() {
        let dbg = format!(
            "{:?}",
            PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing
        );
        assert_eq!(dbg, "EscrowReplayEvidenceMissing");
        let dbg2 = format!(
            "{:?}",
            PlasReleaseGateFailureCode::RevocationEscrowEventMissing
        );
        assert_eq!(dbg2, "RevocationEscrowEventMissing");
    }

    #[test]
    fn enrichment_error_clone_independence() {
        let original = PlasReleaseGateError::InvalidInput {
            detail: "original".to_string(),
        };
        let mut cloned = original.clone();
        // Mutate clone
        if let PlasReleaseGateError::InvalidInput { ref mut detail } = cloned {
            *detail = "mutated".to_string();
        }
        // Original unchanged
        assert_eq!(
            format!("{original}"),
            "invalid PLAS release gate input: original"
        );
        assert_eq!(
            format!("{cloned}"),
            "invalid PLAS release gate input: mutated"
        );
    }

    #[test]
    fn enrichment_decision_artifact_json_field_names() {
        let input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        let artifact = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        let json = serde_json::to_string(&artifact).unwrap();
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"cohort_id\""));
        assert!(json.contains("\"pass\""));
        assert!(json.contains("\"checked_extensions\""));
        assert!(json.contains("\"checked_grants\""));
        assert!(json.contains("\"checked_revocations\""));
        assert!(json.contains("\"findings\""));
        assert!(json.contains("\"logs\""));
        assert!(json.contains("\"decision_hash\""));
    }

    #[test]
    fn enrichment_input_json_field_names() {
        let input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"cohort_id\""));
        assert!(json.contains("\"extensions\""));
    }

    #[test]
    fn enrichment_trust_anchors_json_field_names() {
        let ta = trust_anchors();
        let json = serde_json::to_string(&ta).unwrap();
        assert!(json.contains("\"witness_verification_key\""));
        assert!(json.contains("\"transparency_log_verification_key\""));
    }

    #[test]
    fn enrichment_cohort_extension_default_fields_deserialize() {
        // When manifest_capabilities, active_capabilities, grants, revocations are absent,
        // serde(default) should fill them with empty collections.
        let json = r#"{
            "extension_id": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
            "activation_mode": "active"
        }"#;
        let ext: PlasCohortExtension = serde_json::from_str(json).unwrap();
        assert_eq!(ext.activation_mode, PlasActivationMode::Active);
        assert!(ext.manifest_capabilities.is_empty());
        assert!(ext.active_capabilities.is_empty());
        assert!(ext.grants.is_empty());
        assert!(ext.revocations.is_empty());
    }

    #[test]
    fn enrichment_whitespace_only_decision_id_rejected() {
        let mut input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        input.decision_id = "  \t  ".to_string();
        let err = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap_err();
        assert!(err.to_string().contains("decision_id"));
    }

    #[test]
    fn enrichment_whitespace_only_policy_id_rejected() {
        let mut input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        input.policy_id = " \n ".to_string();
        let err = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap_err();
        assert!(err.to_string().contains("policy_id"));
    }

    #[test]
    fn enrichment_whitespace_only_cohort_id_rejected() {
        let mut input = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        input.cohort_id = "   ".to_string();
        let err = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap_err();
        assert!(err.to_string().contains("cohort_id"));
    }

    #[test]
    fn enrichment_findings_sort_stability_same_code_different_extension() {
        // Two extensions both fail with CohortPlasNotActive; findings should be
        // sorted by extension_id within the same code.
        let input = make_input(vec![
            minimal_extension(5, PlasActivationMode::Disabled),
            minimal_extension(3, PlasActivationMode::Shadow),
        ]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        let not_active: Vec<&PlasReleaseGateFinding> = result
            .findings
            .iter()
            .filter(|f| f.code == PlasReleaseGateFailureCode::CohortPlasNotActive)
            .collect();
        assert_eq!(not_active.len(), 2);
        // Normalization sorts extensions by id string; ext_id(3) < ext_id(5)
        assert!(not_active[0].extension_id < not_active[1].extension_id);
    }

    #[test]
    fn enrichment_multiple_non_active_modes_all_reported() {
        let input = make_input(vec![
            minimal_extension(1, PlasActivationMode::Shadow),
            minimal_extension(2, PlasActivationMode::AuditOnly),
            minimal_extension(3, PlasActivationMode::Disabled),
        ]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        let not_active_count = result
            .findings
            .iter()
            .filter(|f| f.code == PlasReleaseGateFailureCode::CohortPlasNotActive)
            .count();
        assert_eq!(not_active_count, 3);

        // Each finding should mention the mode in detail
        let details: Vec<&str> = result
            .findings
            .iter()
            .filter(|f| f.code == PlasReleaseGateFailureCode::CohortPlasNotActive)
            .map(|f| f.detail.as_str())
            .collect();
        assert!(details.iter().any(|d| d.contains("shadow")));
        assert!(details.iter().any(|d| d.contains("audit_only")));
        assert!(details.iter().any(|d| d.contains("disabled")));
    }

    #[test]
    fn enrichment_decision_hash_sensitive_to_cohort_id() {
        let mut input1 = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        input1.cohort_id = "cohort_alpha".to_string();
        let mut input2 = make_input(vec![minimal_extension(1, PlasActivationMode::Active)]);
        input2.cohort_id = "cohort_beta".to_string();
        let r1 = evaluate_plas_release_gate(&input1, &trust_anchors()).unwrap();
        let r2 = evaluate_plas_release_gate(&input2, &trust_anchors()).unwrap();
        assert_ne!(r1.decision_hash, r2.decision_hash);
        assert_eq!(r1.cohort_id, "cohort_alpha");
        assert_eq!(r2.cohort_id, "cohort_beta");
    }

    #[test]
    fn enrichment_log_events_trace_id_consistency() {
        let input = make_input(vec![
            minimal_extension(1, PlasActivationMode::Active),
            minimal_extension(2, PlasActivationMode::Shadow),
        ]);
        let result = evaluate_plas_release_gate(&input, &trust_anchors()).unwrap();
        assert!(result.logs.len() >= 2);
        for log in &result.logs {
            assert_eq!(log.trace_id, "t1");
            assert_eq!(log.decision_id, "d1");
            assert_eq!(log.policy_id, "p1");
            assert_eq!(log.component, "plas_release_gate");
        }
    }
}
