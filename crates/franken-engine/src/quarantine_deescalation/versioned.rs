use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, SchemaHash};
use crate::engine_object_id::{
    derive_versioned_id, derive_versioned_schema_id, verify_versioned_id, ObjectDomain,
    ObjectIdDerivationVersion, PersistedEngineObjectId, PersistedSchemaId, VersionedIdError,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    sign_object, verify_signature, Signature, SignaturePreimage, SigningKey, VerificationKey,
    SIGNATURE_SENTINEL,
};

use super::compat::{
    AttestationStatus, FallbackPath, QuarantineReason, ReAdmissionDecision, ReAdmissionReceipt,
};

const DECISION_SCHEMA_V2: &[u8] = b"FrankenEngine.ReAdmissionDecision.sha256.v2";
const RECEIPT_SCHEMA_V2: &[u8] = b"FrankenEngine.ReAdmissionReceipt.sha256.v2";

pub const READMISSION_DECISION_PERSISTENCE_SCHEMA_V2: &str =
    "frankenengine.readmission-decision.persistence.v2";
pub const READMISSION_RECEIPT_PERSISTENCE_SCHEMA_V2: &str =
    "frankenengine.readmission-receipt.persistence.v2";

/// A verified legacy decision retained as immutable migration provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyReAdmissionDecisionProvenance {
    pub decision: ReAdmissionDecision,
    pub operator_verification_key: VerificationKey,
}

impl LegacyReAdmissionDecisionProvenance {
    pub fn verify(&self) -> Result<(), VersionedReAdmissionError> {
        let valid = self
            .decision
            .verify_signature(&self.operator_verification_key)
            .map_err(|error| VersionedReAdmissionError::LegacyVerification(error.to_string()))?;
        if valid {
            Ok(())
        } else {
            Err(VersionedReAdmissionError::LegacyVerification(
                "legacy re-admission decision signature is invalid".to_string(),
            ))
        }
    }

    pub fn content_hash(&self) -> ContentHash {
        let mut bytes = self.decision.preimage_bytes();
        bytes.extend_from_slice(&self.decision.operator_signature.to_bytes());
        bytes.extend_from_slice(self.operator_verification_key.as_bytes());
        ContentHash::compute(&bytes)
    }
}

/// A verified legacy receipt and both verification keys retained as migration provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyReAdmissionReceiptProvenance {
    pub receipt: ReAdmissionReceipt,
    pub operator_verification_key: VerificationKey,
    pub system_verification_key: VerificationKey,
}

impl LegacyReAdmissionReceiptProvenance {
    pub fn verify(&self) -> Result<(), VersionedReAdmissionError> {
        LegacyReAdmissionDecisionProvenance {
            decision: self.receipt.decision.clone(),
            operator_verification_key: self.operator_verification_key.clone(),
        }
        .verify()?;

        let valid = self
            .receipt
            .verify(&self.system_verification_key)
            .map_err(|error| VersionedReAdmissionError::LegacyVerification(error.to_string()))?;
        if valid {
            Ok(())
        } else {
            Err(VersionedReAdmissionError::LegacyVerification(
                "legacy re-admission receipt signature or content hash is invalid".to_string(),
            ))
        }
    }

    pub fn content_hash(&self) -> ContentHash {
        let decision_provenance = LegacyReAdmissionDecisionProvenance {
            decision: self.receipt.decision.clone(),
            operator_verification_key: self.operator_verification_key.clone(),
        };
        let mut bytes = self.receipt.preimage_bytes();
        bytes.extend_from_slice(&self.receipt.system_signature.to_bytes());
        bytes.extend_from_slice(decision_provenance.content_hash().as_bytes());
        bytes.extend_from_slice(self.system_verification_key.as_bytes());
        ContentHash::compute(&bytes)
    }
}

/// SHA-256-v2 re-admission decision with explicit persisted ID algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReAdmissionDecisionV2 {
    pub persistence_schema: String,
    pub schema_version: PersistedSchemaId,
    pub epoch: SecurityEpoch,
    pub decision_id: PersistedEngineObjectId,
    pub legacy_provenance: Option<LegacyReAdmissionDecisionProvenance>,
    pub original_quarantine_id: PersistedEngineObjectId,
    pub original_quarantine_reason: QuarantineReason,
    pub time_in_quarantine_secs: u64,
    pub operator_id: String,
    pub tee_attestation: AttestationStatus,
    pub posterior_confidence_millionths: u64,
    pub fallback_path: FallbackPath,
    pub metadata: BTreeMap<String, String>,
    pub operator_signature: Signature,
}

impl ReAdmissionDecisionV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: SecurityEpoch,
        original_quarantine_id: PersistedEngineObjectId,
        original_quarantine_reason: QuarantineReason,
        time_in_quarantine_secs: u64,
        operator_id: String,
        tee_attestation: AttestationStatus,
        posterior_confidence_millionths: u64,
        fallback_path: FallbackPath,
        metadata: BTreeMap<String, String>,
        operator_key: &SigningKey,
    ) -> Result<Self, VersionedReAdmissionError> {
        Self::build(
            epoch,
            None,
            original_quarantine_id,
            original_quarantine_reason,
            time_in_quarantine_secs,
            operator_id,
            tee_attestation,
            posterior_confidence_millionths,
            fallback_path,
            metadata,
            operator_key,
        )
    }

    /// Verify the legacy signature before re-signing an equivalent v2 decision.
    pub fn migrate_verified_legacy(
        legacy: &ReAdmissionDecision,
        legacy_operator_key: &VerificationKey,
        new_operator_key: &SigningKey,
    ) -> Result<Self, VersionedReAdmissionError> {
        let provenance = LegacyReAdmissionDecisionProvenance {
            decision: legacy.clone(),
            operator_verification_key: legacy_operator_key.clone(),
        };
        provenance.verify()?;

        Self::build(
            legacy.epoch,
            Some(provenance),
            PersistedEngineObjectId::legacy(legacy.original_quarantine_id.clone()),
            legacy.original_quarantine_reason.clone(),
            legacy.time_in_quarantine_secs,
            legacy.operator_id.clone(),
            legacy.tee_attestation.clone(),
            legacy.posterior_confidence_millionths,
            legacy.fallback_path.clone(),
            legacy.metadata.clone(),
            new_operator_key,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        epoch: SecurityEpoch,
        legacy_provenance: Option<LegacyReAdmissionDecisionProvenance>,
        original_quarantine_id: PersistedEngineObjectId,
        original_quarantine_reason: QuarantineReason,
        time_in_quarantine_secs: u64,
        operator_id: String,
        tee_attestation: AttestationStatus,
        posterior_confidence_millionths: u64,
        fallback_path: FallbackPath,
        metadata: BTreeMap<String, String>,
        operator_key: &SigningKey,
    ) -> Result<Self, VersionedReAdmissionError> {
        validate_decision_fields(&operator_id, posterior_confidence_millionths)?;
        let schema = derive_versioned_schema_id(
            ObjectIdDerivationVersion::Sha256V2,
            DECISION_SCHEMA_V2,
        )?;
        let identity_material = decision_identity_material(
            epoch,
            legacy_provenance.as_ref(),
            &original_quarantine_id,
            &original_quarantine_reason,
            time_in_quarantine_secs,
            &operator_id,
            &tee_attestation,
            posterior_confidence_millionths,
            &fallback_path,
            &metadata,
        )?;
        let decision_id = derive_versioned_id(
            ObjectDomain::PolicyObject,
            "readmission_decision_v2",
            &schema,
            &identity_material,
        )?;

        let mut decision = Self {
            persistence_schema: READMISSION_DECISION_PERSISTENCE_SCHEMA_V2.to_string(),
            schema_version: PersistedSchemaId::from_versioned(schema),
            epoch,
            decision_id: PersistedEngineObjectId::from_versioned(decision_id),
            legacy_provenance,
            original_quarantine_id,
            original_quarantine_reason,
            time_in_quarantine_secs,
            operator_id,
            tee_attestation,
            posterior_confidence_millionths,
            fallback_path,
            metadata,
            operator_signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        decision.validate_identity()?;
        decision.operator_signature = sign_object(&decision, operator_key)
            .map_err(|error| VersionedReAdmissionError::Signing(error.to_string()))?;
        Ok(decision)
    }

    pub fn validate_identity(&self) -> Result<(), VersionedReAdmissionError> {
        if self.persistence_schema != READMISSION_DECISION_PERSISTENCE_SCHEMA_V2 {
            return Err(VersionedReAdmissionError::UnsupportedSchema {
                actual: self.persistence_schema.clone(),
            });
        }
        validate_decision_fields(
            &self.operator_id,
            self.posterior_confidence_millionths,
        )?;
        require_v2_schema(
            "decision.schema_version",
            &self.schema_version,
            DECISION_SCHEMA_V2,
        )?;
        require_v2_object("decision.decision_id", &self.decision_id)?;
        validate_legacy_decision_mapping(self)?;

        let identity_material = decision_identity_material(
            self.epoch,
            self.legacy_provenance.as_ref(),
            &self.original_quarantine_id,
            &self.original_quarantine_reason,
            self.time_in_quarantine_secs,
            &self.operator_id,
            &self.tee_attestation,
            self.posterior_confidence_millionths,
            &self.fallback_path,
            &self.metadata,
        )?;
        verify_versioned_id(
            &self.decision_id.to_versioned(),
            ObjectDomain::PolicyObject,
            "readmission_decision_v2",
            &self.schema_version.to_versioned(),
            &identity_material,
        )?;
        Ok(())
    }

    pub fn verify(
        &self,
        operator_key: &VerificationKey,
    ) -> Result<bool, VersionedReAdmissionError> {
        self.validate_identity()?;
        Ok(verify_signature(
            operator_key,
            &self.preimage_bytes(),
            &self.operator_signature,
        )
        .is_ok())
    }
}

/// SHA-256-v2 evidence-chain receipt for a re-admission decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReAdmissionReceiptV2 {
    pub persistence_schema: String,
    pub schema_version: PersistedSchemaId,
    pub epoch: SecurityEpoch,
    pub receipt_id: PersistedEngineObjectId,
    pub legacy_provenance: Option<LegacyReAdmissionReceiptProvenance>,
    pub decision: ReAdmissionDecisionV2,
    pub prev_evidence_hash: ContentHash,
    pub content_hash: ContentHash,
    pub generated_at_secs: u64,
    pub system_signature: Signature,
}

impl ReAdmissionReceiptV2 {
    pub fn new(
        epoch: SecurityEpoch,
        decision: ReAdmissionDecisionV2,
        operator_key: &VerificationKey,
        prev_evidence_hash: ContentHash,
        generated_at_secs: u64,
        system_key: &SigningKey,
    ) -> Result<Self, VersionedReAdmissionError> {
        Self::build(
            epoch,
            None,
            decision,
            operator_key,
            prev_evidence_hash,
            generated_at_secs,
            system_key,
        )
    }

    /// Verify the complete legacy chain before emitting a v2 receipt.
    pub fn migrate_verified_legacy(
        legacy: &ReAdmissionReceipt,
        legacy_operator_key: &VerificationKey,
        legacy_system_key: &VerificationKey,
        new_operator_key: &SigningKey,
        new_system_key: &SigningKey,
    ) -> Result<Self, VersionedReAdmissionError> {
        let provenance = LegacyReAdmissionReceiptProvenance {
            receipt: legacy.clone(),
            operator_verification_key: legacy_operator_key.clone(),
            system_verification_key: legacy_system_key.clone(),
        };
        provenance.verify()?;

        let decision = ReAdmissionDecisionV2::migrate_verified_legacy(
            &legacy.decision,
            legacy_operator_key,
            new_operator_key,
        )?;
        let new_operator_verification_key = new_operator_key.verification_key();
        Self::build(
            legacy.epoch,
            Some(provenance),
            decision,
            &new_operator_verification_key,
            legacy.prev_evidence_hash,
            legacy.generated_at_secs,
            new_system_key,
        )
    }

    fn build(
        epoch: SecurityEpoch,
        legacy_provenance: Option<LegacyReAdmissionReceiptProvenance>,
        decision: ReAdmissionDecisionV2,
        operator_key: &VerificationKey,
        prev_evidence_hash: ContentHash,
        generated_at_secs: u64,
        system_key: &SigningKey,
    ) -> Result<Self, VersionedReAdmissionError> {
        if epoch != decision.epoch {
            return Err(VersionedReAdmissionError::InvalidInput(
                "receipt epoch must match decision epoch".to_string(),
            ));
        }
        if !decision.verify(operator_key)? {
            return Err(VersionedReAdmissionError::InvalidInput(
                "decision signature is invalid".to_string(),
            ));
        }

        let schema = derive_versioned_schema_id(
            ObjectIdDerivationVersion::Sha256V2,
            RECEIPT_SCHEMA_V2,
        )?;
        let material = receipt_content_material(
            epoch,
            legacy_provenance.as_ref(),
            &decision,
            &prev_evidence_hash,
            generated_at_secs,
        )?;
        let content_hash = ContentHash::compute(&material);
        let receipt_id = derive_versioned_id(
            ObjectDomain::EvidenceRecord,
            "readmission_receipt_v2",
            &schema,
            &material,
        )?;

        let mut receipt = Self {
            persistence_schema: READMISSION_RECEIPT_PERSISTENCE_SCHEMA_V2.to_string(),
            schema_version: PersistedSchemaId::from_versioned(schema),
            epoch,
            receipt_id: PersistedEngineObjectId::from_versioned(receipt_id),
            legacy_provenance,
            decision,
            prev_evidence_hash,
            content_hash,
            generated_at_secs,
            system_signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        receipt.validate_identity()?;
        receipt.system_signature = sign_object(&receipt, system_key)
            .map_err(|error| VersionedReAdmissionError::Signing(error.to_string()))?;
        Ok(receipt)
    }

    pub fn validate_identity(&self) -> Result<(), VersionedReAdmissionError> {
        if self.persistence_schema != READMISSION_RECEIPT_PERSISTENCE_SCHEMA_V2 {
            return Err(VersionedReAdmissionError::UnsupportedSchema {
                actual: self.persistence_schema.clone(),
            });
        }
        if self.epoch != self.decision.epoch {
            return Err(VersionedReAdmissionError::InvalidInput(
                "receipt epoch must match decision epoch".to_string(),
            ));
        }
        self.decision.validate_identity()?;
        require_v2_schema(
            "receipt.schema_version",
            &self.schema_version,
            RECEIPT_SCHEMA_V2,
        )?;
        require_v2_object("receipt.receipt_id", &self.receipt_id)?;
        validate_legacy_receipt_mapping(self)?;

        let material = receipt_content_material(
            self.epoch,
            self.legacy_provenance.as_ref(),
            &self.decision,
            &self.prev_evidence_hash,
            self.generated_at_secs,
        )?;
        let expected_content_hash = ContentHash::compute(&material);
        if self.content_hash != expected_content_hash {
            return Err(VersionedReAdmissionError::ContentHashMismatch);
        }
        verify_versioned_id(
            &self.receipt_id.to_versioned(),
            ObjectDomain::EvidenceRecord,
            "readmission_receipt_v2",
            &self.schema_version.to_versioned(),
            &material,
        )?;
        Ok(())
    }

    pub fn verify(
        &self,
        operator_key: &VerificationKey,
        system_key: &VerificationKey,
    ) -> Result<bool, VersionedReAdmissionError> {
        self.validate_identity()?;
        if !self.decision.verify(operator_key)? {
            return Ok(false);
        }
        Ok(verify_signature(
            system_key,
            &self.preimage_bytes(),
            &self.system_signature,
        )
        .is_ok())
    }

    pub fn genesis_hash() -> ContentHash {
        ContentHash::compute(b"genesis-quarantine-deescalation-sha256-v2")
    }
}

fn decision_signature_schema() -> &'static SchemaHash {
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(DECISION_SCHEMA_V2));
    &HASH
}

fn receipt_signature_schema() -> &'static SchemaHash {
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(RECEIPT_SCHEMA_V2));
    &HASH
}

impl SignaturePreimage for ReAdmissionDecisionV2 {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn signature_schema(&self) -> &SchemaHash {
        decision_signature_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "persistence_schema".to_string(),
            CanonicalValue::String(self.persistence_schema.clone()),
        );
        insert_schema_id(&mut map, "schema_version", &self.schema_version);
        map.insert("epoch".to_string(), CanonicalValue::U64(self.epoch.as_u64()));
        insert_object_id(&mut map, "decision_id", &self.decision_id);
        map.insert(
            "legacy_provenance_hash".to_string(),
            CanonicalValue::Bytes(optional_decision_provenance_hash(
                self.legacy_provenance.as_ref(),
            )),
        );
        insert_object_id(
            &mut map,
            "original_quarantine_id",
            &self.original_quarantine_id,
        );
        map.insert(
            "original_quarantine_reason".to_string(),
            CanonicalValue::String(self.original_quarantine_reason.to_string()),
        );
        map.insert(
            "time_in_quarantine_secs".to_string(),
            CanonicalValue::U64(self.time_in_quarantine_secs),
        );
        map.insert(
            "operator_id".to_string(),
            CanonicalValue::String(self.operator_id.clone()),
        );
        map.insert(
            "tee_attestation".to_string(),
            CanonicalValue::String(self.tee_attestation.to_string()),
        );
        map.insert(
            "posterior_confidence_millionths".to_string(),
            CanonicalValue::U64(self.posterior_confidence_millionths),
        );
        map.insert(
            "fallback_path".to_string(),
            CanonicalValue::String(self.fallback_path.to_string()),
        );
        map.insert("metadata".to_string(), canonical_metadata(&self.metadata));
        map.insert(
            "operator_signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        CanonicalValue::Map(map)
    }
}

impl SignaturePreimage for ReAdmissionReceiptV2 {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn signature_schema(&self) -> &SchemaHash {
        receipt_signature_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "persistence_schema".to_string(),
            CanonicalValue::String(self.persistence_schema.clone()),
        );
        insert_schema_id(&mut map, "schema_version", &self.schema_version);
        map.insert("epoch".to_string(), CanonicalValue::U64(self.epoch.as_u64()));
        insert_object_id(&mut map, "receipt_id", &self.receipt_id);
        insert_object_id(&mut map, "decision_id", &self.decision.decision_id);
        map.insert(
            "legacy_provenance_hash".to_string(),
            CanonicalValue::Bytes(optional_receipt_provenance_hash(
                self.legacy_provenance.as_ref(),
            )),
        );
        map.insert(
            "decision_signature".to_string(),
            CanonicalValue::Bytes(self.decision.operator_signature.to_bytes().to_vec()),
        );
        map.insert(
            "prev_evidence_hash".to_string(),
            CanonicalValue::Bytes(self.prev_evidence_hash.as_bytes().to_vec()),
        );
        map.insert(
            "content_hash".to_string(),
            CanonicalValue::Bytes(self.content_hash.as_bytes().to_vec()),
        );
        map.insert(
            "generated_at_secs".to_string(),
            CanonicalValue::U64(self.generated_at_secs),
        );
        map.insert(
            "system_signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        CanonicalValue::Map(map)
    }
}

#[allow(clippy::too_many_arguments)]
fn decision_identity_material(
    epoch: SecurityEpoch,
    legacy_provenance: Option<&LegacyReAdmissionDecisionProvenance>,
    original_quarantine_id: &PersistedEngineObjectId,
    original_quarantine_reason: &QuarantineReason,
    time_in_quarantine_secs: u64,
    operator_id: &str,
    tee_attestation: &AttestationStatus,
    posterior_confidence_millionths: u64,
    fallback_path: &FallbackPath,
    metadata: &BTreeMap<String, String>,
) -> Result<Vec<u8>, VersionedReAdmissionError> {
    let mut bytes = Vec::new();
    append_length_prefixed(
        &mut bytes,
        "persistence_schema",
        READMISSION_DECISION_PERSISTENCE_SCHEMA_V2.as_bytes(),
    )?;
    bytes.extend_from_slice(&epoch.as_u64().to_be_bytes());
    append_optional_hash(
        &mut bytes,
        legacy_provenance.map(LegacyReAdmissionDecisionProvenance::content_hash),
    );
    append_object_id(&mut bytes, original_quarantine_id)?;
    append_length_prefixed(
        &mut bytes,
        "original_quarantine_reason",
        original_quarantine_reason.to_string().as_bytes(),
    )?;
    bytes.extend_from_slice(&time_in_quarantine_secs.to_be_bytes());
    append_length_prefixed(&mut bytes, "operator_id", operator_id.as_bytes())?;
    append_length_prefixed(
        &mut bytes,
        "tee_attestation",
        tee_attestation.to_string().as_bytes(),
    )?;
    bytes.extend_from_slice(&posterior_confidence_millionths.to_be_bytes());
    append_length_prefixed(
        &mut bytes,
        "fallback_path",
        fallback_path.to_string().as_bytes(),
    )?;
    append_metadata(&mut bytes, metadata)?;
    Ok(bytes)
}

fn receipt_content_material(
    epoch: SecurityEpoch,
    legacy_provenance: Option<&LegacyReAdmissionReceiptProvenance>,
    decision: &ReAdmissionDecisionV2,
    prev_evidence_hash: &ContentHash,
    generated_at_secs: u64,
) -> Result<Vec<u8>, VersionedReAdmissionError> {
    let mut bytes = Vec::new();
    append_length_prefixed(
        &mut bytes,
        "persistence_schema",
        READMISSION_RECEIPT_PERSISTENCE_SCHEMA_V2.as_bytes(),
    )?;
    bytes.extend_from_slice(&epoch.as_u64().to_be_bytes());
    append_optional_hash(
        &mut bytes,
        legacy_provenance.map(LegacyReAdmissionReceiptProvenance::content_hash),
    );
    append_length_prefixed(&mut bytes, "decision_preimage", &decision.preimage_bytes())?;
    bytes.extend_from_slice(&decision.operator_signature.to_bytes());
    bytes.extend_from_slice(prev_evidence_hash.as_bytes());
    bytes.extend_from_slice(&generated_at_secs.to_be_bytes());
    Ok(bytes)
}

fn validate_legacy_decision_mapping(
    decision: &ReAdmissionDecisionV2,
) -> Result<(), VersionedReAdmissionError> {
    let Some(provenance) = &decision.legacy_provenance else {
        return Ok(());
    };
    provenance.verify()?;
    let legacy = &provenance.decision;
    if decision.epoch != legacy.epoch {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch("epoch"));
    }
    if decision.original_quarantine_id
        != PersistedEngineObjectId::legacy(legacy.original_quarantine_id.clone())
    {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch(
            "original_quarantine_id",
        ));
    }
    if decision.original_quarantine_reason != legacy.original_quarantine_reason {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch(
            "original_quarantine_reason",
        ));
    }
    if decision.time_in_quarantine_secs != legacy.time_in_quarantine_secs {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch(
            "time_in_quarantine_secs",
        ));
    }
    if decision.operator_id != legacy.operator_id {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch("operator_id"));
    }
    if decision.tee_attestation != legacy.tee_attestation {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch(
            "tee_attestation",
        ));
    }
    if decision.posterior_confidence_millionths != legacy.posterior_confidence_millionths {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch(
            "posterior_confidence_millionths",
        ));
    }
    if decision.fallback_path != legacy.fallback_path {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch(
            "fallback_path",
        ));
    }
    if decision.metadata != legacy.metadata {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch("metadata"));
    }
    Ok(())
}

fn validate_legacy_receipt_mapping(
    receipt: &ReAdmissionReceiptV2,
) -> Result<(), VersionedReAdmissionError> {
    let Some(provenance) = &receipt.legacy_provenance else {
        return Ok(());
    };
    provenance.verify()?;
    let Some(decision_provenance) = &receipt.decision.legacy_provenance else {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch(
            "decision.legacy_provenance",
        ));
    };
    if provenance.receipt.decision != decision_provenance.decision
        || provenance.operator_verification_key != decision_provenance.operator_verification_key
    {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch(
            "decision legacy provenance",
        ));
    }
    if receipt.epoch != provenance.receipt.epoch {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch("receipt epoch"));
    }
    if receipt.prev_evidence_hash != provenance.receipt.prev_evidence_hash {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch(
            "prev_evidence_hash",
        ));
    }
    if receipt.generated_at_secs != provenance.receipt.generated_at_secs {
        return Err(VersionedReAdmissionError::LegacyMappingMismatch(
            "generated_at_secs",
        ));
    }
    Ok(())
}

fn validate_decision_fields(
    operator_id: &str,
    posterior_confidence_millionths: u64,
) -> Result<(), VersionedReAdmissionError> {
    if operator_id.trim().is_empty() {
        return Err(VersionedReAdmissionError::InvalidInput(
            "operator_id must not be empty".to_string(),
        ));
    }
    if posterior_confidence_millionths > 1_000_000 {
        return Err(VersionedReAdmissionError::InvalidInput(
            "posterior_confidence_millionths must be <= 1_000_000".to_string(),
        ));
    }
    Ok(())
}

fn require_v2_schema(
    field: &'static str,
    actual: &PersistedSchemaId,
    definition: &[u8],
) -> Result<(), VersionedReAdmissionError> {
    if actual.derivation_version != ObjectIdDerivationVersion::Sha256V2 {
        return Err(VersionedReAdmissionError::AlgorithmMismatch {
            field,
            actual: actual.derivation_version,
        });
    }
    let expected = PersistedSchemaId::from_versioned(derive_versioned_schema_id(
        ObjectIdDerivationVersion::Sha256V2,
        definition,
    )?);
    if actual != &expected {
        return Err(VersionedReAdmissionError::SchemaMismatch { field });
    }
    Ok(())
}

fn require_v2_object(
    field: &'static str,
    actual: &PersistedEngineObjectId,
) -> Result<(), VersionedReAdmissionError> {
    if actual.derivation_version != ObjectIdDerivationVersion::Sha256V2 {
        return Err(VersionedReAdmissionError::AlgorithmMismatch {
            field,
            actual: actual.derivation_version,
        });
    }
    Ok(())
}

fn canonical_metadata(metadata: &BTreeMap<String, String>) -> CanonicalValue {
    CanonicalValue::Map(
        metadata
            .iter()
            .map(|(key, value)| (key.clone(), CanonicalValue::String(value.clone())))
            .collect(),
    )
}

fn insert_object_id(
    map: &mut BTreeMap<String, CanonicalValue>,
    field: &str,
    value: &PersistedEngineObjectId,
) {
    map.insert(
        format!("{field}_derivation_version"),
        CanonicalValue::String(value.derivation_version.as_str().to_string()),
    );
    map.insert(
        field.to_string(),
        CanonicalValue::Bytes(value.as_bytes().to_vec()),
    );
}

fn insert_schema_id(
    map: &mut BTreeMap<String, CanonicalValue>,
    field: &str,
    value: &PersistedSchemaId,
) {
    map.insert(
        format!("{field}_derivation_version"),
        CanonicalValue::String(value.derivation_version.as_str().to_string()),
    );
    map.insert(
        field.to_string(),
        CanonicalValue::Bytes(value.as_bytes().to_vec()),
    );
}

fn append_object_id(
    bytes: &mut Vec<u8>,
    value: &PersistedEngineObjectId,
) -> Result<(), VersionedReAdmissionError> {
    append_length_prefixed(
        bytes,
        "object_id_derivation_version",
        value.derivation_version.as_str().as_bytes(),
    )?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn append_metadata(
    bytes: &mut Vec<u8>,
    metadata: &BTreeMap<String, String>,
) -> Result<(), VersionedReAdmissionError> {
    let count = u32::try_from(metadata.len()).map_err(|_| {
        VersionedReAdmissionError::LengthOverflow {
            field: "metadata".to_string(),
            length: metadata.len(),
        }
    })?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for (key, value) in metadata {
        append_length_prefixed(bytes, "metadata_key", key.as_bytes())?;
        append_length_prefixed(bytes, "metadata_value", value.as_bytes())?;
    }
    Ok(())
}

fn append_length_prefixed(
    bytes: &mut Vec<u8>,
    field: &'static str,
    value: &[u8],
) -> Result<(), VersionedReAdmissionError> {
    let length = u32::try_from(value.len()).map_err(|_| {
        VersionedReAdmissionError::LengthOverflow {
            field: field.to_string(),
            length: value.len(),
        }
    })?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn append_optional_hash(bytes: &mut Vec<u8>, hash: Option<ContentHash>) {
    match hash {
        Some(hash) => {
            bytes.push(1);
            bytes.extend_from_slice(hash.as_bytes());
        }
        None => bytes.push(0),
    }
}

fn optional_decision_provenance_hash(
    provenance: Option<&LegacyReAdmissionDecisionProvenance>,
) -> Vec<u8> {
    provenance
        .map(LegacyReAdmissionDecisionProvenance::content_hash)
        .map(|hash| hash.as_bytes().to_vec())
        .unwrap_or_default()
}

fn optional_receipt_provenance_hash(
    provenance: Option<&LegacyReAdmissionReceiptProvenance>,
) -> Vec<u8> {
    provenance
        .map(LegacyReAdmissionReceiptProvenance::content_hash)
        .map(|hash| hash.as_bytes().to_vec())
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionedReAdmissionError {
    InvalidInput(String),
    UnsupportedSchema {
        actual: String,
    },
    AlgorithmMismatch {
        field: &'static str,
        actual: ObjectIdDerivationVersion,
    },
    SchemaMismatch {
        field: &'static str,
    },
    ContentHashMismatch,
    LegacyMappingMismatch(&'static str),
    LegacyVerification(String),
    LengthOverflow {
        field: String,
        length: usize,
    },
    Signing(String),
    Identity(VersionedIdError),
}

impl std::fmt::Display for VersionedReAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(detail) | Self::LegacyVerification(detail) | Self::Signing(detail) => {
                formatter.write_str(detail)
            }
            Self::UnsupportedSchema { actual } => {
                write!(formatter, "unsupported persistence schema {actual:?}")
            }
            Self::AlgorithmMismatch { field, actual } => {
                write!(formatter, "{field} uses {actual}; sha256_v2 is required")
            }
            Self::SchemaMismatch { field } => write!(formatter, "{field} does not match v2"),
            Self::ContentHashMismatch => formatter.write_str("receipt content hash mismatch"),
            Self::LegacyMappingMismatch(field) => {
                write!(formatter, "legacy migration provenance mismatch at {field}")
            }
            Self::LengthOverflow { field, length } => {
                write!(formatter, "{field} length {length} exceeds u32 encoding")
            }
            Self::Identity(error) => write!(formatter, "identity verification failed: {error}"),
        }
    }
}

impl std::error::Error for VersionedReAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VersionedIdError> for VersionedReAdmissionError {
    fn from(value: VersionedIdError) -> Self {
        Self::Identity(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::{
        derive_versioned_id, derive_versioned_schema_id, EngineObjectId, VersionedEngineObjectId,
    };
    use crate::signature_preimage::generate_keypair;

    fn reason() -> QuarantineReason {
        QuarantineReason::OperatorInitiated {
            operator_id: "security".to_string(),
            reason: "investigation".to_string(),
        }
    }

    fn fallback() -> FallbackPath {
        FallbackPath::AutoReQuarantine {
            policy_id: "strict".to_string(),
            escalation_threshold: 1,
        }
    }

    fn fresh_original() -> PersistedEngineObjectId {
        let schema = derive_versioned_schema_id(
            ObjectIdDerivationVersion::Sha256V2,
            b"FrankenEngine.QuarantineEntry.test.v2",
        )
        .expect("schema");
        PersistedEngineObjectId::from_versioned(
            derive_versioned_id(
                ObjectDomain::EvidenceRecord,
                "quarantine",
                &schema,
                b"quarantine-entry",
            )
            .expect("object id"),
        )
    }

    fn fresh_decision(key: &SigningKey) -> ReAdmissionDecisionV2 {
        ReAdmissionDecisionV2::new(
            SecurityEpoch::from_raw(7),
            fresh_original(),
            reason(),
            30,
            "operator".to_string(),
            AttestationStatus::NotAvailable,
            900_000,
            fallback(),
            BTreeMap::new(),
            key,
        )
        .expect("v2 decision")
    }

    #[test]
    fn v2_decision_and_receipt_verify_end_to_end() {
        let (operator_key, operator_verification_key) = generate_keypair();
        let (system_key, system_verification_key) = generate_keypair();
        let decision = fresh_decision(&operator_key);
        assert!(decision.verify(&operator_verification_key).expect("decision verify"));
        assert_eq!(
            decision.decision_id.derivation_version,
            ObjectIdDerivationVersion::Sha256V2
        );

        let receipt = ReAdmissionReceiptV2::new(
            SecurityEpoch::from_raw(7),
            decision,
            &operator_verification_key,
            ReAdmissionReceiptV2::genesis_hash(),
            123,
            &system_key,
        )
        .expect("v2 receipt");
        assert!(
            receipt
                .verify(&operator_verification_key, &system_verification_key)
                .expect("receipt verify")
        );
    }

    #[test]
    fn v2_json_is_self_describing_and_roundtrips() {
        let (operator_key, _) = generate_keypair();
        let decision = fresh_decision(&operator_key);
        let value = serde_json::to_value(&decision).expect("serialize v2 decision");
        assert_eq!(value["persistence_schema"], READMISSION_DECISION_PERSISTENCE_SCHEMA_V2);
        assert_eq!(value["schema_version"]["derivation_version"], "sha256_v2");
        assert_eq!(value["decision_id"]["derivation_version"], "sha256_v2");
        let decoded: ReAdmissionDecisionV2 =
            serde_json::from_value(value).expect("deserialize v2 decision");
        assert_eq!(decoded, decision);
    }

    #[test]
    fn original_id_algorithm_tag_changes_identity_and_signature() {
        let (operator_key, _) = generate_keypair();
        let raw = EngineObjectId([4; 32]);
        let legacy = ReAdmissionDecisionV2::new(
            SecurityEpoch::from_raw(7),
            PersistedEngineObjectId::legacy(raw.clone()),
            reason(),
            30,
            "operator".to_string(),
            AttestationStatus::NotAvailable,
            900_000,
            fallback(),
            BTreeMap::new(),
            &operator_key,
        )
        .expect("legacy-tagged original");
        let v2 = ReAdmissionDecisionV2::new(
            SecurityEpoch::from_raw(7),
            PersistedEngineObjectId::from_versioned(VersionedEngineObjectId::new(
                ObjectIdDerivationVersion::Sha256V2,
                raw,
            )),
            reason(),
            30,
            "operator".to_string(),
            AttestationStatus::NotAvailable,
            900_000,
            fallback(),
            BTreeMap::new(),
            &operator_key,
        )
        .expect("v2-tagged original");
        assert_ne!(legacy.decision_id, v2.decision_id);
        assert_ne!(legacy.operator_signature, v2.operator_signature);
    }

    #[test]
    fn verified_legacy_receipt_migrates_with_bound_provenance() {
        let (legacy_operator_key, legacy_operator_verification_key) = generate_keypair();
        let (legacy_system_key, legacy_system_verification_key) = generate_keypair();
        let (new_operator_key, new_operator_verification_key) = generate_keypair();
        let (new_system_key, new_system_verification_key) = generate_keypair();

        let legacy_decision = ReAdmissionDecision::new(
            SecurityEpoch::from_raw(11),
            EngineObjectId([5; 32]),
            reason(),
            60,
            "operator".to_string(),
            AttestationStatus::NotAvailable,
            800_000,
            fallback(),
            BTreeMap::new(),
            &legacy_operator_key,
        )
        .expect("legacy decision");
        let legacy_receipt = ReAdmissionReceipt::new(
            SecurityEpoch::from_raw(11),
            legacy_decision,
            ReAdmissionReceipt::genesis_hash(),
            456,
            &legacy_system_key,
        )
        .expect("legacy receipt");

        let migrated = ReAdmissionReceiptV2::migrate_verified_legacy(
            &legacy_receipt,
            &legacy_operator_verification_key,
            &legacy_system_verification_key,
            &new_operator_key,
            &new_system_key,
        )
        .expect("migrate legacy receipt");
        assert!(migrated.legacy_provenance.is_some());
        assert!(migrated.decision.legacy_provenance.is_some());
        assert_eq!(
            migrated.decision.original_quarantine_id.derivation_version,
            ObjectIdDerivationVersion::LegacyV1
        );
        assert!(
            migrated
                .verify(&new_operator_verification_key, &new_system_verification_key)
                .expect("migrated receipt verify")
        );
    }

    #[test]
    fn invalid_legacy_signature_is_never_resigned_as_v2() {
        let (legacy_operator_key, legacy_operator_verification_key) = generate_keypair();
        let (new_operator_key, _) = generate_keypair();
        let mut legacy = ReAdmissionDecision::new(
            SecurityEpoch::from_raw(11),
            EngineObjectId([6; 32]),
            reason(),
            60,
            "operator".to_string(),
            AttestationStatus::NotAvailable,
            800_000,
            fallback(),
            BTreeMap::new(),
            &legacy_operator_key,
        )
        .expect("legacy decision");
        legacy.operator_id = "tampered".to_string();
        assert!(matches!(
            ReAdmissionDecisionV2::migrate_verified_legacy(
                &legacy,
                &legacy_operator_verification_key,
                &new_operator_key,
            ),
            Err(VersionedReAdmissionError::LegacyVerification(_))
        ));
    }

    #[test]
    fn tampering_algorithm_metadata_fails_identity_verification() {
        let (operator_key, _) = generate_keypair();
        let mut decision = fresh_decision(&operator_key);
        decision.original_quarantine_id.derivation_version = ObjectIdDerivationVersion::LegacyV1;
        assert!(decision.validate_identity().is_err());
    }

    #[test]
    fn migrated_fields_cannot_diverge_from_legacy_provenance() {
        let (legacy_operator_key, legacy_operator_verification_key) = generate_keypair();
        let (new_operator_key, _) = generate_keypair();
        let legacy = ReAdmissionDecision::new(
            SecurityEpoch::from_raw(11),
            EngineObjectId([8; 32]),
            reason(),
            60,
            "operator".to_string(),
            AttestationStatus::NotAvailable,
            800_000,
            fallback(),
            BTreeMap::new(),
            &legacy_operator_key,
        )
        .expect("legacy decision");
        let mut migrated = ReAdmissionDecisionV2::migrate_verified_legacy(
            &legacy,
            &legacy_operator_verification_key,
            &new_operator_key,
        )
        .expect("migrate legacy decision");
        migrated.operator_id = "different-operator".to_string();
        assert!(matches!(
            migrated.validate_identity(),
            Err(VersionedReAdmissionError::LegacyMappingMismatch("operator_id"))
        ));
    }

    #[test]
    fn receipt_content_hash_tampering_fails_closed() {
        let (operator_key, operator_verification_key) = generate_keypair();
        let (system_key, _) = generate_keypair();
        let decision = fresh_decision(&operator_key);
        let mut receipt = ReAdmissionReceiptV2::new(
            SecurityEpoch::from_raw(7),
            decision,
            &operator_verification_key,
            ReAdmissionReceiptV2::genesis_hash(),
            123,
            &system_key,
        )
        .expect("v2 receipt");
        receipt.content_hash = ContentHash::compute(b"tampered");
        assert!(matches!(
            receipt.validate_identity(),
            Err(VersionedReAdmissionError::ContentHashMismatch)
        ));
    }
}
