#![forbid(unsafe_code)]

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::evidence_ledger::{
    EvidenceAuthorityClass, EvidenceTrustRegistry, RuntimeEvidenceAuthority,
};
use frankenengine_engine::guardplane_integration::{
    BasicGuardplaneAdapter, CallContext, CallType, CodeTrustLevel, GUARDPLANE_EVIDENCE_PRODUCER_ID,
    GUARDPLANE_EVIDENCE_SIGNATURE_DOMAIN, GUARDPLANE_INTEGRATION_SCHEMA_VERSION, GuardplaneConfig,
    GuardplaneDecisionEvidence, GuardplaneError, InterpreterHook,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{Signature, SigningKey};

fn live_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(7)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequirementLevel {
    Must,
}

#[derive(Clone, Copy)]
struct ConformanceRequirement {
    id: &'static str,
    level: RequirementLevel,
    clause: &'static str,
    check: fn() -> Result<(), String>,
}

fn signing_key(byte: u8) -> Result<SigningKey, String> {
    SigningKey::from_bytes([byte; 32]).map_err(|error| error.to_string())
}

fn runtime_authority(
    byte: u8,
    activation_epoch: u64,
    rotation_sequence: u64,
    previous_key_id: Option<String>,
) -> Result<RuntimeEvidenceAuthority, String> {
    RuntimeEvidenceAuthority::from_signing_key(
        GUARDPLANE_EVIDENCE_PRODUCER_ID,
        signing_key(byte)?,
        SecurityEpoch::from_raw(activation_epoch),
        rotation_sequence,
        previous_key_id,
    )
    .map_err(|error| error.to_string())
}

fn sample_call() -> CallContext {
    CallContext {
        function_id: 42,
        arg_count: 3,
        call_type: CallType::Method,
        source_span: SourceSpan::new(0, 12, 1, 0, 1, 12),
        trust_level: CodeTrustLevel::Untrusted,
        extension_id: Some("guardplane-conformance-extension".to_string()),
    }
}

fn signed_evidence() -> Result<(GuardplaneDecisionEvidence, EvidenceTrustRegistry), String> {
    let root = runtime_authority(0x41, 1, 1, None)?;
    let root_identity = root.verification_identity();
    let live = runtime_authority(
        0x42,
        3,
        2,
        Some(root_identity.key_provenance.key_id.clone()),
    )?;
    let live_identity = live.verification_identity();
    let registry = EvidenceTrustRegistry::from_runtime_identities(
        live_epoch(),
        [root_identity, live_identity],
    )
    .map_err(|error| error.to_string())?;
    let mut adapter = BasicGuardplaneAdapter::new_with_runtime_authority(
        GuardplaneConfig::default(),
        live,
        live_epoch(),
    )
    .map_err(|error| error.to_string())?;
    adapter
        .pre_call(&sample_call())
        .map_err(|err| err.to_string())?;
    let evidence = adapter
        .decision_history
        .first()
        .cloned()
        .ok_or_else(|| "signed configuration did not emit decision evidence".to_string())?;
    Ok((evidence, registry))
}

fn require_signature_present() -> Result<(), String> {
    let (evidence, _) = signed_evidence()?;
    let envelope = evidence
        .signature
        .as_ref()
        .ok_or_else(|| "decision evidence signature was absent".to_string())?;
    if envelope.signature.is_sentinel() {
        return Err("decision evidence retained the unsigned signature sentinel".to_string());
    }
    Ok(())
}

fn require_signature_verifies() -> Result<(), String> {
    let (evidence, registry) = signed_evidence()?;
    evidence
        .verify_runtime_signature(&registry)
        .map_err(|err| err.to_string())
}

fn require_tampered_fields_rejected() -> Result<(), String> {
    let (mut evidence, registry) = signed_evidence()?;
    evidence.reason.push_str(" tampered");
    evidence
        .verify_runtime_signature(&registry)
        .is_err()
        .then_some(())
        .ok_or_else(|| "tampered decision evidence fields verified".to_string())
}

fn require_tampered_signature_rejected() -> Result<(), String> {
    let (mut evidence, registry) = signed_evidence()?;
    let envelope = evidence
        .signature
        .as_mut()
        .ok_or_else(|| "decision evidence signature was absent".to_string())?;
    let mut bytes = envelope.signature.to_bytes();
    bytes[0] ^= 0x80;
    envelope.signature = Signature::from_bytes(bytes);
    evidence
        .verify_runtime_signature(&registry)
        .is_err()
        .then_some(())
        .ok_or_else(|| "tampered decision evidence signature verified".to_string())
}

fn require_missing_key_fails_closed() -> Result<(), String> {
    match BasicGuardplaneAdapter::new(GuardplaneConfig::default()) {
        Err(GuardplaneError::ConfigurationError(message))
            if message.contains("runtime authority") =>
        {
            Ok(())
        }
        Err(other) => Err(format!(
            "unexpected error for missing signing authority: {other}"
        )),
        Ok(_) => Err("missing runtime authority constructed a signed-evidence adapter".to_string()),
    }
}

fn require_runtime_coordinates_are_bound() -> Result<(), String> {
    let (evidence, _) = signed_evidence()?;
    let envelope = evidence
        .signature
        .as_ref()
        .ok_or_else(|| "decision evidence signature was absent".to_string())?;
    if envelope.producer_id != GUARDPLANE_EVIDENCE_PRODUCER_ID
        || envelope.key_provenance.authority_class != EvidenceAuthorityClass::Runtime
        || envelope.key_provenance.activation_epoch != SecurityEpoch::from_raw(3)
        || envelope.key_provenance.rotation_sequence != 2
        || envelope.key_provenance.previous_key_id.is_none()
        || envelope.signed_epoch != live_epoch()
        || evidence.security_epoch != live_epoch()
        || GUARDPLANE_INTEGRATION_SCHEMA_VERSION != "franken-engine.guardplane-integration.v2"
        || GUARDPLANE_EVIDENCE_SIGNATURE_DOMAIN
            != "franken-engine.guardplane.decision-evidence.signature.v2"
    {
        return Err(format!(
            "runtime producer/key/epoch/rotation coordinates were not preserved: {envelope:?}"
        ));
    }
    Ok(())
}

fn require_tampered_runtime_coordinates_rejected() -> Result<(), String> {
    let (evidence, registry) = signed_evidence()?;

    let mut producer = evidence.clone();
    producer
        .signature
        .as_mut()
        .ok_or_else(|| "decision evidence signature was absent".to_string())?
        .producer_id
        .push_str(".attacker");
    let mut key = evidence.clone();
    key.signature
        .as_mut()
        .ok_or_else(|| "decision evidence signature was absent".to_string())?
        .key_provenance
        .key_id
        .push_str("-attacker");
    let mut rotation = evidence.clone();
    rotation
        .signature
        .as_mut()
        .ok_or_else(|| "decision evidence signature was absent".to_string())?
        .key_provenance
        .rotation_sequence += 1;
    let mut epoch = evidence;
    epoch
        .signature
        .as_mut()
        .ok_or_else(|| "decision evidence signature was absent".to_string())?
        .signed_epoch = SecurityEpoch::from_raw(6);

    for (coordinate, variant) in [
        ("producer", producer),
        ("key", key),
        ("rotation", rotation),
        ("epoch", epoch),
    ] {
        if variant.verify_runtime_signature(&registry).is_ok() {
            return Err(format!(
                "tampered runtime {coordinate} coordinate still authenticated"
            ));
        }
    }
    Ok(())
}

fn require_raw_key_config_is_rejected() -> Result<(), String> {
    let mut config =
        serde_json::to_value(GuardplaneConfig::default()).map_err(|error| error.to_string())?;
    config["evidence_signing_key"] = serde_json::json!([1, 2, 3, 4]);
    serde_json::from_value::<GuardplaneConfig>(config)
        .is_err()
        .then_some(())
        .ok_or_else(|| "legacy serialized raw signing key was silently accepted".to_string())
}

fn require_old_public_key_cannot_forge_runtime_evidence() -> Result<(), String> {
    let (live_evidence, registry) = signed_evidence()?;
    let root = runtime_authority(0x41, 1, 1, None)?;
    let public_default = ["franken-engine.guardplane.", "default-evidence-key.v1"].concat();
    let attacker_seed = *ContentHash::compute(public_default.as_bytes()).as_bytes();
    let attacker_key = SigningKey::from_bytes(attacker_seed).map_err(|error| error.to_string())?;
    let attacker = RuntimeEvidenceAuthority::from_signing_key(
        GUARDPLANE_EVIDENCE_PRODUCER_ID,
        attacker_key,
        SecurityEpoch::from_raw(3),
        2,
        Some(root.key_provenance().key_id.clone()),
    )
    .map_err(|error| error.to_string())?;
    let mut attacker_adapter = BasicGuardplaneAdapter::new_with_runtime_authority(
        GuardplaneConfig::default(),
        attacker,
        live_epoch(),
    )
    .map_err(|error| error.to_string())?;
    attacker_adapter
        .pre_call(&sample_call())
        .map_err(|error| error.to_string())?;
    let forged = attacker_adapter
        .decision_history
        .first()
        .ok_or_else(|| "attacker adapter did not emit evidence".to_string())?;
    if forged.evidence_hash != live_evidence.evidence_hash {
        return Err("forgery fixture did not reproduce the live unsigned evidence".to_string());
    }
    forged
        .verify_runtime_signature(&registry)
        .is_err()
        .then_some(())
        .ok_or_else(|| "old public default material forged live runtime evidence".to_string())
}

fn guardplane_evidence_requirements() -> [ConformanceRequirement; 9] {
    [
        ConformanceRequirement {
            id: "GP-EVIDENCE-MUST-001",
            level: RequirementLevel::Must,
            clause: "emitted guardplane decision evidence carries a provenance-bound signature",
            check: require_signature_present,
        },
        ConformanceRequirement {
            id: "GP-EVIDENCE-MUST-002",
            level: RequirementLevel::Must,
            clause: "decision evidence signatures verify through external trust",
            check: require_signature_verifies,
        },
        ConformanceRequirement {
            id: "GP-EVIDENCE-MUST-003",
            level: RequirementLevel::Must,
            clause: "signature verification rejects tampered decision evidence fields",
            check: require_tampered_fields_rejected,
        },
        ConformanceRequirement {
            id: "GP-EVIDENCE-MUST-004",
            level: RequirementLevel::Must,
            clause: "signature verification rejects tampered authenticity tags",
            check: require_tampered_signature_rejected,
        },
        ConformanceRequirement {
            id: "GP-EVIDENCE-MUST-005",
            level: RequirementLevel::Must,
            clause: "required signing fails closed when runtime authority is unavailable",
            check: require_missing_key_fails_closed,
        },
        ConformanceRequirement {
            id: "GP-EVIDENCE-MUST-006",
            level: RequirementLevel::Must,
            clause: "signatures bind runtime producer, key, epoch, and rotation coordinates",
            check: require_runtime_coordinates_are_bound,
        },
        ConformanceRequirement {
            id: "GP-EVIDENCE-MUST-007",
            level: RequirementLevel::Must,
            clause: "tampered runtime producer, key, epoch, and rotation coordinates are rejected",
            check: require_tampered_runtime_coordinates_rejected,
        },
        ConformanceRequirement {
            id: "GP-EVIDENCE-MUST-008",
            level: RequirementLevel::Must,
            clause: "serialized raw signing keys are rejected",
            check: require_raw_key_config_is_rejected,
        },
        ConformanceRequirement {
            id: "GP-EVIDENCE-MUST-009",
            level: RequirementLevel::Must,
            clause: "the former public default material cannot forge live runtime evidence",
            check: require_old_public_key_cannot_forge_runtime_evidence,
        },
    ]
}

#[test]
fn guardplane_decision_evidence_conformance_matrix() {
    let requirements = guardplane_evidence_requirements();
    let mut passing_must = 0usize;

    for requirement in requirements {
        (requirement.check)().unwrap_or_else(|reason| {
            panic!(
                "{} {:?} failed: {}\nclause: {}",
                requirement.id, requirement.level, reason, requirement.clause
            )
        });
        if requirement.level == RequirementLevel::Must {
            passing_must += 1;
        }
    }

    assert_eq!(passing_must, 9, "all guardplane evidence MUST clauses pass");
}
