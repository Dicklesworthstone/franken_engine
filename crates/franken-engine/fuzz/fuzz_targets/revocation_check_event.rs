#![no_main]

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::revocation_chain::RevocationTargetType;
use frankenengine_engine::revocation_enforcement::{
    EnforcementPoint, REVOCATION_AUDIT_DIRECT_DENIAL_CODE, REVOCATION_AUDIT_OUTCOME_CLEARED,
    REVOCATION_AUDIT_OUTCOME_DENIED, REVOCATION_AUDIT_TRANSITIVE_DENIAL_CODE, RevocationCheckEvent,
};
use libfuzzer_sys::fuzz_target;

fn object_id(data: &[u8], offset: usize) -> EngineObjectId {
    let mut bytes = [0_u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = data.get(offset + index).copied().unwrap_or(index as u8);
    }
    EngineObjectId(bytes)
}

fn u64_from(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = data.get(offset + index).copied().unwrap_or(0);
    }
    u64::from_le_bytes(bytes)
}

fn enforcement_point(byte: u8) -> EnforcementPoint {
    match byte % 3 {
        0 => EnforcementPoint::TokenAcceptance,
        1 => EnforcementPoint::HighRiskOperation,
        _ => EnforcementPoint::ExtensionActivation,
    }
}

fn target_type(byte: u8) -> RevocationTargetType {
    match byte % 5 {
        0 => RevocationTargetType::Key,
        1 => RevocationTargetType::Token,
        2 => RevocationTargetType::Attestation,
        3 => RevocationTargetType::Extension,
        _ => RevocationTargetType::Checkpoint,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 {
        return;
    }

    let _ = serde_json::from_slice::<RevocationCheckEvent>(data);

    let is_revoked = data.first().copied().unwrap_or(0) & 1 == 1;
    let transitive = data.get(1).copied().unwrap_or(0) & 1 == 1;
    let outcome = if is_revoked {
        REVOCATION_AUDIT_OUTCOME_DENIED
    } else {
        REVOCATION_AUDIT_OUTCOME_CLEARED
    };
    let error_code = if is_revoked {
        Some(
            if transitive {
                REVOCATION_AUDIT_TRANSITIVE_DENIAL_CODE
            } else {
                REVOCATION_AUDIT_DIRECT_DENIAL_CODE
            }
            .to_string(),
        )
    } else {
        None
    };

    let event = RevocationCheckEvent {
        enforcement_point: enforcement_point(data.get(2).copied().unwrap_or(0)),
        target_id: object_id(data, 3),
        target_type: target_type(data.get(35).copied().unwrap_or(0)),
        is_revoked,
        transitive,
        trace_id: format!("trace-{}", u64_from(data, 36)),
        decision_id: format!("decision-{}", u64_from(data, 44)),
        policy_id: format!("policy-{}", u64_from(data, 52)),
        frontier_head_seq: (data.get(60).copied().unwrap_or(0) & 1 == 1)
            .then_some(u64_from(data, 61)),
        frontier_chain_hash: format!("{:016x}", u64_from(data, 69)),
        revocation_id: is_revoked.then(|| object_id(data, 77)),
        outcome: outcome.to_string(),
        error_code,
        checked_at: DeterministicTimestamp(u64_from(data, 109)),
    };

    let encoded = serde_json::to_string(&event).expect("event should serialize");
    let decoded: RevocationCheckEvent =
        serde_json::from_str(&encoded).expect("event should deserialize");
    assert_eq!(decoded, event);
    assert_eq!(decoded.error_code.is_some(), decoded.is_revoked);
    if decoded.is_revoked {
        assert_eq!(decoded.outcome, REVOCATION_AUDIT_OUTCOME_DENIED);
    } else {
        assert_eq!(decoded.outcome, REVOCATION_AUDIT_OUTCOME_CLEARED);
    }
});
