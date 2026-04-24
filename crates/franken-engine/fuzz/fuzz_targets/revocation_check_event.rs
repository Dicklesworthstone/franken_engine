#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::revocation_chain::RevocationTargetType;
use frankenengine_engine::revocation_enforcement::{
    EnforcementPoint, RevocationCheckEvent, SchemaVersion,
};
use libfuzzer_sys::fuzz_target;

struct ArbitraryRevocationCheckEvent(RevocationCheckEvent);

impl<'a> Arbitrary<'a> for ArbitraryRevocationCheckEvent {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(RevocationCheckEvent {
            schema_version: SchemaVersion::V1.as_u16(),
            enforcement_point: arbitrary_enforcement_point(u)?,
            target_id: EngineObjectId(<[u8; 32]>::arbitrary(u)?),
            target_type: arbitrary_target_type(u)?,
            is_revoked: bool::arbitrary(u)?,
            transitive: bool::arbitrary(u)?,
            trace_id: bounded_string(u, 96)?,
            decision_id: bounded_string(u, 96)?,
            policy_id: bounded_string(u, 96)?,
            frontier_head_seq: Option::<u64>::arbitrary(u)?,
            frontier_chain_hash: bounded_string(u, 128)?,
            revocation_id: Option::<[u8; 32]>::arbitrary(u)?.map(EngineObjectId),
            outcome: bounded_string(u, 64)?,
            error_code: arbitrary_optional_string(u, 96)?,
            checked_at: DeterministicTimestamp(u64::arbitrary(u)?),
        }))
    }
}

fn arbitrary_enforcement_point(u: &mut Unstructured<'_>) -> arbitrary::Result<EnforcementPoint> {
    Ok(match u.int_in_range(0_u8..=2)? {
        0 => EnforcementPoint::TokenAcceptance,
        1 => EnforcementPoint::HighRiskOperation,
        _ => EnforcementPoint::ExtensionActivation,
    })
}

fn arbitrary_target_type(u: &mut Unstructured<'_>) -> arbitrary::Result<RevocationTargetType> {
    Ok(match u.int_in_range(0_u8..=4)? {
        0 => RevocationTargetType::Key,
        1 => RevocationTargetType::Token,
        2 => RevocationTargetType::Attestation,
        3 => RevocationTargetType::Extension,
        _ => RevocationTargetType::Checkpoint,
    })
}

fn arbitrary_optional_string(
    u: &mut Unstructured<'_>,
    max_len: usize,
) -> arbitrary::Result<Option<String>> {
    if bool::arbitrary(u)? {
        Ok(Some(bounded_string(u, max_len)?))
    } else {
        Ok(None)
    }
}

fn bounded_string(u: &mut Unstructured<'_>, max_len: usize) -> arbitrary::Result<String> {
    let len = u.int_in_range(0_usize..=max_len.min(u.len()))?;
    let bytes = u.bytes(len)?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 2048 {
        return;
    }

    let _ = serde_json::from_slice::<RevocationCheckEvent>(data);

    let mut unstructured = Unstructured::new(data);
    let Ok(ArbitraryRevocationCheckEvent(event)) =
        ArbitraryRevocationCheckEvent::arbitrary(&mut unstructured)
    else {
        return;
    };

    let encoded = serde_json::to_string(&event).expect("event should serialize");
    let decoded: RevocationCheckEvent =
        serde_json::from_str(&encoded).expect("event should deserialize");
    assert_eq!(decoded, event);
});
