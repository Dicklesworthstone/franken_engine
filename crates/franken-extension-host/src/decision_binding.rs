//! Bind declassification audit receipts to the complete policy input.
//!
//! A caller-chosen request ID is not a commitment to a data reference, label
//! transition, requester, or policy context. Commit the canonical serializable
//! input and effective capability set without retaining sensitive request text
//! in the public receipt. Verification proves correspondence, not freshness or
//! permission to replay a data release.

use super::{
    Capability, CryptographicDecisionReceipt, DecisionPublicKey, DeclassificationRequest,
    FlowEnforcementContext, MAX_POLICY_SIGNING_PAYLOAD_BYTES, PolicySignError, PolicySignSurface,
    policy_sign_fail_closed,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{self, Write};

const REQUEST_DOMAIN: &[u8] = b"franken-extension-host-declassification-input-v1\0";
const RECEIPT_ID_DOMAIN: &[u8] = b"franken-extension-host-bound-receipt-id-v1\0";

struct BoundedPayload {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for BoundedPayload {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("policy signing payload limit exceeded"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other("policy signing payload allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Enforce the encoded limit while serializing, rather than after allocating an
/// arbitrarily large JSON copy. On overflow actual_bytes is the first refused
/// size (limit + 1), a lower bound rather than a scan of the rest of the input.
pub(super) fn serialize_payload<T: Serialize + ?Sized>(
    surface: PolicySignSurface,
    request_id: &str,
    payload: &T,
) -> Result<Vec<u8>, PolicySignError> {
    let mut writer = BoundedPayload {
        bytes: Vec::new(),
        limit: MAX_POLICY_SIGNING_PAYLOAD_BYTES,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut writer, payload);
    // A malicious/custom serializer may swallow the writer error. The sticky
    // overflow flag still forbids signing an incomplete prefix.
    if writer.exceeded {
        return Err(PolicySignError::OversizedPayload {
            request_id: request_id.to_string(),
            surface,
            actual_bytes: MAX_POLICY_SIGNING_PAYLOAD_BYTES + 1,
            max_bytes: MAX_POLICY_SIGNING_PAYLOAD_BYTES,
        });
    }
    result.map_err(|error| policy_sign_fail_closed(surface, request_id, error.to_string()))?;
    Ok(writer.bytes)
}

#[derive(Serialize)]
struct BindingInput<'a> {
    request: &'a DeclassificationRequest,
    requester_capabilities: &'a BTreeSet<Capability>,
    trace_id: &'a str,
    decision_id: &'a str,
    policy_id: &'a str,
}

pub(super) fn request_binding(
    request: &DeclassificationRequest,
    capabilities: &BTreeSet<Capability>,
    context: &FlowEnforcementContext<'_>,
) -> Result<[u8; 32], PolicySignError> {
    let input = BindingInput {
        request,
        requester_capabilities: capabilities,
        trace_id: context.trace_id,
        decision_id: context.decision_id,
        policy_id: context.policy_id,
    };
    let bytes = serialize_payload(
        PolicySignSurface::DeclassificationReceipt,
        &request.request_id,
        &input,
    )?;
    let mut hash = Sha256::new();
    hash.update(REQUEST_DOMAIN);
    hash.update(bytes);
    Ok(hash.finalize().into())
}

pub(super) fn bound_receipt_id<T: Serialize + ?Sized>(
    request_id: &str,
    payload_without_id: &T,
) -> Result<String, PolicySignError> {
    let bytes = serialize_payload(
        PolicySignSurface::DeclassificationReceipt,
        request_id,
        payload_without_id,
    )?;
    let mut hash = Sha256::new();
    hash.update(RECEIPT_ID_DOMAIN);
    hash.update(bytes);
    Ok(format!("dcr-{}", super::to_hex(&hash.finalize())))
}

impl CryptographicDecisionReceipt {
    /// Verify the signed decision and its exact request/capability/context
    /// correspondence. Unbound legacy audit receipts and fail-closed fallback
    /// receipts cannot pass this check. This authenticates both approval and
    /// denial evidence: callers must separately check the verdict and enforce
    /// their current trust, replay, expiry, and data-reference resolution rules.
    /// No in-process trusted FlowLabel is reconstructed from external evidence.
    pub fn verify_for_request(
        &self,
        public_key: &DecisionPublicKey,
        request: &DeclassificationRequest,
        requester_capabilities: &BTreeSet<Capability>,
        context: &FlowEnforcementContext<'_>,
    ) -> bool {
        let Some(expected) = self.request_binding else {
            return false;
        };
        if self.request_id != request.request_id
            || self.timestamp_ns != request.timestamp_ns
            || !self.verify(public_key)
        {
            return false;
        }
        request_binding(request, requester_capabilities, context)
            .is_ok_and(|actual| actual == expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DataRef, DecisionSigningKey, DecisionVerdict, DeclassificationGateway,
        DeclassificationOutcome, DeclassificationPurpose, FlowLabel, IntegrityLevel, SecrecyLevel,
    };

    fn request() -> DeclassificationRequest {
        DeclassificationRequest {
            request_id: "caller-selected-id".into(),
            requester: "extension-a".into(),
            data_ref: DataRef::new("memory", "secret-token"),
            current_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
            target_label: FlowLabel::new(SecrecyLevel::Confidential, IntegrityLevel::Validated),
            purpose: DeclassificationPurpose::OperatorOverride,
            justification: "sensitive operator justification".into(),
            timestamp_ns: 100,
        }
    }

    fn caps() -> BTreeSet<Capability> {
        BTreeSet::from([Capability::Declassify])
    }

    fn context() -> FlowEnforcementContext<'static> {
        FlowEnforcementContext::new("trace-a", "decision-a", "policy-a")
    }

    fn receipt(request: DeclassificationRequest) -> CryptographicDecisionReceipt {
        let mut gateway = DeclassificationGateway::with_default_contracts(key());
        match gateway.evaluate_request(request, &caps(), 500_000, &context()) {
            DeclassificationOutcome::Approved { receipt, .. } => receipt,
            other => panic!("expected real gateway approval, got {other:?}"),
        }
    }

    fn key() -> DecisionSigningKey {
        DecisionSigningKey::new([91; 32])
    }

    #[test]
    fn gateway_receipt_verifies_exact_request_after_serialization() {
        let request = request();
        let receipt = receipt(request.clone());
        assert!(receipt.request_binding.is_some());
        assert!(receipt.verify_for_request(&key().public_key(), &request, &caps(), &context()));
        let decoded: CryptographicDecisionReceipt =
            serde_json::from_slice(&serde_json::to_vec(&receipt).unwrap()).unwrap();
        let decoded_request: DeclassificationRequest =
            serde_json::from_slice(&serde_json::to_vec(&request).unwrap()).unwrap();
        assert!(decoded.verify_for_request(
            &key().public_key(),
            &decoded_request,
            &caps(),
            &context()
        ));
    }

    #[test]
    fn request_fields_cannot_be_substituted_under_a_shared_request_id() {
        let original = request();
        let receipt = receipt(original.clone());
        let mut variants = vec![original.clone(); 10];
        variants[0].requester = "extension-b".into();
        variants[1].data_ref.namespace = "other-memory".into();
        variants[2].data_ref.key = "other-secret".into();
        variants[3].current_label =
            FlowLabel::new(SecrecyLevel::TopSecret, IntegrityLevel::Validated);
        variants[4].target_label = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Validated);
        variants[5].target_label =
            FlowLabel::new(SecrecyLevel::Confidential, IntegrityLevel::Untrusted);
        variants[6].purpose = DeclassificationPurpose::UserConsent;
        variants[7].justification = "different justification".into();
        variants[8].timestamp_ns += 1;
        variants[9].request_id = "other-id".into();
        for (index, variant) in variants.iter().enumerate() {
            assert!(
                !receipt.verify_for_request(&key().public_key(), variant, &caps(), &context()),
                "request field mutation {index} was not committed"
            );
        }
    }

    #[test]
    fn policy_trace_decision_and_effective_capabilities_are_bound() {
        let request = request();
        let receipt = receipt(request.clone());
        for context in [
            FlowEnforcementContext::new("other-trace", "decision-a", "policy-a"),
            FlowEnforcementContext::new("trace-a", "other-decision", "policy-a"),
            FlowEnforcementContext::new("trace-a", "decision-a", "other-policy"),
        ] {
            assert!(!receipt.verify_for_request(&key().public_key(), &request, &caps(), &context));
        }
        for capabilities in [
            BTreeSet::new(),
            BTreeSet::from([Capability::Declassify, Capability::FsRead]),
        ] {
            assert!(!receipt.verify_for_request(
                &key().public_key(),
                &request,
                &capabilities,
                &context()
            ));
        }
    }

    #[test]
    fn receipt_identifiers_commit_the_data_reference_not_only_the_caller_id() {
        let a = request();
        let mut b = a.clone();
        b.data_ref.key = "another-object".into();
        let first = receipt(a.clone());
        let identical = receipt(a);
        let different = receipt(b);
        assert_eq!(first, identical);
        assert_ne!(first.request_binding, different.request_binding);
        assert_ne!(first.receipt_id, different.receipt_id);
        assert_ne!(first.signature, different.signature);
    }

    #[test]
    fn receipt_identity_includes_the_full_signed_decision_not_only_the_request() {
        let input = request();
        let original = receipt(input.clone());
        let mut gateway = DeclassificationGateway::with_default_contracts(key());
        let DeclassificationOutcome::Approved {
            receipt: changed, ..
        } = gateway.evaluate_request(input, &caps(), 700_000, &context())
        else {
            panic!("expected approval");
        };
        assert_eq!(original.request_binding, changed.request_binding);
        assert_ne!(original.receipt_id, changed.receipt_id);
        assert_ne!(original.signature, changed.signature);
    }

    #[test]
    fn binding_is_part_of_the_signature_not_unsigned_metadata() {
        let request = request();
        let original = receipt(request.clone());
        let mut changed = original.clone();
        changed.request_binding.as_mut().unwrap()[0] ^= 1;
        assert!(!changed.verify(&key().public_key()));
        changed = original.clone();
        changed.request_binding = None;
        assert!(!changed.verify(&key().public_key()));
        assert!(!changed.verify_for_request(&key().public_key(), &request, &caps(), &context()));
        changed = original;
        changed.receipt_id = "another-id".into();
        assert!(!changed.verify(&key().public_key()));
    }

    #[test]
    fn unbound_audit_receipts_cannot_verify_request_authorization() {
        let request = request();
        let legacy = CryptographicDecisionReceipt::new_signed(
            &request.request_id,
            DecisionVerdict::Approved { conditions: vec![] },
            vec![],
            vec![],
            500_000,
            request.timestamp_ns,
            &key(),
        )
        .unwrap();
        assert!(legacy.verify(&key().public_key()));
        assert!(!legacy.verify_for_request(&key().public_key(), &request, &caps(), &context()));
        let json = serde_json::to_value(&legacy).unwrap();
        assert!(json.get("request_binding").is_none());
        let decoded: CryptographicDecisionReceipt = serde_json::from_value(json).unwrap();
        assert!(!decoded.verify_for_request(&key().public_key(), &request, &caps(), &context()));
    }

    #[test]
    fn binding_does_not_publish_sensitive_request_text() {
        let json = serde_json::to_string(&receipt(request())).unwrap();
        assert!(!json.contains("secret-token"));
        assert!(!json.contains("sensitive operator justification"));
    }

    #[test]
    fn oversized_binding_refuses_approval_with_a_signed_denial() {
        let mut request = request();
        request.justification = "x".repeat(MAX_POLICY_SIGNING_PAYLOAD_BYTES);
        let mut gateway = DeclassificationGateway::with_default_contracts(key());
        let denied = gateway.evaluate_request(request.clone(), &caps(), 500_000, &context());
        let DeclassificationOutcome::Denied { receipt, .. } = denied else {
            panic!("oversized policy input must not authorize a label release");
        };
        assert!(receipt.verify(&key().public_key()));
        assert!(!receipt.verify_for_request(&key().public_key(), &request, &caps(), &context()));
        assert_eq!(gateway.receipt_log().receipts().len(), 1);
        assert_eq!(gateway.denied_evidence().len(), 1);
    }

    #[test]
    fn denied_decisions_are_bound_without_becoming_approvals() {
        let request = request();
        let mut gateway = DeclassificationGateway::with_default_contracts(key());
        let denied =
            gateway.evaluate_request(request.clone(), &BTreeSet::new(), 500_000, &context());
        let DeclassificationOutcome::Denied { receipt, .. } = denied else {
            panic!("capability required");
        };
        assert!(matches!(receipt.verdict, DecisionVerdict::Denied { .. }));
        assert!(receipt.verify_for_request(
            &key().public_key(),
            &request,
            &BTreeSet::new(),
            &context()
        ));
        assert!(!receipt.verify_for_request(&key().public_key(), &request, &caps(), &context()));
    }

    #[test]
    fn payload_writer_enforces_the_exact_boundary_before_retaining_bytes() {
        let mut writer = BoundedPayload {
            bytes: vec![],
            limit: 3,
            exceeded: false,
        };
        writer.write_all(b"abc").unwrap();
        assert_eq!(writer.bytes, b"abc");
        assert!(writer.write_all(b"d").is_err());
        assert!(writer.exceeded);
        assert_eq!(writer.bytes, b"abc");
        let mut writer = BoundedPayload {
            bytes: vec![],
            limit: 3,
            exceeded: false,
        };
        assert!(writer.write_all(b"too large").is_err());
        assert!(writer.bytes.is_empty());
    }

    #[test]
    fn signing_serializer_refuses_large_and_escaped_values() {
        for value in [
            "a".repeat(MAX_POLICY_SIGNING_PAYLOAD_BYTES),
            "\"".repeat(MAX_POLICY_SIGNING_PAYLOAD_BYTES / 2),
        ] {
            assert!(matches!(
                serialize_payload(
                    PolicySignSurface::DeclassificationReceipt,
                    "request",
                    &value
                ),
                Err(PolicySignError::OversizedPayload { .. })
            ));
        }
    }
}
