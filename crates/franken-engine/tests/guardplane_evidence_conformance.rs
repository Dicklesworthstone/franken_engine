#![forbid(unsafe_code)]

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::guardplane_integration::{
    BasicGuardplaneAdapter, CallContext, CallType, CodeTrustLevel, GuardplaneConfig,
    GuardplaneDecisionEvidence, GuardplaneError, InterpreterHook,
};

const SIGNING_KEY: &[u8] = b"bd-2tlef-guardplane-evidence-conformance-key";

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

fn signed_config() -> GuardplaneConfig {
    GuardplaneConfig {
        evidence_signing_key: Some(SIGNING_KEY.to_vec()),
        require_evidence_signature: true,
        ..Default::default()
    }
}

fn unsigned_required_config() -> GuardplaneConfig {
    GuardplaneConfig {
        evidence_signing_key: None,
        require_evidence_signature: true,
        ..Default::default()
    }
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

fn signed_evidence() -> Result<GuardplaneDecisionEvidence, String> {
    let mut adapter = BasicGuardplaneAdapter::new(signed_config());
    adapter
        .pre_call(&sample_call())
        .map_err(|err| err.to_string())?;
    adapter
        .decision_history
        .first()
        .cloned()
        .ok_or_else(|| "signed configuration did not emit decision evidence".to_string())
}

fn require_signature_present() -> Result<(), String> {
    let evidence = signed_evidence()?;
    let signature = evidence
        .signature
        .as_ref()
        .ok_or_else(|| "decision evidence signature was absent".to_string())?;
    if signature.len() != 32 {
        return Err(format!(
            "decision evidence signature length was {}, expected 32 bytes",
            signature.len()
        ));
    }
    Ok(())
}

fn require_signature_verifies() -> Result<(), String> {
    let evidence = signed_evidence()?;
    evidence
        .verify_signature_with_key(SIGNING_KEY)
        .map_err(|err| err.to_string())
        .and_then(|verified| {
            verified
                .then_some(())
                .ok_or_else(|| "decision evidence signature did not verify".to_string())
        })
}

fn require_tampered_fields_rejected() -> Result<(), String> {
    let mut evidence = signed_evidence()?;
    evidence.reason.push_str(" tampered");
    evidence
        .verify_signature_with_key(SIGNING_KEY)
        .map_err(|err| err.to_string())
        .and_then(|verified| {
            (!verified)
                .then_some(())
                .ok_or_else(|| "tampered decision evidence fields verified".to_string())
        })
}

fn require_tampered_signature_rejected() -> Result<(), String> {
    let mut evidence = signed_evidence()?;
    let signature = evidence
        .signature
        .as_mut()
        .ok_or_else(|| "decision evidence signature was absent".to_string())?;
    signature[0] ^= 0x80;
    evidence
        .verify_signature_with_key(SIGNING_KEY)
        .map_err(|err| err.to_string())
        .and_then(|verified| {
            (!verified)
                .then_some(())
                .ok_or_else(|| "tampered decision evidence signature verified".to_string())
        })
}

fn require_missing_key_fails_closed() -> Result<(), String> {
    let mut adapter = BasicGuardplaneAdapter::new(unsigned_required_config());
    match adapter.pre_call(&sample_call()) {
        Err(GuardplaneError::ConfigurationError(message)) if message.contains("signing key") => {
            if adapter.decision_history.is_empty() {
                Ok(())
            } else {
                Err("fail-closed signing error still recorded decision evidence".to_string())
            }
        }
        Err(other) => Err(format!("unexpected error for missing signing key: {other}")),
        Ok(action) => Err(format!(
            "missing required signing key allowed guardplane action {action}"
        )),
    }
}

fn guardplane_evidence_requirements() -> [ConformanceRequirement; 5] {
    [
        ConformanceRequirement {
            id: "GP-EVIDENCE-MUST-001",
            level: RequirementLevel::Must,
            clause: "emitted guardplane decision evidence carries a keyed authenticity signature",
            check: require_signature_present,
        },
        ConformanceRequirement {
            id: "GP-EVIDENCE-MUST-002",
            level: RequirementLevel::Must,
            clause: "decision evidence signatures verify against the configured key",
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
            clause: "required signing fails closed when key material is unavailable",
            check: require_missing_key_fails_closed,
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

    assert_eq!(passing_must, 5, "all guardplane evidence MUST clauses pass");
}
